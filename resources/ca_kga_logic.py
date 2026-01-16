# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility for processing non-local key generation inside a `PKIMessage` when local key generation is unavailable.

Focuses on the `EnvelopedData` structure.
"""

import logging
from typing import List, Optional, Tuple, Union

import pyasn1
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import (
    rfc4055,
    rfc5280,
    rfc5652,
    rfc5753,
    rfc5958,
    rfc8018,
    rfc9480,
    rfc9481,
    rfc9629,
)
from robot.api.deco import keyword, not_keyword

import pq_logic.combined_factory
from pq_logic.keys.abstract_pq import PQKEMPrivateKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey, KEMPrivateKey
from pq_logic.keys.composite_kem import CompositeKEMPrivateKey
from pq_logic.keys.trad_kem_keys import RSADecapKey
from pq_logic.pq_utils import get_kem_oid_from_key
from pq_logic.tmp_oids import COMPOSITE_SIG_OID_TO_NAME
from resources import (
    asn1utils,
    certextractutils,
    certutils,
    checkutils,
    cmputils,
    compareutils,
    cryptoutils,
    envdatautils,
    keyutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.convertutils import str_to_bytes
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyData, MismatchingKey
from resources.oid_mapping import (
    compute_hash,
    get_digest_hash_alg_from_alg_id,
    get_hash_from_oid,
    may_return_oid_to_name,
)
from resources.oidutils import (
    ECMQV,
    HKDF_NAME_2_OID,
    KDF_OID_2_NAME,
    KEM_OID_2_NAME,
    KEY_WRAP_NAME_2_OID,
    KEY_WRAP_OID_2_NAME,
    KM_KA_ALG,
    KM_KD_ALG,
    KM_KT_ALG,
    KM_KW_ALG,
    MSG_SIG_ALG,
    PQ_SIG_OID_2_NAME,
    PROT_SYM_ALG,
)
from resources.suiteenums import KeyUsageStrictness
from resources.typingutils import ECDHPrivateKey, EnvDataPrivateKey, PrivateKey, Strint


@not_keyword
def process_mqv(
    mqv_der: Optional[bytes],
    private_key: ec.EllipticCurvePrivateKey,
    hash_alg: str,
    key_wrap_oid: univ.ObjectIdentifier,
    cmp_prot_cert: rfc9480.CMPCertificate,
):
    """Process Elliptic Curve Menezes–Qu–Vanstone (ECMQV) key agreement based on the provided input.

    :param mqv_der: MQV User Keying Material (UKM) encoded as DER bytes. It includes the ephemeral public key
                    and additional keying material used in the MQV key agreement.
    :param private_key: The private key used in the MQV process to derive the shared secret (e.g., an EC private key).
    :param hash_alg: The name of the hashing algorithm (e.g., "sha256", "sha512") to be used for the KDF.
    :param key_wrap_oid: The OID of the key wrap algorithm used for the key agreement.
    :param cmp_prot_cert: The CMP protection certificate used for the key agreement.
    :return: The derived key as bytes after processing the MQV key agreement and KDF.
    :raises ValueError: If there is unexpected data after decoding the MQV User Keying Material (UKM),
        or if the ephemeral public key is not `ecPublicKey`.
    """
    if mqv_der is None:
        raise BadAsn1Data("`MQVuserKeyingMaterial` was not found inside the KeyAgreementRecipientInfo.", overwrite=True)

    mqv_ukm, rest = decoder.decode(mqv_der, asn1Spec=rfc5753.MQVuserKeyingMaterial())

    if rest != b"":
        raise ValueError("Unexpected data found after decoding `MQVuserKeyingMaterial`.")

    if rfc5753.id_ecPublicKey != mqv_ukm["ephemeralPublicKey"]["algorithm"]["algorithm"]:
        may_name = may_return_oid_to_name(mqv_ukm["ephemeralPublicKey"]["algorithm"]["algorithm"])
        raise ValueError(f"The OID must be `id_ecPublicKey`, but was: {may_name}")

    public_key = keyutils.load_public_key_from_spki(mqv_ukm["ephemeralPublicKey"])
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("The extracted public key is not an instance of `EllipticCurvePublicKey`.")

    ukm = None
    if mqv_ukm["addedukm"].isValue:
        ukm = mqv_ukm["addedukm"].asOctets()

    return cryptoutils.perform_one_pass_mqv(
        private_key=private_key,
        peer_cert=cmp_prot_cert,
        public_key_eph=public_key,
        hash_alg=hash_alg,
        key_wrap_oid=key_wrap_oid,
        ukm=ukm,
    )


@not_keyword
def process_kari(
    alg_id: rfc5280.AlgorithmIdentifier,
    private_key: ECDHPrivateKey,
    cmp_prot_cert: rfc9480.CMPCertificate,
    ukm: Optional[bytes] = None,
) -> bytes:
    """Process a KeyAgreementRecipientInfo (KARI) structure based on the provided algorithm identifier and private key.

    :param alg_id: The `AlgorithmIdentifier` structure specifying the algorithm and parameters used for key agreement.
    :param private_key: The private key to perform the key agreement (e.g., an EC private key
        or an X25519/X448 private key).
    :param ukm: Optional bytes representing the User Keying Material (UKM) used in MQV-based key agreement.
        Defaults to None.
    :param cmp_prot_cert: Optional CMP protection certificate required for deriving the shared key.
    :return: The derived key.
    :raises ValueError: If the algorithm identifier specifies an unsupported or unrecognized algorithm.
    """
    if not isinstance(alg_id["algorithm"], rfc5753.KeyWrapAlgorithm):
        key_wrap, rest = try_decode_pyasn1(alg_id["parameters"], rfc5753.KeyWrapAlgorithm())  # type: ignore
        key_wrap: rfc5753.KeyWrapAlgorithm
        if rest != b"":
            raise BadAsn1Data("`KeyWrapAlgorithm`")
    else:
        key_wrap = alg_id["parameters"]

    key_wrap_oid = key_wrap["algorithm"]

    if alg_id["algorithm"] in ECMQV:
        hash_alg = ECMQV[alg_id["algorithm"]].split("-")[1]

        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("The private key must be an instance of `EllipticCurvePrivateKey`.For the `ECMQV` method.")

        k = process_mqv(
            mqv_der=ukm,
            private_key=private_key,
            hash_alg=hash_alg,
            key_wrap_oid=key_wrap_oid,
            cmp_prot_cert=cmp_prot_cert,
        )
        logging.info("Derived `ECMQV` wrapping key: %s", k.hex())
        return k

    if cmp_prot_cert is None:
        raise ValueError("A certificate needs to be provided if `kari` is used, but not the `ECMQV` method.")

    if alg_id["algorithm"] in {rfc9481.id_X25519, rfc9481.id_X448, rfc9481.id_alg_ESDH}:
        name = KM_KA_ALG[alg_id["algorithm"]]

        # TODO: Fix hash algorithm, it is server-specific.
        k = cryptoutils.perform_static_dh(
            private_key=private_key,
            public_key=cmp_prot_cert,
            hash_alg="sha256",
            key_wrap_oid=key_wrap_oid,
            ukm=ukm,
        )
        logging.info("Derived `%s` wrapping key: %s", name, k.hex())
        return k

    if alg_id["algorithm"] in KM_KA_ALG:
        name = KM_KA_ALG[alg_id["algorithm"]]
        hash_alg = name.lower().split("-")[1]
        use_cofactor = "cofactor" in name
        k = cryptoutils.perform_static_dh(
            private_key=private_key,
            public_key=cmp_prot_cert,
            hash_alg=hash_alg,
            key_wrap_oid=key_wrap_oid,
            ukm=ukm,
            use_cofactor=use_cofactor,
        )
        logging.info("Derived `%s` wrapping key: %s", name, k.hex())
        return k

    raise ValueError("The algorithm identifier provided is not defined in RFC 9481 Section 4!")


def validate_not_local_key_gen(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    password: Optional[str] = None,
    expected_type: Optional[str] = None,
    cert_index: Strint = 0,
    expected_size: Strint = 1,
    key_index: Strint = 0,
    trustanchors: str = "data/trustanchors",
    ee_key: Optional[EnvDataPrivateKey] = None,
    key_save_type: Optional[str] = None,
) -> PrivateKey:
    """Validate that the provided PKIMessage is correct, according to Rfc9483 Section 4.1.6.

    Validates All currently supported structures from the `EnvelopeData` to The extracted key.
    It Also validates that the protection salt differs and that for kari the server the needed
    `keyAgreement` extension has.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the certificate and key information.
        - `password`: An optional password used for decrypting the private key (if necessary).
        - `expected_type`: Optionally, the expected type of the protection mechanism used
          to encrypt the private key.
        - `cert_index`: The index of the certificate in the `extraCerts` field of the PKIMessage.
          The certificate is used to validate the identifier fields and for key agreement, if used.
          Defaults to `0` (the CMP protection certificate).
        - `expected_size`: The expected number of private keys to be present. Defaults to `1`.
        - `key_index`: The index of the private key to extract. Defaults to `0`.
        - `trustanchors`: The path to the directory where the trust anchors are stored.
          Defaults to "data/trustanchors".
        - `ee_key`: The private key of the end-entity used for RSA decryption if KTRI is used,
          or EC/X25519/X448 used for key agreement.
        - `key_save_type`: The type of key export expected for a PQ key (e.g., "seed", "raw", "seed_and_raw").
        Defaults to `None`.

    Returns:
    -------
        - The private key extracted from the `CertifiedKeyPair` in the PKIMessage.

    Raises:
    ------
        - `ValueError`: If the version in the PKIHeader is not 3.
        - `ValueError`: If any structure validations fail, like values are incorrectly set or not allowed in
        Rfc9483 Section 4.1.6.
        - `ValueError`: If the private key does not match the public key.
        - `ValueError`: If the senderKID and the CMP protection certificate's SKI extension do not match.
        - `ValueError`: If the key unwrap fails.
        - `ValueError`: If the KGA certificate is not a trust anchor or does not have the `cmKGA`
          ExtendedKeyUsage extension.
        - `MismatchingKey`: If the extracted private key does not match the public key or not the public key
            in the newly issued certificate.

    Examples:
    --------
    | ${private_key}= | Validate Not Local Key Gen | ${pki_message} | password=${password} \
    | expected_type=pwri | cert_index=1 |
    | ${private_key}= | Validate Not Local Key Gen | ${pki_message} | ee_key=${private_key} |
    | ${private_key}= | Validate Not Local Key Gen | ${pki_message} | cert_index=1 |

    """
    body_name = pki_message["body"].getName()
    header_version = int(pki_message["header"]["pvno"])
    if header_version != 3:
        raise ValueError(f"The PKIHeader says version {header_version} but MUST be 3")

    # In a correct message, the newly issued chain must be inside, so in
    # the worst case, there must be one certificate inside.
    cert = pki_message["extraCerts"][int(cert_index)]

    cert_key_pair = asn1utils.get_asn1_value(  # type: ignore
        pki_message, query=f"body.{body_name}.response/{key_index}.certifiedKeyPair"
    )
    cert_key_pair: rfc9480.CertifiedKeyPair
    if cert_key_pair["privateKey"].getName() != "envelopedData":
        raise ValueError("The private field MUST be an `envelopedData` structure")

    env_data = cert_key_pair["privateKey"]["envelopedData"]
    decrypted_data = validate_enveloped_data(
        env_data=env_data,
        cmp_protection_cert=cert,
        expected_type=expected_type,
        pki_message=pki_message,
        password=password,
        expected_size=int(expected_size),
        recip_info_index=int(key_index),
        ee_key=ee_key,
    )
    signed_data, rest = decoder.decode(decrypted_data, rfc5652.SignedData())
    if rest != b"":
        raise ValueError("The decoding of 'SignedData' structure had a remainder!")

    private_key = validate_signed_data_structure(
        signed_data,
        expected_size=expected_size,
        key_index=key_index,
        trustanchors=trustanchors,
        key_save_type=key_save_type,
    )

    kga_type = env_data["recipientInfos"][key_index].getName()
    _check_correct_non_local_key_gen_use(cmp_cert=cert, kga_type=kga_type, pki_message=pki_message, password=password)

    issued_cert = cmputils.get_cert_from_pkimessage(pki_message, key_index)
    issued_cert_pub_key = certutils.load_public_key_from_cert(issued_cert)

    if issued_cert_pub_key != private_key.public_key():
        raise MismatchingKey("The extracted private key does not match the public key in the newly issued certificate.")

    return private_key


@not_keyword
def _check_correct_non_local_key_gen_use(
    cmp_cert: rfc9480.CMPCertificate,
    kga_type: str,
    pki_message: Optional[PKIMessageTMP] = None,
    password: Optional[Union[bytes, str]] = None,
    strictness: int = 2,
):
    """Validate that the CA used the non-local key generation correctly.

    Verifies if the CMP protection certificate has the required key usage.
    If the `pwri` structure was used, it checks that the same password was used for protecting the `PKIMessage`.

    :param cmp_cert: The CMP certificate (`CMPCertificate`) to validate.
    :param kga_type: A string representing the type of key agreement (`ktri`, `kari`, or `pwri`).
    :param pki_message: The PKIMessage to verify against the password, if `pwri` was used.
    :param password: The password used for verifying the PKIMessage protection and the `pwri` structure.
    :param strictness: An integer controlling the strictness of key usage validation (defaults to 2).
        - 2 ensures that the key usage is present but not necessarily the only usage.
    :raises ValueError: If the `kga_type` is unrecognized, key usage validation fails, or if the PKIMessage
        was not protected with the same password.
    """
    if kga_type == "ktri":
        pass

    elif kga_type == "ori":
        # currently only supports the `KEMRecipientInfo`.
        pass

    elif kga_type == "kari":
        # Public key that supports key agreement and where any
        # given key usage extension allows keyAgreement
        strictness = max(2, strictness)  # Must be present, but not only usage!
        try:
            certutils.validate_key_usage(cmp_cert, key_usages="keyAgreement", strictness=strictness)
        except ValueError as err:
            name = KeyUsageStrictness.get(strictness).name
            raise ValueError(f"Failed to validate key usage for keyAgreement with strictness {name}.") from err

    elif kga_type == "pwri":
        if password is None or pki_message is None:
            raise ValueError(
                "The `pwri` structure requires a password and PKIMessage to verify, if the same password was used."
            )

        try:
            protectionutils.verify_pkimessage_protection(pki_message=pki_message, password=password)
        except ValueError as err:
            raise ValueError("The PKIMessage was not protected with the same password!") from err
    else:
        raise ValueError(f"Invalid key agreement type: {kga_type}. Expected 'ktri', 'kari', or 'pwri'.")


def _extract_pwri_content_enc_key(
    pki_message: Optional[PKIMessageTMP],
    password: Union[str, bytes],
    recip_info: rfc5652.RecipientInfo,
    cmp_protection_salt: Optional[bytes] = None,
) -> bytes:
    """Extract and compute the content encryption key from the `pwri` structure, based on the shared password/secret.

    :param pki_message: The PKIMessage to extract the protection salt from, which must not be the same as the one
    used here to encrypt the content encryption key.
    :param password: The password used for key derivation, provided as a string or bytes. If the string
                     starts with "0x", it is interpreted as hex.
    :param recip_info: The `RecipientInfo` structure to check and then extract and unwrap the content encryption key.
    :param cmp_protection_salt: The salt used for the password-based key derivation. If not provided,
    it will be extracted from the `pki_message` header.
    :return: The content encryption key.
    :raises ValueError: If the recipient info is not of type 'pwri' or if the password is not provided.
    """
    if recip_info.getName() != "pwri":
        raise ValueError("If the version is 0, the RecipientInfo name must be 'pwri'.")

    if password is None:
        raise ValueError("A password must be provided when the `RecipientInfo` is `pwri`.")

    if cmp_protection_salt is None and pki_message is None:
        raise ValueError("Either the `pki_message` or `cmp_protection_salt` must be provided.")

    if cmp_protection_salt is None:
        # If the `cmp_protection_salt` is not provided, extract it from the PKIMessage header.
        # The `protectionAlg` field contains the salt used for the password-based key derivation.
        # MUST not be the same.
        alg_id = pki_message["header"]["protectionAlg"]  # type: ignore
        if not alg_id.isValue:
            raise ValueError("The `protectionAlg` field must contain the a value.")

        cmp_protection_salt = protectionutils.get_cmp_protection_salt(protection_alg=alg_id)

    params = validate_password_recipient_info(recip_info["pwri"], cmp_protection_salt)
    password_bytes = str_to_bytes(password)
    content_encryption_key = _compute_password_based_key_management_technique(password=password_bytes, **params)
    logging.info("Pwri content encryption key: %s", content_encryption_key.hex())
    return content_encryption_key


def _extract_kari_content_enc_key(
    recip_info: rfc5652.RecipientInfo,
    cmp_protection_cert: rfc9480.CMPCertificate,
    ee_key: ECDHPrivateKey,
    for_pop: bool = False,
    kari_cert: Optional[rfc9480.CMPCertificate] = None,
) -> bytes:
    """Extract and compute the content encryption key from the `kari` structure, based on the end-entity private key.

    :param recip_info: The `RecipientInfo` structure to check and then extract and unwrap the content encryption key.
    :param cmp_protection_cert: The certificate used for key agreement or encryption.
    :param ee_key: The private key of the end-entity used for the key agreement or encipherment.
    :param for_pop: Whether the extraction is for proof-of-possession (POP) purposes.
    (changes the validation for the `rid` field)
    :param kari_cert: The certificate used for key agreement or encryption, if X448 or X22519 is not used.
    :return: The content encryption key.
    """
    params = validate_key_agree_recipient_info(
        kari_structure=recip_info["kari"],
        cmp_cert=cmp_protection_cert,
        for_pop=for_pop,
    )

    if not isinstance(ee_key, ECDHPrivateKey):
        raise ValueError("The `ee_key` must be an instance of `ECDHPrivateKey` for `kari`.")

    kari_cert = kari_cert or cmp_protection_cert
    if kari_cert is None:
        raise ValueError("A certificate must be provided for `kari`.")

    content_encryption_key = compute_key_agreement_mechanism(
        ee_private_key=ee_key,  # type: ignore
        cmp_protection_cert=kari_cert,
        **params,
    )
    return content_encryption_key


def _extract_ktri_and_kari_content_enc_key(
    recip_info: rfc5652.RecipientInfo,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate],
    ee_key: EnvDataPrivateKey,
    for_pop: bool = False,
    allow_rsa_null: bool = False,
    kari_cert: Optional[rfc9480.CMPCertificate] = None,
) -> bytes:
    """Extract and compute the content encryption key from the `kari` or `ktri` structure, based on the EE private key.

    :param recip_info: The `RecipientInfo` structure to check and then extract and unwrap the content encryption key.
    :param cmp_protection_cert: The certificate used for key agreement or encryption, if ECMQV is not used.
    :param ee_key: The private key of the end-entity used for the key agreement or encipherment.
    :param for_pop: Whether the extraction is for proof-of-possession (POP) purposes.
    (changes the validation for the `rid` field)
    :param allow_rsa_null: Whether to allow RSA parameters to be `NUll`. Defaults to `False`.
    :param kari_cert: The certificate used for key agreement or encryption, if X448 or X22519 is not used.
    :return: The content encryption key.
    :raises ValueError: If the RecipientInfo type is not 'ktri' or 'kari'.
    """
    recip_name = recip_info.getName()
    if recip_name == "ktri":
        if (cmp_protection_cert is None or not cmp_protection_cert.isValue) and not for_pop:
            raise ValueError("A CMP protection certificate must be provided for `ktri`.")

        params = validate_key_trans_recipient_info(recip_info["ktri"], cmp_protection_cert, for_pop=for_pop)

        if not isinstance(ee_key, RSAPrivateKey):
            raise ValueError("The `ee_key` must be an instance of `RSAPrivateKey` for `ktri`.")

        content_encryption_key = compute_key_transport_mechanism(
            ee_private_key=ee_key, allow_rsa_null=allow_rsa_null, **params
        )
        logging.info("Ktri content encryption key: %s", content_encryption_key.hex())

    elif recip_name == "kari":
        if not isinstance(ee_key, ECDHPrivateKey):
            raise ValueError("The `ee_key` must be an instance of `ECDHPrivateKey` for `kari`.")

        content_encryption_key = _extract_kari_content_enc_key(
            recip_info=recip_info,
            cmp_protection_cert=cmp_protection_cert,  # type: ignore
            ee_key=ee_key,
            for_pop=for_pop,
            kari_cert=kari_cert,
        )
        logging.info("Kari content encryption key: %s", content_encryption_key.hex())
    else:
        raise ValueError(
            "The `RecipientInfo` is only allowed to have the values: 'ktri' and 'kari' "
            f"for version 2. But got: '{recip_name}'"
        )

    return content_encryption_key


@not_keyword
def process_other_recip_info(
    recip_private_key: KEMPrivateKey,
    server_cert: Optional[rfc9480.CMPCertificate],
    other_info: rfc5652.OtherRecipientInfo,
    for_pop: bool = False,
) -> bytes:
    """Process a `OtherRecipientInfo` structure based on the provided input.

    Only supports the `KEMRecipientInfo` structure for now.

    :param recip_private_key: The private key of the end-entity used for the decapsulation.
    :param server_cert: The CMP protection certificate used for validating the `rid` field.
    :param other_info: The `OtherRecipientInfo` structure to check and then extract and unwrap
    the content encryption key.
    :param for_pop: Whether the extraction is for proof-of-possession (POP) purposes.
    (skipped the validation)
    :return: The content encryption key.
    :raises ValueError: If the oriType type is not `id_ori_kem`.
    :raises BadAsn1Data: If the `KEMRecipientInfo` structure has a remainder.
    """
    if other_info["oriType"] == rfc9629.id_ori_kem:
        der_data = other_info["oriValue"].asOctets()
        kem_recip_info, rest = decoder.decode(der_data, rfc9629.KEMRecipientInfo())
        if rest:
            raise BadAsn1Data("KEMRecipientInfo", remainder=rest)

        return process_kem_recip_info(
            kem_recip_info=kem_recip_info, server_cert=server_cert, private_key=recip_private_key, for_pop=for_pop
        )
    raise ValueError(f"Got a unknown `oriType`: {other_info['oriType']}")


def _get_kari_cert(pki_message: PKIMessageTMP) -> rfc9480.CMPCertificate:
    """Get the KARI certificate from the PKIMessage.

    Extracts the KARI certificate from the `extraCerts` field of the PKIMessage,
    which contains the X-Key certificate at position 0 or 1.
    """
    if not pki_message["extraCerts"].isValue:
        raise ValueError("The `extraCerts` field must contain the X-Key certificate.")

    tmp = pki_message["extraCerts"][0]
    pub_key = keyutils.load_public_key_from_spki(tmp["tbsCertificate"]["subjectPublicKeyInfo"])
    if isinstance(pub_key, (X448PublicKey, X25519PublicKey)):
        return tmp

    tmp = pki_message["extraCerts"][1]

    if not tmp.isValue:
        raise ValueError("The certificate at position 1 must be the matching X-Key.")

    pub_key = keyutils.load_public_key_from_spki(tmp["tbsCertificate"]["subjectPublicKeyInfo"])
    if not isinstance(pub_key, (X448PublicKey, X25519PublicKey)):
        raise ValueError(
            "Either a kari cert must be provided or the certificate at position 1, must be the matching X-Key."
        )
    kari_cert = tmp
    return kari_cert


def extract_content_encryption_key(
    env_data: rfc9480.EnvelopedData,
    pki_message: Optional[PKIMessageTMP] = None,
    password: Optional[Union[str, bytes]] = None,
    ee_key: Optional[EnvDataPrivateKey] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    recip_index: int = 0,
    expected_size: int = 1,
    for_pop: bool = False,
    allow_rsa_null: bool = False,
    kari_cert: Optional[rfc9480.CMPCertificate] = None,
    cmp_protection_salt: Optional[bytes] = None,
) -> bytes:
    """
    Extract the content-encryption-key from an EnvelopedData structure.

    This function focuses solely on retrieving the content-encryption-key without performing
    recipient validation, version checks, or decryption of the content.


    :param env_data: The `EnvelopedData` structure containing the encrypted key.
    :param pki_message: Optional PKIMessage for processing specific RecipientInfo types.
    :param password: Optional password for `pwri` recipient decryption.
    :param ee_key: Optional private key for `kari` or `ktri` recipient types.
    :param cmp_protection_cert: Optional certificate for decryption in `ktri` or `kari` scenarios.
    :param recip_index: The index of the recipient key in the `RecipientInfos` structure.
    :param expected_size: The expected size of the entries inside the `RecipientInfos` structure.
    :param for_pop: Whether the extraction is for proof-of-possession (POP) purposes.
    (changes the validation for the `rid` field)
    :param allow_rsa_null: Whether to allow for RSA `parameters` to be `NUll`. Defaults to `False`.
    :param kari_cert: Optional certificate for `KARI`. Defaults to `None`.
    :param cmp_protection_salt: Optional CMP protection salt for `pwri` recipient structure. Defaults to `None`.
    :return: The extracted content-encryption-key.
    :raises ValueError: If the extraction fails due to missing keys or unsupported RecipientInfo types.
    """
    recip_infos: rfc5652.RecipientInfos = env_data["recipientInfos"]

    if len(recip_infos) != expected_size:
        raise ValueError(f"Invalid `recipientInfos` size. Expected: {expected_size} had: {len(recip_infos)}")

    if not recip_infos or recip_index >= len(recip_infos):
        raise ValueError("Invalid `recipientInfos`: empty or index out of range.")

    recip_info: rfc5652.RecipientInfo = recip_infos[recip_index]

    # if recip_info.getName() != "pwri" and cmp_protection_cert is None:
    #    cmp_protection_cert = pki_message["extraCerts"][0]

    if recip_info.getName() == "pwri":
        if password is None or (pki_message is None and cmp_protection_salt is None):
            raise ValueError(
                "The `pwri` structure requires a password and PKIMessage to verify, if a different salt was used."
            )
        content_encryption_key = _extract_pwri_content_enc_key(
            pki_message, password, recip_info, cmp_protection_salt=cmp_protection_salt
        )

    elif recip_info.getName() == "ori":
        return process_other_recip_info(
            other_info=recip_info["ori"],
            server_cert=cmp_protection_cert,
            recip_private_key=ee_key,  # type: ignore
            for_pop=for_pop,
        )

    elif recip_info.getName() in ["ktri", "kari"]:
        if cmp_protection_cert is None and not for_pop:
            raise ValueError("CMP protection certificate is required for `ktri` or `kari`.")

        if ee_key is None:
            raise ValueError("A private key are required for `ktri` or `kari`.")

        if kari_cert is None and isinstance(ee_key, (X448PrivateKey, X25519PrivateKey)):
            if not pki_message:
                raise ValueError(
                    "A PKIMessage is required to extract the `KARI` certificate"
                    " for X448 or X25519 private keys or the `KARI` certificate must be provided."
                )

            kari_cert = _get_kari_cert(pki_message)

        content_encryption_key = _extract_ktri_and_kari_content_enc_key(
            recip_info=recip_info,
            cmp_protection_cert=cmp_protection_cert,
            ee_key=ee_key,
            for_pop=for_pop,
            allow_rsa_null=allow_rsa_null,
            kari_cert=kari_cert,
        )

    else:
        logging.error("Unsupported RecipientInfo type: %s", recip_info.getName())
        raise ValueError(f"Unsupported RecipientInfo type: {recip_info.getName()}")

    return content_encryption_key


def _decode_kem_recip_info(
    other_info: Union[univ.Any, bytes, rfc9629.KEMRecipientInfo, rfc5652.OtherRecipientInfo],
) -> rfc9629.KEMRecipientInfo:
    """Decode the `KEMRecipientInfo` structure from the provided bytes.

    :param other_info: The bytes representing the `KEMRecipientInfo` structure.
    :return: The decoded `KEMRecipientInfo` object.
    :raises BadAsn1Data: If there is unexpected data after decoding the `KEMRecipientInfo`.
    """
    if isinstance(other_info, bytes):
        pass
    elif isinstance(other_info, univ.Any):
        other_info = other_info.asOctets()
    elif isinstance(other_info, rfc9629.KEMRecipientInfo):
        return other_info
    elif isinstance(other_info, rfc5652.OtherRecipientInfo):
        if other_info["oriType"] != rfc9629.id_ori_kem:
            raise ValueError("The `oriType` must be `id_ori_kem`.")
        return _decode_kem_recip_info(other_info["oriValue"])

    kem_recip_info, rest = decoder.decode(other_info, rfc9629.KEMRecipientInfo())
    if rest != b"":
        raise BadAsn1Data("KEMRecipientInfo", remainder=rest)
    return kem_recip_info


@not_keyword
def validate_kemri_env_data_for_ca(
    env_data: rfc9480.EnvelopedData,
    kem_cert: rfc9480.CMPCertificate,
    recip_info_index: int = 0,
    expected_size: int = 1,
    for_pop: bool = False,
    expected_raw_data: bool = False,
    kem_key: Optional[KEMPrivateKey] = None,
    hybrid_key: Optional[HybridKEMPrivateKey] = None,
    hybrid_kem_cert: Optional[rfc9480.CMPCertificate] = None,
) -> bytes:
    """Validate and decrypt the `EnvelopedData` structure from a KEMRecipientInfo."""
    if kem_key is None and hybrid_key is None:
        raise ValueError("A private key is required for `KEMRecipientInfo` decryption.")

    recip_info = _validate_recip_info_size(
        env_data=env_data,
        expected_size=expected_size,
        recip_info_index=recip_info_index,
        expected_type="ori",
    )

    enc_content_info: rfc5652.EncryptedContentInfo = env_data["encryptedContentInfo"]

    kemri = _decode_kem_recip_info(
        other_info=recip_info["ori"],
    )

    oid = kemri["kem"]["algorithm"]

    key_oid = None
    key_oid2 = None
    if kem_key is not None:
        key_oid = get_kem_oid_from_key(kem_key)

    if hybrid_key is not None:
        key_oid2 = get_kem_oid_from_key(hybrid_key)

    if key_oid == oid:
        ee_key = kem_key
        ee_cert = kem_cert
    elif key_oid2 == oid:
        ee_key = hybrid_key
        ee_cert = hybrid_kem_cert
    else:
        _oid_name = may_return_oid_to_name(oid)

        if kem_key is not None:
            key_oid = kem_key.name

        if hybrid_key is not None:
            key_oid2 = hybrid_key.name

        raise ValueError(
            f"The `KEMRecipientInfo` algorithm OID: {_oid_name} does not match the "
            f"private key OID: {key_oid} or {key_oid2}"
        )

    if not isinstance(ee_key, (KEMPrivateKey, HybridKEMPrivateKey)):
        raise ValueError("The `ee_key` must be an instance of `KEMPrivateKey` or `HybridKEMPrivateKey`.")

    encrypted_key = process_kem_recip_info(
        kem_recip_info=kemri,
        server_cert=ee_cert,
        private_key=ee_key,
        for_pop=for_pop,
    )

    return validate_encrypted_content_info(
        enc_content_info=enc_content_info,
        content_encryption_key=encrypted_key,
        expected_raw_data=expected_raw_data,
    )


def _validate_recip_info_size(
    env_data: rfc9480.EnvelopedData,
    expected_size: Strint = 1,
    recip_info_index: Strint = 0,
    expected_type: Optional[str] = None,
) -> rfc5652.RecipientInfo:
    """Validate the size of the `recipientInfos` structure.

    :param env_data: The `EnvelopedData` structure to validate.
    :param expected_size: The expected size of the `recipientInfos` structure.
    :param recip_info_index: The index of the `RecipientInfo` to validate.
    :return: The `RecipientInfo` at the specified index.
    """
    recip_infos: rfc5652.RecipientInfos = env_data["recipientInfos"]
    if len(recip_infos) != int(expected_size):
        raise ValueError(f"Invalid `recipientInfos` size. Expected: {expected_size} had: {len(recip_infos)}")

    if not recip_infos or int(recip_info_index) >= len(recip_infos):
        raise ValueError("Invalid `recipientInfos`: empty or index out of range.")
    recip_info = recip_infos[int(recip_info_index)]
    if expected_type is not None and recip_info.getName() != expected_type:
        raise ValueError(f"The `RecipientInfo` must be of type `{expected_type}`but got: {recip_info.getName()}.")
    return recip_info


@keyword("Validate KEMRI EnvelopedData")
def validate_kemri_enveloped_data(  # noqa D417 undocumented-param
    env_data: rfc9480.EnvelopedData,
    ee_key: KEMPrivateKey,
    ee_cert: Optional[rfc9480.CMPCertificate] = None,
    expected_size: Strint = 1,
    recip_info_index: Strint = 0,
    for_pop: bool = False,
    expected_raw_data: bool = False,
    is_sun_hybrid: bool = False,
) -> bytes:
    """Validate and decrypt the content inside a `EnvelopedData` structure for a `KEMRecipientInfo`.

    Arguments:
    ---------
        - `env_data`: The `EnvelopedData` structure to validate.
        - `ee_key`: The private key of the end-entity used for KEMRI decryption.
        - `ee_cert`: The EE certificate used for validating the `rid` field.
        - `expected_size`: The expected size of the `recipientInfos` structure.
        - `recip_info_index`: The index of the `RecipientInfo` to validate.
        - `for_pop`: Whether the extraction is for proof-of-possession (POP) purposes (
        skip rid validation).
        - `expected_raw_data`: Whether to expect raw data in the `EncryptedContentInfo`.
        - `is_sun_hybrid`: Whether the KEMRecipientInfo is from a Sun hybrid KEM request.

    Returns:
    -------
        - The decrypted content.

    Raises:
    ------
        - `ValueError`: If the `recipientInfos` size does not match the expected size.
        - `ValueError`: If the `RecipientInfo` type is not `ori`.
        - `ValueError`: If the `KEMRecipientInfo` algorithm OID does not match the private key OID.
        - `ValueError`: If the `encryptedContentInfo` structure is invalid.
        - `ValueError`: If the `KEMRecipientInfo` structure has a remainder.
        - `ValueError`: If the `KEMRecipientInfo` does not contain the expected fields.
        - `InvalidUnwrap`: If the decryption of the content encryption key fails.

    Examples:
    --------
    | ${data}= | Validate KEMRI EnvelopedData | ${env_data} | ee_key=${ee_key} |
    | ${data}= | Validate KEMRI EnvelopedData | ${env_data} | ee_key=${ee_key} | for_pop=True |

    """
    recip_info = _validate_recip_info_size(
        env_data=env_data,
        expected_size=expected_size,
        recip_info_index=recip_info_index,
        expected_type="ori",
    )

    kemri = _decode_kem_recip_info(
        other_info=recip_info["ori"],
    )

    enc_content_info: rfc5652.EncryptedContentInfo = env_data["encryptedContentInfo"]

    encrypted_key = process_kem_recip_info(
        kem_recip_info=kemri,
        server_cert=ee_cert,
        private_key=ee_key,
        for_pop=for_pop,
        is_sun_hybrid=is_sun_hybrid,
    )

    return validate_encrypted_content_info(
        enc_content_info=enc_content_info,
        content_encryption_key=encrypted_key,
        expected_raw_data=expected_raw_data,
    )


@keyword("Validate PWRI EnvelopedData")
def validate_pwri_enveloped_data(  # noqa D417 undocumented-param
    env_data: rfc9480.EnvelopedData,
    password: Union[str, bytes],
    pki_message: Optional[PKIMessageTMP] = None,
    cmp_protection_salt: Optional[bytes] = None,
    expected_size: Strint = 1,
    recip_info_index: Strint = 0,
    expected_raw_data: bool = False,
    skip_verify: bool = False,
) -> bytes:
    """Validate the `EnvelopedData` structure and decrypt the content.

    Arguments:
    ---------
        - `env_data`: The `EnvelopedData` structure to validate and decrypt.
        - `password`: The password used for decryption.
        - `pki_message`: The PKIMessage containing the `EnvelopedData` structure.
        - `cmp_protection_salt`: The salt used for password-based key derivation. Defaults to `None`.
        - `expected_size`: The expected size of the entries inside the `RecipientInfos` structure. Defaults to `1`.
        - `recip_info_index`: The index of the private key to extract. Defaults to `0`.
        - `expected_raw_data`: Return the raw DER-encoded bytes, which were decrypted. Defaults to `False`.
        - `skip_verify`: Whether to skip the verification of the PKIMessage protection. Defaults to `False`.

    Returns:
    -------
        - The decrypted raw DER-encoded bytes.

    Raises:
    ------
        - `ValueError`: If validation fails due to incorrect `RecipientInfo`, version mismatch, or decryption issues.
        - `ValueError`: If the `recipientInfos` size is not as expected.
        - `ValueError`: If the `RecipientInfo` type is not 'pwri'.
        - `ValueError`: If the `cmp_protection_salt` is not provided and the `pki_message` is not provided.
        - `ValueError`: If the pki_message is not protected with the same password.

    Examples:
    --------
    | ${decrypted_data}= | Validate PWRI Enveloped Data | ${env_data} | password=${password} \
    | pki_message=${pki_message} |

    """
    if cmp_protection_salt is None and pki_message is None:
        raise ValueError(
            "Either the `pki_message` or `cmp_protection_salt` must be provided for `pwri` recipient decryption,"
            "so that the `salt` can be compared."
        )
    recip_info = _validate_recip_info_size(
        env_data=env_data,
        expected_size=expected_size,
        recip_info_index=recip_info_index,
        expected_type="pwri",
    )
    enc_content_info: rfc5652.EncryptedContentInfo = env_data["encryptedContentInfo"]

    content_encryption_key = _extract_pwri_content_enc_key(
        pki_message=pki_message, password=password, recip_info=recip_info, cmp_protection_salt=cmp_protection_salt
    )
    decrypted_data = validate_encrypted_content_info(
        enc_content_info=enc_content_info,
        content_encryption_key=content_encryption_key,
        expected_raw_data=expected_raw_data,
    )

    if skip_verify:
        return decrypted_data

    if pki_message is None:
        raise ValueError("The `pki_message` must be provided to verify the protection of the message.")

    # MUST use the same shared secret.
    protectionutils.verify_pkimessage_protection(
        pki_message=pki_message,
        password=password,
    )
    return decrypted_data


@not_keyword
def validate_enveloped_data(
    env_data: rfc9480.EnvelopedData,
    pki_message: Optional[PKIMessageTMP] = None,
    password: Optional[Union[str, bytes]] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    kari_cert: Optional[rfc9480.CMPCertificate] = None,
    expected_type: Optional[str] = None,
    recip_info_index: int = 0,
    expected_size: int = 1,
    ee_key: Optional[EnvDataPrivateKey] = None,
    expected_raw_data: bool = False,
    for_pop: bool = False,
    allow_rsa_null: bool = False,
    cmp_protection_salt: Optional[bytes] = None,
) -> bytes:
    """Validate and decrypt the `EnvelopedData` structure from a PKIMessage and extract the private key.

    Verifies the recipient information, version, and expected recipient type.
    It calculates the content-encryption-key and decrypts the encrypted content.

    :param env_data: The `EnvelopedData` structure to validate and decrypt.
    :param pki_message: The PKIMessage containing the `EnvelopedData` structure.
    It is used to extract the protection salt in the case of `pwri`, or to validate the `senderKID` otherwise.
    :param password: Optional password for password-based recipient decryption.
    :param cmp_protection_cert: Optional CMP protection certificate for decryption of the content-encryption-key.
    :param kari_cert: Optional certificate for `KARI` recipient decryption.
    :param expected_type: Expected `RecipientInfo` type (`ktri`, `kari`, or `pwri`).
    :param recip_info_index: The index of the private key to extract.
    :param expected_size: The expected size of the entries inside the `RecipientInfos` structure.
    :param ee_key: Optional private key of the end-entity used for `kari` or `ktri`.
    :param expected_raw_data: Return the raw DER-encoded bytes, which were decrypted.
    :param for_pop: Whether the decryption is for proof-of-possession (POP) purposes.
    (skip the validation for the `rid` field)
    :param allow_rsa_null: Whether to allow RSA `NULL` as `parameters`. Defaults to `False`.
    :param cmp_protection_salt: Optional protection salt for `pwri` recipient decryption.
    :return: The decrypted raw DER-encoded bytes.
    :raises ValueError: If validation fails due to incorrect `RecipientInfo`, version mismatch, or decryption issues.
    """
    if expected_type is not None:
        if expected_type == "pwri":
            if password is None:
                raise ValueError("A password must be provided for `pwri` recipient decryption.")

            return validate_pwri_enveloped_data(
                env_data=env_data,
                password=password,
                pki_message=pki_message,
                cmp_protection_salt=cmp_protection_salt,
                expected_size=expected_size,
                recip_info_index=recip_info_index,
                expected_raw_data=expected_raw_data,
            )
        if expected_type == "kemri":
            if not isinstance(ee_key, KEMPrivateKey):
                raise ValueError("For validation of the KEMRecipientInfo must a KEMPrivateKey be provided.")

            return validate_kemri_enveloped_data(
                env_data=env_data,
                ee_key=ee_key,
                ee_cert=cmp_protection_cert,
                expected_size=expected_size,
                recip_info_index=recip_info_index,
                for_pop=for_pop,
                expected_raw_data=expected_raw_data,
            )

    enc_content_info: rfc5652.EncryptedContentInfo = env_data["encryptedContentInfo"]
    _ = _validate_recip_info_size(
        env_data=env_data,
        expected_size=expected_size,
        recip_info_index=recip_info_index,
        expected_type=expected_type,
    )

    content_encryption_key = extract_content_encryption_key(
        env_data,
        pki_message,
        password,
        ee_key,
        cmp_protection_cert,
        expected_size=expected_size,
        for_pop=for_pop,
        allow_rsa_null=allow_rsa_null,
        kari_cert=kari_cert,
        cmp_protection_salt=cmp_protection_salt,
    )

    decrypted_data = validate_encrypted_content_info(
        enc_content_info=enc_content_info,
        content_encryption_key=content_encryption_key,
        expected_raw_data=expected_raw_data,
    )

    return decrypted_data


@not_keyword
def validate_encrypted_content_info(
    enc_content_info: rfc5652.EncryptedContentInfo,
    content_encryption_key: bytes,
    expected_raw_data: bool = False,
) -> bytes:
    """Validate and decrypt the `EncryptedContentInfo` structure.

    :param enc_content_info: The `EncryptedContentInfo` structure to validate and decrypt.
    :param content_encryption_key: The key used for AES-CBC decryption.
    :param expected_raw_data: Whether the `SignedData` or raw bytes were expected.
    :return: The decrypted and validated private key from the `SignedData` structure.
    :raises ValueError: If validation fails due to incorrect content type, encryption algorithm, or key size mismatch.
    :raises BadAlgError: If the encryption algorithm is not AES-CBC.
    :raises BadAsn1Data: If the AES-CBC IV is not set in the `parameters` field.
    """
    if expected_raw_data:
        if enc_content_info["contentType"] != rfc5652.id_data:
            raise ValueError("The `contentType` MUST be id_data")

    elif enc_content_info["contentType"] != rfc5652.id_signedData:
        raise ValueError("The `contentType` MUST be id-signedData!")

    if enc_content_info["contentEncryptionAlgorithm"]["algorithm"] not in PROT_SYM_ALG:
        raise BadAlg("Only AES-CBC is allowed!")

    if not enc_content_info["contentEncryptionAlgorithm"]["parameters"].isValue:
        raise BadAsn1Data("AES-CBC must have the IV set inside the `parameters` field", overwrite=True)

    try:
        iv, rest = decoder.decode(
            enc_content_info["contentEncryptionAlgorithm"]["parameters"].asOctets(), rfc8018.AES_IV()
        )
    except pyasn1.error.PyAsn1Error as err:  # type: ignore
        raise BadAsn1Data("The decoding of 'AES_IV' structure failed!", overwrite=True) from err

    if rest:
        raise BadAsn1Data("AES_IV", remainder=rest)

    iv = iv.asOctets()

    enc_content = enc_content_info["encryptedContent"].asOctets()
    aes_name = PROT_SYM_ALG[enc_content_info["contentEncryptionAlgorithm"]["algorithm"]]

    key_size = int(aes_name.replace("_cbc", "").replace("aes", "")) // 8
    size = len(content_encryption_key)

    if size != key_size:
        logging.info("Content-encryption-key size: %s", str(size))
        logging.info("AES-CBC key size: %s", str(key_size))
        raise ValueError("The length of the derived key is different than what the AES-CBC algorithm indicates!")

    decrypted_data = cryptoutils.compute_aes_cbc(key=content_encryption_key, iv=iv, data=enc_content, decrypt=True)

    return decrypted_data


@not_keyword
def get_certificates_from_signed_data(certificates: rfc5652.CertificateSet) -> List[rfc9480.CMPCertificate]:
    """Extract and build a chain of certificates from a `SignedData` `CertificateSet` structure.

    :param certificates: The `CertificateSet` from a `SignedData` structure containing the certificates.
    :return: A list of CMP certificates, possibly in a chain.
    :raises NotImplementedError: If a certificate choice other than `certificate` is encountered.
    """
    certs = []

    for cert_choice in certificates:
        if cert_choice.getName() != "certificate":
            raise NotImplementedError(
                "Currently only the `certificate` choice inside the `SignedData` `certificates` attribute is supported!"
            )

        certs.append(cert_choice["certificate"])

    if len(certs) <= 1:
        return certs

    # Attempt to build the correct certificate chain
    cert_chain1 = certutils.build_chain_from_list(certs[0], certs[1:])
    cert_chain2 = certutils.build_chain_from_list(certs[-1], certs[:-1])
    if len(cert_chain1) > len(cert_chain2):
        out_chain = cert_chain1
    else:
        out_chain = cert_chain2

    if len(out_chain) != len(certs):
        logging.info("The certificate chain names:\n %s", utils.get_cert_chain_names(out_chain))
        logging.info("The KGA certificates names:\n %s", utils.get_cert_chain_names(certs))

        raise ValueError(
            "The KGA certificates contains additional certificates that are not in the chain! "
            f"Chain length: {len(out_chain)}. Certificates length: {len(certs)}"
        )

    return out_chain


def _validate_signature_and_algorithm_in_signed_data(
    data: dict, asym_key_package_bytes: bytes, encap_content_info_data: bytes, kga_certificate: rfc9480.CMPCertificate
) -> None:
    """Validate the signature and algorithm in the SignedData structure.

    :param data: A dictionary containing signature data extracted from the SignerInfo.
    :param asym_key_package_bytes: The bytes of the AsymmetricKeyPackage used for digest comparison.
    :param encap_content_info_data: The encoded EncapsulatedContentInfo data.
    :param kga_certificate: The KGA certificate used to verify the signature.
    :raises ValueError: If the digest does not match or signature verification fails.
    """
    signature = data["signature"]
    digest_econtent = data["digest_eContent"]

    hash_alg = keyutils.get_digest_alg_for_cmp(data["signatureAlgorithm"], kga_certificate)

    digest = compute_hash(hash_alg, asym_key_package_bytes)
    if digest_econtent != digest:
        logging.info("Digest inside the SignerInfo structure: %s", digest_econtent.hex())
        logging.info("Newly calculated digest with %s: %s", hash_alg, digest.hex())
        raise ValueError("The digest of the eContent is different!")

    logging.info("Hash algorithm used for signing the `encapContentInfo`: %s", hash_alg)
    logging.info("Signature of `encapContentInfo`: %s", signature.hex())
    certutils.verify_signature_with_cert(
        signature=signature, asn1cert=kga_certificate, data=encap_content_info_data, hash_alg=hash_alg
    )


@not_keyword
def validate_signed_data_structure(
    signed_data: rfc5652.SignedData,
    expected_size: Strint = 1,
    key_index: Strint = 0,
    trustanchors: str = "data/trustanchors",
    key_save_type: Optional[str] = None,
) -> PrivateKey:
    """Validate the structure and content of a `SignedData` object and extract the private key.

    :param signed_data: The `SignedData` object to validate.
    :param expected_size: The expected number of `DigestAlgorithmIdentifiers`.
    :param key_index: The index of the private key to extract.
    :param trustanchors: The path to the directory where the trust anchors are saved. Defaults to "data/trustanchors".
    :param key_save_type: The type of key export expected for a PQ key (e.g., "seed", "raw, "seed_and_raw").
    Defaults to `None`.
    :return: The extracted private key from the `AsymmetricKeyPackage`.
    :raises ValueError: If any validation step fails (e.g., incorrect version, digest mismatch, signature failure).
    """
    if int(signed_data["version"]) != 3:
        raise ValueError("The version of the `SignedData` structure MUST be 3!")

    dig_alg_ids: rfc5652.DigestAlgorithmIdentifiers = signed_data["digestAlgorithms"]
    if len(dig_alg_ids) != int(expected_size):
        raise ValueError("The `digestAlgorithms` field of the `SignedData` structure MUST be a sequence of size 1!")

    dig_alg_id: rfc5652.DigestAlgorithmIdentifier = dig_alg_ids[int(key_index)]
    encap_content_info: rfc5652.EncapsulatedContentInfo = signed_data["encapContentInfo"]

    if encap_content_info["eContentType"] != rfc5958.id_ct_KP_aKeyPackage:
        raise ValueError("The `eContentType` MUST be id-ct-KP-aKeyPackage!")

    asym_key_package_bytes = encap_content_info["eContent"].asOctets()
    asym_key_package, rest = decoder.decode(asym_key_package_bytes, rfc5958.AsymmetricKeyPackage())
    if rest != b"":
        raise ValueError("The decoding of the `AsymmetricKeyPackage` had a remainder!")

    new_private_key = validate_asymmetric_key_package(
        asym_key_package=asym_key_package,
        expected_size=expected_size,
        key_index=key_index,
        key_save_type=key_save_type,
    )

    # MUST contain the certificate for the private key used to sign
    # the SignedData content, together with its chain.
    certs = get_certificates_from_signed_data(signed_data["certificates"])
    kga_certificate = certs[0]

    data = check_signer_infos(
        signed_data["signerInfos"], dig_alg_id, kga_certificate=kga_certificate, expected_digests=expected_size
    )

    encap_content_info_data = encoder.encode(signed_data["encapContentInfo"])

    _validate_signature_and_algorithm_in_signed_data(
        data=data,
        asym_key_package_bytes=asym_key_package_bytes,
        encap_content_info_data=encap_content_info_data,
        kga_certificate=kga_certificate,
    )

    _validate_kga_certificate(
        certs=certs,
        asym_key_package_bytes=encap_content_info_data,
        signature=data["signature"],
        hash_alg=get_hash_from_oid(data["signatureAlgorithm"]["algorithm"], only_hash=True),
        trustanchors=trustanchors,
    )

    certutils.validate_cmp_extended_key_usage(kga_certificate, strictness=2, ext_key_usages="cmKGA")

    return new_private_key


def _check_is_hybrid_or_pq_sig_alg_cert_chain(certs: List[rfc9480.CMPCertificate]) -> bool:
    """Check if the certificate chain contains hybrid or PQ signature algorithm certificates.

    :param certs: A list of CMP certificates.
    :return: True if the certificate chain contains hybrid or PQ signature algorithm certificates, False otherwise.
    """
    support_openssl_pq = certutils.check_openssl_pqc_support()
    if support_openssl_pq:
        return certutils.pqc_algs_cannot_be_validated_with_openssl(certs=certs)
    for cert in certs:
        sig_alg = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        if sig_alg in COMPOSITE_SIG_OID_TO_NAME or sig_alg in PQ_SIG_OID_2_NAME:
            return True
    return False


def _validate_kga_certificate(
    certs: List[rfc9480.CMPCertificate],
    asym_key_package_bytes: bytes,
    signature: bytes,
    hash_alg: Optional[str],
    trustanchors: str,
):
    """Validate the Key Generation Authority (KGA) certificate chain.

    :param certs: A list of certificates from the `SignedData` structure.
    :param asym_key_package_bytes: The bytes of the `AsymmetricKeyPackage` used for signature validation.
    :param signature: The signature applied to the `SignedData` content.
    :param hash_alg: The hash algorithm used to compute the signature, if necessary.
    :param trustanchors: The path to the directory where the trust anchors are saved.
    :raises ValueError: If the signing certificate is not found, not trusted, or not in the expected position.
    """
    # TODO: ask Alex if self-signed certificates are acceptable for the Test-Suite.
    if len(certs) == 0:
        logging.info("Used a self-signed certificate to sign the `SignedData` content")
    else:
        certutils.certificates_are_trustanchors([certs[-1]], trustanchors=trustanchors)

        if _check_is_hybrid_or_pq_sig_alg_cert_chain(certs):
            logging.warning(
                "The certificate chain is a hybrid or PQ signature algorithm certificate chain, "
                "So it can not be verified with OpenSSL!"
            )
            if certutils.build_chain_from_list(certs[0], certs[1:]) != certs:
                raise ValueError(
                    "The certificate chain is not valid! "
                    "The first certificate in the chain must be the KGA certificate."
                )
            return

        certutils.verify_cert_chain_openssl(cert_chain=certs)
        signer_cert_index = checkutils.find_right_cert_pos(
            certs, asym_key_package_bytes, signature=signature, hash_alg=hash_alg
        )
        if signer_cert_index == -1:
            raise ValueError(
                "The `certificates` structure inside `SignedData` did not contain the certificate "
                "used for signing the `SignedData` content."
            )

        if signer_cert_index != 0:
            raise ValueError(
                f"Certificate used to sign the `SignedData` content was not at position 0 "
                f"but at position: {signer_cert_index}"
            )


@not_keyword
def check_signer_infos(
    signer_infos: rfc5652.SignerInfos,
    dig_alg_id_enc_content: rfc5652.DigestAlgorithmIdentifier,
    kga_certificate: rfc9480.CMPCertificate,
    expected_digests: Strint = 1,
    key_index: Strint = 0,
) -> dict:
    """Validate the `SignerInfos` structure of the `SignedData` and extract the signature and message digest.

    It checks that the signer information is correctly set, validates the signed attributes, ensures the signature
    algorithm is consistent with the KGA certificate, and verifies the digest algorithm used for the signed content.

    :param signer_infos: A `SignerInfos` sequence from the `SignedData` structure.
    :param dig_alg_id_enc_content: The digest algorithm identifier for the encapsulated content.
    :param kga_certificate: The CMP certificate of the Key Generation Authority (KGA).
    :param expected_digests: The expected number of digests inside the `SignedAttributes` structure.
    :param key_index: The index of the key to extract the necessary information from the `signerInfos` structure.
    :return: A dictionary containing the message digest (`digest_eContent`), the signature algorithm, and the signature.
    :raises ValueError: If validation fails due to incorrect signer information,
                        signature absence, or algorithm mismatch.
    """
    if len(signer_infos) != int(expected_digests):
        raise ValueError("The `SignerInfos` structure inside the `SignedData` must be a sequence of size 1!")

    signer_info: rfc5652.SignerInfo = signer_infos[int(key_index)]
    if int(signer_info["version"]) != 3:
        raise ValueError("The version of the `SignerInfo` structure must be 3!")

    # Must be the subjectKeyIdentifier of the KGA certificate
    sid: rfc5652.SignerIdentifier = signer_info["sid"]
    if sid.getName() != "subjectKeyIdentifier":
        raise ValueError(
            "The `sid` inside the `SignerInfo` structure must be the KGA certificate's subjectKeyIdentifier!"
        )

    sign_attr: rfc5652.SignedAttributes = signer_info["signedAttrs"]
    message_digest_value = validate_signed_attributes(sign_attr, expected_digests=int(expected_digests))

    sig_alg_id = signer_info["signatureAlgorithm"]
    digest_oid = signer_info["digestAlgorithm"]
    validate_signature_and_digest_alg(
        sig_alg_id=sig_alg_id, digest_alg_id=digest_oid, dig_alg_id_enc_content=dig_alg_id_enc_content
    )

    is_equal = checkutils.check_protection_alg_conform_to_spki(sig_alg_id, cert=kga_certificate)
    if not is_equal:
        alg = kga_certificate["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        raise ValueError(
            "The signature algorithm must be consistent with "
            "the subjectPublicKeyInfo field of the KGA certificate! "
            f"Found OID as signature algorithm: {may_return_oid_to_name(sig_alg_id['algorithm'])}, "
            f"KGA certificate OID as signature algorithm: {may_return_oid_to_name(alg)}"
        )

    # Must be the digital signature of the encapContentInfo
    if not signer_info["signature"].isValue:
        raise ValueError("The `signature` field was absent!")

    signature = signer_info["signature"].asOctets()
    return {"digest_eContent": message_digest_value, "signatureAlgorithm": sig_alg_id, "signature": signature}


def _is_signature_alg_id(alg_id: rfc5652.SignatureAlgorithmIdentifier) -> None:
    """Check if the algorithm identifier is a valid signature algorithm."""
    oid = alg_id["algorithm"]
    if oid in MSG_SIG_ALG:
        logging.info("Thea Signature algorithm is a MSG_SIG_ALG algorithm. Sig name: %s", MSG_SIG_ALG[oid])
    elif oid in COMPOSITE_SIG_OID_TO_NAME:
        logging.info(
            "The Signature algorithm is a Composite-Sig13 algorithm. Sig name: %s", COMPOSITE_SIG_OID_TO_NAME[oid]
        )
    elif oid in PQ_SIG_OID_2_NAME:
        logging.info("The Signature algorithm is a PQ_SIG algorithm. Sig name: %s", PQ_SIG_OID_2_NAME[oid])
    else:
        raise BadAlg(
            "The SignerInfo `signatureAlgorithm` OID is not supported or invalid! "
            f"Got: {may_return_oid_to_name(alg_id['algorithm'])}"
        )


@not_keyword
def validate_signature_and_digest_alg(
    sig_alg_id: rfc5652.SignatureAlgorithmIdentifier,
    digest_alg_id: rfc5652.DigestAlgorithmIdentifier,
    dig_alg_id_enc_content: rfc5652.DigestAlgorithmIdentifier,
) -> None:
    """Ensure that the same hash algorithm is used.

    :param sig_alg_id: The signature algorithm identifier used for the `encapContentInfo` signature.
    :param digest_alg_id: The digest algorithm identifier used to calculate the digest of the eContent.
    :param dig_alg_id_enc_content: The digest algorithm identifier from the encapsulated content.
    :raises ValueError: If the algorithms do not match or are not as expected.
    """
    # digestAlgorithms must be the same as in the digestAlgorithms field of encryptedContent
    other = encoder.encode(dig_alg_id_enc_content)
    this = encoder.encode(digest_alg_id)

    # as of RFC8419 section-3.1
    # Ed25519, the digestAlgorithm MUST be id-sha512
    # Ed448, the digestAlgorithm MUST be id-shake256 because CMP output length must be 64.
    if other != this:
        raise ValueError(
            "The `digestAlgorithm` inside the `SignerInfo` structure must be the same as in "
            "the `digestAlgorithms` field of `encryptedContent`"
        )

    _is_signature_alg_id(sig_alg_id)

    try:
        hash_name_dig = get_hash_from_oid(digest_alg_id["algorithm"])
    except ValueError as e:
        raise BadAlg(
            "The `digestAlgorithm` OID is not supported or invalid!."
            f"Got: {may_return_oid_to_name(digest_alg_id['algorithm'])}"
        ) from e

    hash_name_sig = get_digest_hash_alg_from_alg_id(alg_id=sig_alg_id)
    if hash_name_sig != hash_name_dig:
        raise ValueError(
            f"The hash algorithm used in `signatureAlgorithm` ({hash_name_sig}) and "
            f"`digestAlgorithm` ({hash_name_dig}) must be the same."
            f"Signature algorithm OID: {may_return_oid_to_name(sig_alg_id['algorithm'])}, "
        )


@not_keyword
def validate_signed_attributes(sign_attr: rfc5652.SignedAttributes, expected_digests: int = 1, index: int = 0) -> bytes:
    """Validate the `SignedAttributes` in a `SignerInfo` structure and extract the message digest.

    Checks the `SignedAttributes` for the required attributes `id-contentType` and `id-messageDigest`.
    It ensures that the content type is set to `id-ct-KP-aKeyPackage` and that the message digest attribute contains
    the correct size of elements, which represents the message digest of the encapsulated content (`eContent`).

    :param sign_attr: A `SignedAttributes` structure from the `SignerInfo`.
    :param expected_digests: The expected number of digests inside the `SignedAttributes` structure.
    :param index: The index of the digest to extract.
    :return: The message digest value as bytes.
    :raises ValueError: If the `id-contentType` or `id-messageDigest` attributes are missing,
                        or if their values are invalid.
    """
    found_id_content_type = False
    message_digest_value = None
    id_ct_kp_a_key_package_der = encoder.encode(rfc5958.id_ct_KP_aKeyPackage)

    for attr in sign_attr:
        if attr["attrType"] == rfc5652.id_contentType:
            for item in attr["attrValues"]:
                if item == id_ct_kp_a_key_package_der:
                    found_id_content_type = True

        elif attr["attrType"] == rfc5652.id_messageDigest:
            if len(attr["attrValues"]) != expected_digests:
                raise ValueError("The `id-messageDigest` `attrValues` must contain exactly one value!")

            val = attr["attrValues"][index]
            message_digest_value, _ = decoder.decode(val, rfc5652.MessageDigest())

    if message_digest_value is None:
        raise ValueError("The `id-messageDigest` attribute was not found in the `SignedAttributes` structure!")

    _check_required_attributes(found_id_content_type, message_digest_value, sign_attr)

    return message_digest_value


def _check_required_attributes(
    found_content_type: bool, message_digest_value: bytes, sign_attr: rfc5652.SignedAttributes
):
    """Validate the presence of required attributes: `id-contentType` and `id-messageDigest`.

    :param found_content_type: Boolean indicating whether `id-contentType` was found.
    :param message_digest_value: The message digest value extracted from the `id-messageDigest` attribute.
    :param sign_attr: The full `SignedAttributes` structure for logging purposes.
    :raises ValueError: If either `id-contentType` or `id-messageDigest` is missing.
    """
    if not found_content_type:
        logging.info("Values of signed attributes: %s", sign_attr.prettyPrint())
        raise ValueError(
            "The `id-contentType` must be inside the `SignedAttributes` structure "
            "with the value `id-ct-KP-aKeyPackage`."
        )

    if message_digest_value is None:
        logging.info("Values of signed attributes: %s", sign_attr.prettyPrint())
        raise ValueError(
            "The `id-messageDigest` must be inside the `SignedAttributes` structure containing "
            "the message digest of `eContent`."
        )


@not_keyword
def validate_asymmetric_key_package(
    asym_key_package: rfc5958.AsymmetricKeyPackage,
    expected_size: Strint = 1,
    key_index: Strint = 0,
    key_save_type: Optional[str] = None,
) -> PrivateKey:
    """Validate the structure of an `AsymmetricKeyPackage` and extract the private key.

    :param asym_key_package: The `AsymmetricKeyPackage` structure, which contains the private
                             and public key information.
    :param expected_size: The expected number of keys that are allowed to be present.
    :param key_index: The index of the key to extract.
    :param key_save_type: The type of key export expected for a PQ key (e.g., "seed", "raw, "seed_and_raw").
    Defaults to `None`.
    :return: The validated private key as a `PrivateKey` object.
    :raises ValueError: If the package contains more than one key, if the version is incorrect,
                        or if the private and public keys do not match.
    """
    if len(asym_key_package) != int(expected_size):
        raise ValueError(
            f"The `AsymmetricKeyPackage` structure must be a sequence of {expected_size}, "
            f"but got: {len(asym_key_package)}!"
        )

    one_asym_key: rfc5958.OneAsymmetricKey = asym_key_package[int(key_index)]
    if int(one_asym_key["version"]) != 1:
        raise InvalidKeyData(
            "The version of the `OneAsymmetricKey` structure must be 1 (indicating v2)!. "
            f"But Got: {int(one_asym_key['version'])}"
        )

    private_key = pq_logic.combined_factory.CombinedKeyFactory.load_private_key_from_one_asym_key(
        one_asym_key, must_be_version_2=True
    )

    if key_save_type is not None:
        pq_logic.combined_factory.CombinedKeyFactory.validate_key_export_type(
            private_key=private_key,  # type: ignore
            private_key_bytes=one_asym_key["privateKey"].asOctets(),
            key_save_type=key_save_type,
        )

    return private_key


@not_keyword
def validate_password_recipient_info(pwri_structure: rfc5652.PasswordRecipientInfo, cmp_protection_salt: bytes) -> dict:
    """Validate a `PasswordRecipientInfo` structure and extract parameters for key derivation.

    Ensures that the `PasswordRecipientInfo` structure conforms to the standard
    and extracts the necessary parameters for key derivation and decryption.

    :param pwri_structure: The `PasswordRecipientInfo` structure to validate.
    :param cmp_protection_salt: The salt used for MAC-based protection in the CMP message,
                                which must not be reused here.
    :return: A dictionary containing the PBKDF2 parameters (`parameters`) and the encrypted key (`encrypted_key`).
    :raises ValueError: If any of the following conditions are violated:
        The `version` field is missing or not equal to `3`.
        The `keyDerivationAlgorithm` field is missing or not one of the allowed algorithms.
        The `keyEncryptionAlgorithm` field is missing or not one of the allowed algorithms.
        The `encryptedKey` field is missing.
        The salt used in the key derivation matches the `cmp_protection_salt`, violating the standard's requirement
          for a different salt.
        Decoding of the PBKDF2 parameters resulted in unexpected extra data.
            The AES key wrap `parameters` field is present (must be absent).
    """
    if pwri_structure["version"].isValue:
        # According to RFC9483 Errata ID: 7833, must the `PasswordRecipientInfo` version be 3.
        if int(pwri_structure["version"]) != 3:
            raise ValueError("The `version` field of the `PasswordRecipientInfo` structure must be 3!")
    else:
        raise ValueError("The `version` field of the `PasswordRecipientInfo` structure was absent!")

    if not pwri_structure["keyDerivationAlgorithm"].isValue:
        raise ValueError("The `keyDerivationAlgorithm` field of the `PasswordRecipientInfo` structure was absent!")

    if pwri_structure["keyDerivationAlgorithm"]["algorithm"] not in KM_KD_ALG:
        raise ValueError(
            "The `keyDerivationAlgorithm` field of the `PasswordRecipientInfo` is only allowed to be `PBKDF2`."
        )

    if not pwri_structure["keyEncryptionAlgorithm"].isValue:
        raise ValueError("The `keyEncryptionAlgorithm` field of the `PasswordRecipientInfo` structure was absent!")

    if pwri_structure["keyEncryptionAlgorithm"]["algorithm"] not in KM_KW_ALG:
        raise ValueError(
            "The `keyEncryptionAlgorithm` field of the `PasswordRecipientInfo` is only allowed to be "
            "`id_aes128_wrap`, `id_aes192_wrap`, or `id_aes256_wrap`."
        )

    if not pwri_structure["encryptedKey"].isValue:
        raise ValueError("The `encryptedKey` field of the `PasswordRecipientInfo` structure was absent!")

    # Check for different salt as per Section 4.1.6.3.
    der_data = encoder.encode(pwri_structure["keyDerivationAlgorithm"]["parameters"])
    pbkdf2_params, rest = decoder.decode(der_data, rfc8018.PBKDF2_params())
    if rest != b"":
        raise ValueError("Decoding of PBKDF2 parameters resulted in unexpected extra data!")

    # The `parameters` field in `keyEncryptionAlgorithm` must be absent.
    if pwri_structure["keyEncryptionAlgorithm"]["parameters"].isValue:
        raise ValueError("The AES key wrap `parameters` field must be absent!")

    if pbkdf2_params["salt"].getName() != "specified":
        raise NotImplementedError("Only specified salt values are supported for PBKDF2.")

    pbkdf2_salt = pbkdf2_params["salt"]["specified"].asOctets()
    if pbkdf2_salt == cmp_protection_salt:
        raise ValueError(
            "The salt used in the key derivation must be different from the one used for MAC-based protection."
        )

    _check_aes_wrap_and_key_size(
        aes_name=KM_KW_ALG[pwri_structure["keyEncryptionAlgorithm"]["algorithm"]],
        size=int(pbkdf2_params["keyLength"]),
    )
    return {"parameters": pbkdf2_params, "encrypted_key": pwri_structure["encryptedKey"].asOctets()}


def _check_aes_wrap_and_key_size(aes_name: str, size: int):
    """Validate that the provided key size matches the expected AES key size.

    :param aes_name: The name of the AES algorithm (e.g., "aes128_wrap", "aes256_wrap").
    :param size: The size of the key in bytes.
    :raises ValueError: If the provided key size does not match the expected key size for the AES algorithm.
    """
    key_size = int(aes_name.replace("_wrap", "").replace("aes", "")) // 8

    if size != key_size:
        logging.info("pbkdf2_params key size: %s", str(size))
        logging.info("Expected AES key size: %s", str(key_size))
        raise ValueError("The length of the derived key is different than what the AES key wrap algorithm indicates!")


def _compute_password_based_key_management_technique(
    password: bytes, parameters: rfc8018.PBKDF2_params, encrypted_key: bytes
) -> bytes:
    """Derive a key using PBKDF2 and decrypt an encrypted key using AES key wrap.

    :param password: The password used for key derivation, provided as bytes.
    :param parameters: The PBKDF2 parameters for key derivation, including salt, iteration count, etc.
    :param encrypted_key: The encrypted key to be decrypted, provided as a byte string.
    :return: The decrypted key as a byte string.
    :raises ValueError: If key derivation or decryption fails.
    """
    derive_key = cryptoutils.compute_pbkdf2_from_parameter(parameters, key=password)
    logging.info("Derived `PWRI` key: %s", derive_key.hex())
    return keywrap.aes_key_unwrap(wrapping_key=derive_key, wrapped_key=encrypted_key)


def _ensure_can_validate_rid(for_pop: bool, cert: Optional[rfc9480.CMPCertificate]) -> rfc9480.CMPCertificate:
    """Ensure that the certificate can be used for validating the recipient info.

    :param for_pop: A boolean indicating whether the rid is validated for proof-of-possession.
    :param cert: The CMP certificate to validate.
    :return: The validated CMP certificate.
    :raises ValueError: If the certificate cannot be used for validation.
    """
    if not for_pop and cert is None:
        raise ValueError(
            "The CMP protection certificate is required to validate the `KeyAgreeRecipientInfo` structure!"
        )
    return cert  # type: ignore


@not_keyword
def validate_key_agree_recipient_info(
    kari_structure: rfc5652.KeyAgreeRecipientInfo,
    cmp_cert: Optional[rfc9480.CMPCertificate],
    expected_size: int = 1,
    key_index: int = 0,
    for_pop: bool = False,
) -> dict:
    """Validate a `KeyAgreeRecipientInfo` structure and extract key agreement parameters.

    :param kari_structure: The `KeyAgreeRecipientInfo` structure to validate.
    :param cmp_cert: The CMP protection certificate used for key agreement and validation.
    :param expected_size: The expected number of private keys to be present.
    :param key_index: The index of the private key to extract.
    :param for_pop: A boolean indicating whether the structure is used for proof-of-possession. Defaults to `False`.
    :return: A dictionary containing the `encrypted_key`, key encryption algorithm, and `ukm` or None if not set.
    :raises ValueError: If any required field is missing, invalid, or if the structure does not comply
    with expected values.
    """
    if not for_pop and cmp_cert is None:
        raise ValueError(
            "The CMP protection certificate is required, to validate the `KeyAgreeRecipientInfo` structure!"
        )

    if kari_structure["version"].isValue:
        if int(kari_structure["version"]) != 3:
            raise ValueError("The `version` field of the `KeyAgreeRecipientInfo` structure must be 3!")
    else:
        raise ValueError("The `version` field of the `KeyAgreeRecipientInfo` structure was absent!")

    if not kari_structure["originator"].isValue:
        raise ValueError("The `originator` field of the `KeyAgreeRecipientInfo` structure was absent!")

    if not for_pop:
        cert = _ensure_can_validate_rid(for_pop, cmp_cert)
        validate_originator_in_kari(kari_structure, cert)

    if not kari_structure["keyEncryptionAlgorithm"].isValue:
        raise ValueError("The `keyEncryptionAlgorithm` field of the `KeyAgreeRecipientInfo` structure was absent!")

    key_enc_alg: rfc5652.KeyEncryptionAlgorithmIdentifier = kari_structure["keyEncryptionAlgorithm"]
    if key_enc_alg["algorithm"] not in KM_KA_ALG:
        name = may_return_oid_to_name(key_enc_alg["algorithm"])
        raise ValueError(
            f"The key encryption algorithm in the `KeyAgreeRecipientInfo` structure is not supported. Got: {name}"
        )

    ukm = None
    if not kari_structure["ukm"].isValue:
        logging.info("Use of the `ukm` field of the `KeyAgreeRecipientInfo` is recommended.")
        if key_enc_alg["algorithm"] in ECMQV:
            raise ValueError("The `ukm` field is mandatory for the ECMQV key agreement algorithm but was not provided.")
    else:
        ukm = kari_structure["ukm"].asOctets()

    if not kari_structure["recipientEncryptedKeys"].isValue:
        raise ValueError("The `recipientEncryptedKeys` field of the `KeyAgreeRecipientInfo` structure was absent!")

    if len(kari_structure["recipientEncryptedKeys"]) != expected_size:
        raise ValueError("The `recipientEncryptedKeys` field must contain exactly one `RecipientEncryptedKey`.")

    recip_enc_keys: rfc5652.RecipientEncryptedKeys = kari_structure["recipientEncryptedKeys"]

    encrypted_key = check_recip_enc_key(recip_enc_keys[key_index], cmp_cert, for_pop=for_pop)

    return {"encrypted_key": encrypted_key, "key_enc_alg": key_enc_alg, "ukm": ukm}


@not_keyword
def compute_key_agreement_mechanism(
    ee_private_key: Union[x448.X448PrivateKey, x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey],
    cmp_protection_cert: rfc9480.CMPCertificate,
    key_enc_alg: rfc5652.KeyEncryptionAlgorithmIdentifier,
    encrypted_key: bytes,
    ukm: Optional[bytes] = None,
) -> bytes:
    """Perform the key agreement mechanism to compute and unwrap an encrypted key.

    :param ee_private_key: The end entity's private key, used for the key agreement. It can be an `x448.X448PrivateKey`,
    `x25519.X25519PrivateKey`, or `ec.EllipticCurvePrivateKey` object.

    :param cmp_protection_cert: The `x509.Certificate` used for key agreement.
    :param key_enc_alg: The `rfc5652.KeyEncryptionAlgorithmIdentifier` specifying the key encryption
    algorithm used for wrapping.
    :param encrypted_key: The encrypted key to be unwrapped using the wrapping key derived
        from the key agreement.
    :param ukm: Optional user keying material (UKM) to be included in the key agreement mechanism,
        if required by the algorithm.
    :return: The unwrapped key as bytes.
    """
    wrapping_key = process_kari(
        private_key=ee_private_key, ukm=ukm, cmp_prot_cert=cmp_protection_cert, alg_id=key_enc_alg
    )
    return keywrap.aes_key_unwrap(wrapping_key=wrapping_key, wrapped_key=encrypted_key)


@not_keyword
def check_recip_enc_key(
    recip_enc_key: rfc5652.RecipientEncryptedKey,
    cmp_cert: Optional[rfc9480.CMPCertificate],
    for_pop: bool = False,
) -> bytes:
    """Validate and extract the encrypted key from a `RecipientEncryptedKey` structure.

    :param recip_enc_key: The `RecipientEncryptedKey` structure to validate.
    :param cmp_cert: The CMP protection certificate to validate against.
    :param for_pop: A boolean indicating whether the validation is for proof-of-possession. Defaults to `False`.
    :return: The extracted encrypted key as bytes.
    :raises ValueError: If the recipient identifier does not match the CMP certificate's subjectKeyIdentifier
                        or issuer and serial number.
    """
    if not for_pop:
        rid: rfc5652.KeyAgreeRecipientIdentifier = recip_enc_key["rid"]
        ski = certextractutils.get_field_from_certificate(cmp_cert, extension="ski")  # type: ignore
        ski: Optional[bytes]
        # If the CMP protection certificate has a subjectKeyIdentifier (ski) it must be used.
        if ski is not None:
            if rid.getName() != "rKeyId":
                raise ValueError(
                    "The CMP protection certificate contains a subjectKeyIdentifier, "
                    f"so the recipient identifier must be of type `subjectKeyIdentifier`, but was: {rid.getName()}"
                )

            r_key_id = rid["rKeyId"]
            if r_key_id["subjectKeyIdentifier"].asOctets() != ski:
                raise ValueError(
                    "The subjectKeyIdentifier in the CMP protection certificate does not match "
                    "the recipient identifier in the `RecipientEncryptedKey`."
                )
        else:
            if cmp_cert is None:
                raise ValueError(
                    "The CMP protection certificate must be provided, to validate "
                    "the `KeyAgreeRecipientInfo` structure!"
                )

            if rid.getName() != "issuerAndSerialNumber":
                raise ValueError(
                    "If the CMP protection certificate does not contain a subjectKeyIdentifier, "
                    "the `issuerAndSerialNumber` choice must be used."
                )

            validate_issuer_and_serial_number_field(rid["issuerAndSerialNumber"], cmp_cert)

    enc_key = recip_enc_key["encryptedKey"].asOctets()
    return enc_key


@not_keyword
def validate_originator_in_kari(kari_structure: rfc5652.KeyAgreeRecipientInfo, cmp_cert: rfc9480.CMPCertificate):
    """Validate the `originator` field inside a `KeyAgreeRecipientInfo` structure.

    The `originator` field inside the `KeyAgreeRecipientInfo` structure must match the
    CMP protection certificate, either by the subjectKeyIdentifier extension, if present
    or issuer and serial number.

    :param kari_structure: The `KeyAgreeRecipientInfo` structure to validate.
    :param cmp_cert: The CMP protection certificate to validate against.
    :raises ValueError: If the `originator` field is of the wrong type or does not match the CMP certificate.
    """
    originator = kari_structure["originator"]

    cmp_cert_ski = certextractutils.get_field_from_certificate(cmp_cert, extension="ski")  # type: ignore
    cmp_cert_ski: Optional[bytes]

    if cmp_cert_ski is not None:
        if originator.getName() != "subjectKeyIdentifier":
            raise ValueError(
                "The CMP protection certificate has a `subjectKeyIdentifier` extension, "
                f"so the `originator` must be of type `subjectKeyIdentifier`, but was: {originator.getName()}"
            )
        if cmp_cert_ski != originator["subjectKeyIdentifier"].asOctets():
            logging.warning(
                "Expected SKI: %s. Got: %s", cmp_cert_ski.hex(), originator["subjectKeyIdentifier"].asOctets().hex()
            )
            raise ValueError(
                "The `subjectKeyIdentifier` in the CMP protection certificate does not match "
                "the `originator` field in the `KeyAgreeRecipientInfo` structure."
            )
    else:
        if originator.getName() != "issuerAndSerialNumber":
            raise ValueError(
                "If the CMP protection certificate does not contain a `subjectKeyIdentifier` extension, "
                "the `issuerAndSerialNumber` choice must be used."
            )
        validate_issuer_and_serial_number_field(originator["issuerAndSerialNumber"], cmp_cert)


@not_keyword
def validate_issuer_and_serial_number_field(structure: rfc5652.IssuerAndSerialNumber, cert: rfc9480.CMPCertificate):
    """Validate that the `IssuerAndSerialNumber` structure matches the issuer and serial number of a CMP certificate.

    :param structure: The `IssuerAndSerialNumber` structure to validate.
    :param cert: The CMP protection certificate.
    :raises ValueError: If the `issuer` or `serialNumber` fields do not match the CMP certificate.
    """
    if not compareutils.compare_pyasn1_names(structure["issuer"], cert["tbsCertificate"]["issuer"], "without_tag"):
        cert_name = utils.get_openssl_name_notation(cert["tbsCertificate"]["issuer"])
        structure_name = utils.get_openssl_name_notation(structure["issuer"])
        logging.info("IssuerAndSerialNumber: %s", structure_name)
        logging.info("CMP protection certificate: %s", cert_name)
        raise ValueError(
            "The issuer inside the `IssuerAndSerialNumber` structure was different from the provided certificate!"
        )

    if int(structure["serialNumber"]) != int(cert["tbsCertificate"]["serialNumber"]):
        logging.info("IssuerAndSerialNumber: %s", int(structure["serialNumber"]))
        logging.info("CMP protection certificate: %s", int(cert["tbsCertificate"]["serialNumber"]))

        raise ValueError(
            "The serialNumber inside the `IssuerAndSerialNumber` structure was different from the provided certificate!"
        )


@not_keyword
def validate_key_trans_recipient_info(
    ktri: rfc5652.KeyTransRecipientInfo,
    cmp_cert: Optional[rfc9480.CMPCertificate],
    for_pop: bool = False,
) -> dict:
    """Validate a `KeyTransRecipientInfo` structure.

    :param ktri: The `KeyTransRecipientInfo` structure to validate.
    :param cmp_cert: The CMP protection certificate to validate against.
    :param for_pop: A boolean indicating whether the validation is for proof-of-possession.
    (skip the validation).
    :return: A dictionary containing the `encrypted_key` and the key encryption algorithm OID.
    :raises ValueError: If validation of the version, recipient identifier, or key encryption algorithm fails.
    """
    logging.info("Starting validation of KeyTransRecipientInfo (ktri).")

    if int(ktri["version"]) != 2:
        raise ValueError("The `version` field of the `KeyTransRecipientInfo` structure MUST be 2.")

    if not for_pop:
        if cmp_cert is None:
            raise ValueError(
                "The CMP protection certificate must be provided, to validate the `KeyTransRecipientInfo` structure."
            )
        _check_recipient_identifier(ktri["rid"], cmp_cert)

    if not ktri["keyEncryptionAlgorithm"].isValue:
        raise ValueError("The `keyEncryptionAlgorithm` inside the `KeyTransRecipientInfo` structure is absent.")

    key_enc_alg: rfc5652.KeyEncryptionAlgorithmIdentifier = ktri["keyEncryptionAlgorithm"]
    if key_enc_alg["algorithm"] not in KM_KT_ALG:
        raise ValueError(
            "MUST be the algorithm identifier of the key transport algorithm. specified in [RFC9481], Section 4.2"
        )
    logging.info("Uses algorithm: %s", KM_KT_ALG.get(key_enc_alg["algorithm"]))

    if not ktri["encryptedKey"].isValue:
        raise ValueError("The `encryptedKey` was absent inside the `ktri` structure.")

    return {"encrypted_key": ktri["encryptedKey"].asOctets(), "key_enc_alg_id": key_enc_alg}


@not_keyword
def compute_key_transport_mechanism(
    ee_private_key: rsa.RSAPrivateKey,
    key_enc_alg_id: rfc5652.KeyEncryptionAlgorithmIdentifier,
    encrypted_key: bytes,
    allow_rsa_null: bool = False,
) -> bytes:
    """Decrypt an encrypted key using a key transport mechanism.

    :param ee_private_key: The recipient's RSA private key used for decryption.
    :param key_enc_alg_id: The key encryption algorithm identifier.
    :param encrypted_key: The encrypted key to be decrypted.
    :param allow_rsa_null: A boolean indicating whether the `rsaEncryption` algorithm with no parameters is allowed.
    Defaults to `False`.
    :return: The decrypted key as bytes.
    :raises ValueError: If the key encryption algorithm is unsupported or has incorrect parameters.
    """
    if key_enc_alg_id["algorithm"] == rfc9481.rsaEncryption:
        # because inside a certificate univ.Null("") is used for rsaEncryption.
        if compareutils.check_if_alg_id_parameters_is_absent(key_enc_alg_id, allow_null=allow_rsa_null):
            padding_val = padding.PKCS1v15()
        else:
            raise ValueError(
                "The `parameters` field must be absent for `rsaEncryption` key transport."
                f"Got: {key_enc_alg_id['parameters'].prettyPrint()}"
            )

    elif key_enc_alg_id["algorithm"] == rfc9481.id_RSAES_OAEP:
        param, rest = decoder.decode(key_enc_alg_id["parameters"], rfc4055.RSAES_OAEP_params())
        if rest != b"":
            raise ValueError("Decoding of `RSAES_OAEP_params` resulted in unexpected extra data.")
        padding_val = protectionutils.get_rsa_oaep_padding(param)

    else:
        logging.info("%s", key_enc_alg_id.prettyPrint())
        raise ValueError("Invalid OID. Only `rsaEncryption` and `RSAES_OAEP` are allowed for key transport.")

    return ee_private_key.decrypt(ciphertext=encrypted_key, padding=padding_val)


def _check_recipient_identifier(
    rid: rfc5652.RecipientIdentifier, cmp_cert: rfc9480.CMPCertificate, for_pop: bool = False
):
    """Validate the `RecipientIdentifier` field inside a `KeyTransRecipientInfo` structure.

    :param rid: The `RecipientIdentifier` structure to validate.
    :param cmp_cert: The CMP protection certificate.
    :param for_pop: A boolean indicating whether the validation is for proof-of-possession.
    (skip the validation).
    :raises ValueError: If the `RecipientIdentifier` does not match the CMP certificate.
    """
    if not rid.isValue:
        raise ValueError("The `rid` field must be set.")

    ski = certextractutils.get_field_from_certificate(cmp_cert, extension="ski")  # type: ignore
    ski: Optional[bytes]
    if ski is not None:
        if rid.getName() != "subjectKeyIdentifier":
            raise ValueError(
                "The CMP protection certificate has a `subjectKeyIdentifier` extension, "
                "so the `RecipientIdentifier` must be of type `subjectKeyIdentifier`, but was: `issuerAndSerialNumber`."
            )

        if ski != rid["subjectKeyIdentifier"].asOctets():
            logging.warning("Expected SKI: %s. Got: %s", ski.hex(), rid["subjectKeyIdentifier"].asOctets().hex())
            raise ValueError(
                "The `subjectKeyIdentifier` in the CMP protection certificate does not match "
                "the recipient identifier in the `KeyTransRecipientInfo` structure."
            )
    else:
        if not for_pop:
            validate_issuer_and_serial_number_field(rid["issuerAndSerialNumber"], cmp_cert)


@not_keyword
def validate_recip_identifier(server_cert: rfc9480.CMPCertificate, rid: rfc9629.RecipientIdentifier):
    """Validate the recipient identifier against the server certificate.

    If the `SubjectKeyIdentifier` extension is present, then must be used.

    :param server_cert: The server's certificate to compare against.
    :param rid: The recipient identifier to validate.
    :raises ValueError: If the recipient identifier does not match the expected values in the server certificate.
    """
    ski = certextractutils.get_field_from_certificate(server_cert, extension="ski")
    if ski is not None:
        if rid.getName() != "subjectKeyIdentifier":
            raise ValueError("The Server certificate had the `SubjectKeyIdentifier` extension, but it was not used.")

        if rid["subjectKeyIdentifier"].asOctets() != ski:
            raise ValueError(
                "The subjectKeyIdentifier in the CMP certificate does not match "
                "the recipient identifier in the `RecipientEncryptedKey`."
            )
    else:
        validate_issuer_and_serial_number_field(rid["issuerAndSerialNumber"], server_cert)


def _validate_kem_and_kemct(
    kem_recip_info: rfc9629.KEMRecipientInfo,
    private_key: Optional[KEMPrivateKey] = None,
    is_sun_hybrid: bool = False,
) -> bytes:
    """Validate the KEM and KEMCT fields in a KEMRecipientInfo structure.

    :param kem_recip_info: The KEMRecipientInfo structure to validate.
    :param private_key: The private key to validate the OID against. Defaults to `None`.
    :param is_sun_hybrid: A boolean indicating whether the KEM is a Sun hybrid KEM (skip the
    cert KEM oid and KEMRI oid validation. Defaults to `False`.
    :return: The encapsulated key as bytes.
    :raises ValueError: If the KEM or KEMCT fields are missing or invalid.
    """
    if not kem_recip_info["kem"].isValue:
        raise ValueError(
            "The `kem` (Key Encapsulation Mechanism) field of the `KEMRecipientInfo` structure is missing!"
        )

    kem_oid = kem_recip_info["kem"]["algorithm"]

    if kem_oid not in KEM_OID_2_NAME:
        raise BadAlg(f"The `kem` OID must be a known KEM id! Found: {kem_oid}")

    if not kem_recip_info["kemct"].isValue:
        raise ValueError("The `kemct` (encapsulated ciphertext) field of the `KEMRecipientInfo` structure is missing!")

    if private_key is not None and not is_sun_hybrid:
        key_oid = get_kem_oid_from_key(private_key)
        if key_oid != kem_oid:
            raise ValueError(
                f"The KEM OID {may_return_oid_to_name(kem_oid)} does not match the server's certificate OID "
                f"{may_return_oid_to_name(key_oid)}!"
            )

    return kem_recip_info["kemct"].asOctets()


def _validate_kemri_wrap_and_kek(
    kem_recip_info: rfc9629.KEMRecipientInfo,
) -> Tuple[rfc9629.KeyEncryptionAlgorithmIdentifier, int]:
    """Validate the `wrap` and `kekLength` fields in a `KEMRecipientInfo` structure.

    :param kem_recip_info: The `KEMRecipientInfo` structure to validate.
    :return: The key wrap algorithm identifier and the key encryption key length.
    :raises ValueError: If the `wrap` or `kekLength` fields are missing or invalid.
    """
    if not kem_recip_info["wrap"].isValue:
        raise ValueError(
            "The `wrap` (Key Wrap Algorithm Identifier) field of the `KEMRecipientInfo` structure is missing!"
        )

    if not kem_recip_info["kekLength"].isValue:
        raise ValueError("The `kekLength` field of the `KEMRecipientInfo` structure is missing!")

    wrap_algorithm = kem_recip_info["wrap"]["algorithm"]
    if wrap_algorithm not in KEY_WRAP_NAME_2_OID.values():
        raise ValueError(
            "The `wrap` (Key Wrap Algorithm Identifier) field of the "
            "`KEMRecipientInfo` structure must use a supported algorithm!"
        )
    kek_length = int(kem_recip_info["kekLength"])
    wrap_name = KEY_WRAP_OID_2_NAME[wrap_algorithm]
    expected_length = envdatautils.get_aes_keywrap_length(wrap_name)
    if kek_length != expected_length:
        raise ValueError(
            f"The `kekLength` field of the `KEMRecipientInfo` structure does not match the expected length "
            f"for the specified key wrap algorithm {wrap_name} ({expected_length} bytes)!"
        )

    return kem_recip_info["wrap"], kek_length


@not_keyword
def validate_kem_recip_info_structure(
    kem_recip_info: rfc9629.KEMRecipientInfo,
    server_cert: Optional[rfc9480.CMPCertificate] = None,
    for_pop: bool = False,
    private_key: Optional[KEMPrivateKey] = None,
    is_sun_hybrid: bool = False,
) -> dict:
    """Validate a `KEMRecipientInfo` structure and ensure all necessary items are correctly set.

    Ensures that the `KEMRecipientInfo` structure conforms to the standard by checking required
    fields and their correctness. This includes validating the recipient identifier (`rid`) against
    the provided server certificate, ensuring the KEM OID matches `rfc9629.id_ori_kem`, and verifying
    all other necessary fields.

    :param kem_recip_info: The `KEMRecipientInfo` structure to validate.
    :param server_cert: The server's certificate, used to validate the `rid` field.
    (needs to be present for validation of the `rid` field.)
    :param for_pop: A boolean indicating whether the validation is for proof-of-possession.
    (skip the validation).
    :param private_key: The KEM private key to validate the OID against.
    :param is_sun_hybrid: A boolean indicating whether the KEM is a Sun hybrid KEM (skip the
    cert KEM oid and KEMRI oid validation. Defaults to `False`.
    :return: A dictionary containing the following:
        - `encrypted_key`: The encrypted content encryption key (CEK) as bytes.
        - `kemct`: The encapsulated ciphertext as bytes.
        - `kdf_algorithm`: The OID of the key derivation function (e.g., HKDF).
        - `ukm`: The User Keying Material (UKM) as bytes, or None if absent.
        - `length`: The length of the key encryption key (KEK) in bytes.
        - `wrap`: The algorithm identifier for key wrapping.
    :raises ValueError: If any of the following conditions are violated:
        - The `version` field is missing or not equal to `0`.
        - The `rid` (Recipient Identifier) field is missing or invalid.
        - The `kem` (Key Encapsulation Mechanism) field is missing.
        - The `kemct` (encapsulated ciphertext) field is missing.
        - The `kdf` (Key Derivation Function) field is missing or incorrectly specified.
        - The `wrap` (Key Wrap Algorithm Identifier) field is missing or incorrectly specified.
        - The `encryptedKey` field is missing.
        - The `kekLength` field is missing or does not match the expected value.
    :raises BadAlg: If the `kem` OID is not a known KEM OID.
    """
    if not kem_recip_info["version"].isValue or int(kem_recip_info["version"]) != 0:
        raise ValueError("The `version` field of the `KEMRecipientInfo` structure must be present and equal to `0`!")

    if not kem_recip_info["rid"].isValue:
        raise ValueError("The `rid` (Recipient Identifier) field of the `KEMRecipientInfo` structure is missing!")

    if not for_pop:
        if server_cert is None:
            raise ValueError(
                "The `server_cert` must be provided for recipient identifier validation."
                "Inside the `KEMRecipientInfo` structure."
            )

        validate_recip_identifier(server_cert, kem_recip_info["rid"])

    kem_ct = _validate_kem_and_kemct(kem_recip_info, private_key, is_sun_hybrid)

    if not kem_recip_info["kdf"].isValue:
        raise ValueError("The `kdf` (Key Derivation Function) field of the `KEMRecipientInfo` structure is missing!")

    kdf_algorithm = kem_recip_info["kdf"]["algorithm"]
    if kdf_algorithm not in KDF_OID_2_NAME:
        raise ValueError(
            "The `kdf` (Key Derivation Function) field of the "
            "`KEMRecipientInfo` structure must use a supported algorithm! "
            f"Got: {may_return_oid_to_name(kdf_algorithm)}"
        )

    wrap_alg_id, kek_length = _validate_kemri_wrap_and_kek(kem_recip_info)

    if not kem_recip_info["encryptedKey"].isValue:
        raise ValueError("The `encryptedKey` field of the `KEMRecipientInfo` structure is missing!")

    ukm = None if not kem_recip_info["ukm"].isValue else kem_recip_info["ukm"].asOctets()

    return {
        "encrypted_key": kem_recip_info["encryptedKey"].asOctets(),
        "kemct": kem_ct,
        "kdf_algorithm": kem_recip_info["kdf"],
        "ukm": ukm,
        "length": kek_length,
        "wrap": wrap_alg_id,
    }


@not_keyword
def perform_rsa_kemri(
    private_key: Union[RSAPrivateKey, RSADecapKey],
    ct: bytes,
    key_length: int,
) -> bytes:
    """Perform RSA-KEM decapsulation.

    :param private_key: The RSA private key.
    :param ct: The ciphertext.
    :param key_length: The length of the derived key.
    :return: The shared secret.
    """
    if isinstance(private_key, RSAPrivateKey):
        private_key = RSADecapKey(private_key)

    return private_key.decaps(
        ct=ct,
        hash_alg="sha256",
        use_oaep=False,
        ss_length=key_length,
    )


@not_keyword
def process_kem_recip_info(
    kem_recip_info: rfc9629.KEMRecipientInfo,
    server_cert: Optional[rfc9480.CMPCertificate],
    private_key: KEMPrivateKey,
    for_pop: bool = False,
    is_sun_hybrid: bool = False,
) -> bytes:
    """Process a `KEMRecipientInfo` structure to derive the content encryption key (CEK).

    This function validates the `KEMRecipientInfo` structure, decapsulates the shared secret,
    derives the key encryption key (KEK) using HKDF, and finally unwraps the content encryption
    key (CEK) using the derived KEK.

    :param kem_recip_info: The `KEMRecipientInfo` structure containing necessary information.
    :param server_cert: The server's certificate, used to validate the `rid` field.
    :param private_key: The private key used for decapsulation.
    :param for_pop: A boolean indicating whether the validation is for proof-of-possession.
    (skipped `rid` validation).
    :param is_sun_hybrid: A boolean indicating whether the KEM is a Sun hybrid KEM (skip the
    cert KEM oid and KEMRI oid validation. Defaults to `False`.
    :return: The unwrapped content encryption key (CEK) as bytes.
    :raises ValueError: If validation or processing of the `KEMRecipientInfo` fails or the
    key cannot be unwrapped.
    """
    if not for_pop and server_cert is None:
        raise ValueError("The `server_cert` must be provided for recipient identifier validation.")

    validated_info = validate_kem_recip_info_structure(
        kem_recip_info=kem_recip_info,
        server_cert=server_cert,
        for_pop=for_pop,
        private_key=private_key,
        is_sun_hybrid=is_sun_hybrid,
    )

    if isinstance(private_key, CompositeKEMPrivateKey):
        shared_secret = private_key.decaps(validated_info["kemct"], use_in_cms=True)
    elif not isinstance(private_key, (RSAPrivateKey, RSADecapKey)):
        shared_secret = private_key.decaps(validated_info["kemct"])
    else:
        shared_secret = perform_rsa_kemri(
            private_key=private_key,
            ct=validated_info["kemct"],
            key_length=validated_info["length"],
        )
    logging.info("Shared secret: %s", shared_secret.hex())

    ukm_der = envdatautils.prepare_cmsori_for_kem_other_info(
        wrap_algorithm=validated_info["wrap"],
        kek_length=validated_info["length"],
        ukm=validated_info["ukm"],
    )

    key_enc_key = protectionutils.compute_kdf_from_alg_id(
        kdf_alg_id=validated_info["kdf_algorithm"],
        length=validated_info["length"],
        ss=shared_secret,
        ukm=ukm_der,
    )
    return keywrap.aes_key_unwrap(wrapping_key=key_enc_key, wrapped_key=validated_info["encrypted_key"])


@not_keyword
def compute_decaps_from_asn1(private_key: PQKEMPrivateKey, kem_recip_info: rfc9629.KEMRecipientInfo):
    """Perform decapsulation of a shared secret from an ASN.1-decoded KEMRecipientInfo structure.

    Extracts the encapsulated ciphertext (`kemct`) and associated parameters from the KEMRecipientInfo
    structure to derive the content encryption key (CEK).

    Currently supports only HKDF for key derivation.

    :param private_key: The private key used for decapsulation.
    :param kem_recip_info: The KEMRecipientInfo structure containing the encapsulated ciphertext,
                           key derivation parameters, and encrypted key.
    :return: The unwrapped content encryption key (CEK) as bytes.
    :raises KeyError: If the hash algorithm in the KEMRecipientInfo structure is not supported.
    :raises ValueError: If the derived KEK length does not match the expected length for the
                        specified key wrap algorithm.
    """
    kem_ct = kem_recip_info["kemct"].asOctets()
    kek_length = int(kem_recip_info["kekLength"])
    shared_secret = private_key.decaps(kem_ct)
    hash_alg = HKDF_NAME_2_OID[kem_recip_info["kdf"]["algorithm"]].split("-")[1]
    ukm = b""
    if kem_recip_info["ukm"].isValue:
        ukm = kem_recip_info["ukm"].asOctets()

    key_enc_key = cryptoutils.compute_hkdf(key_material=shared_secret, info=ukm, hash_alg=hash_alg, length=kek_length)

    key_wrap_oid = kem_recip_info["wrap"]["algorithm"]
    aes_length = envdatautils.get_aes_keywrap_length(KEY_WRAP_OID_2_NAME[key_wrap_oid])
    kek_length = len(key_enc_key)
    if kek_length != aes_length:
        raise ValueError(
            f"The derived KEK length ({kek_length} bytes) does not match the expected length "
            f"for the key wrap algorithm '{KEY_WRAP_OID_2_NAME[key_wrap_oid]}' ({aes_length} bytes)."
        )

    content_enc_key = keywrap.aes_key_unwrap(
        wrapping_key=key_enc_key, wrapped_key=kem_recip_info["encryptedKey"].asOctets()
    )

    return content_enc_key


@keyword(name="Validate KARI EnvelopedData")
def validate_kari_env_data(  # noqa: D417 undocumented-params
    env_data: rfc9480.EnvelopedData,
    recip_private_key: ECDHPrivateKey,
    cmp_protection_cert: rfc9480.CMPCertificate,
    expected_raw_data: bool = False,
    for_pop: bool = False,
) -> bytes:
    """Validate the KeyAgreeRecipientInfo structure inside an `EnvelopedData` structure.

    Supports ECDH, cofactor ECDH, and ECMQV key agreement mechanisms.
    All use the KDF2 as the key derivation function.

    Arguments:
    ---------
        - `env_data`: The `EnvelopedData` structure to validate.
        - `recip_private_key`: The recipient's private key.
        - `cmp_protection_cert`: The CMP protection certificate.
        - `expected_raw_data`: If `True` the raw data is expected. Defaults to `False`.
        - `for_pop`: If `True` the recipient info RID is not checked. Defaults to `False`.

    Returns:
    -------
        - `bytes`: The decrypted data if validation is successful.

    Raises:
    ------
        - `ValueError`: If the validation fails.

    Examples:
    --------
    | ${der_data}= | Validate KARI EnvelopedData | ${env_data} | ${key} | ${cert} |
    | ${der_data}= | Validate KARI EnvelopedData | ${env_data} | ${key} | ${cert} | True |

    """
    recip_info = _validate_recip_info_size(
        env_data=env_data,
        expected_size=1,
        recip_info_index=0,
        expected_type="kari",
    )

    enc_content_info = env_data["encryptedContentInfo"]
    params = validate_key_agree_recipient_info(
        kari_structure=recip_info["kari"],
        cmp_cert=cmp_protection_cert,
        for_pop=for_pop,
    )

    content_encryption_key = compute_key_agreement_mechanism(
        cmp_protection_cert=cmp_protection_cert,
        ee_private_key=recip_private_key,
        key_enc_alg=params["key_enc_alg"],
        encrypted_key=params["encrypted_key"],
        ukm=params["ukm"],
    )

    decrypted_data = validate_encrypted_content_info(
        enc_content_info=enc_content_info,
        content_encryption_key=content_encryption_key,
        expected_raw_data=expected_raw_data,
    )
    return decrypted_data
