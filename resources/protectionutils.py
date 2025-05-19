# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utilities that generate and parse protection-related structures in PKIMessage."""

import logging
import math
import os
from typing import List, Optional, Tuple, Union

import pyasn1.error
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import (
    rfc4055,
    rfc4210,
    rfc5280,
    rfc5480,
    rfc5990,
    rfc8017,
    rfc8018,
    rfc9044,
    rfc9480,
    rfc9481,
)
from robot.api.deco import keyword, not_keyword

from pq_logic import pq_verify_logic
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey, CompositeSig04PublicKey
from pq_logic.keys.sig_keys import MLDSAPublicKey
from pq_logic.pq_utils import get_kem_oid_from_key
from pq_logic.tmp_oids import COMPOSITE_SIG03_OID_2_NAME, COMPOSITE_SIG04_OID_2_NAME, id_it_KemCiphertextInfo
from resources import (
    certbuildutils,
    certextractutils,
    certutils,
    cmputils,
    convertutils,
    cryptoutils,
    keyutils,
    oid_mapping,
    prepare_alg_ids,
    utils,
)
from resources.asn1_structures import (
    KemBMParameterAsn1,
    KemCiphertextInfoAsn1,
    KemCiphertextInfoValue,
    KemOtherInfoAsn1,
    PKIMessageTMP,
    ProtectedPartTMP,
)
from resources.asn1utils import try_decode_pyasn1
from resources.convertutils import (
    ensure_is_kem_priv_key,
    ensure_is_kem_pub_key,
    ensure_is_sign_key,
    str_to_bytes,
    subject_public_key_info_from_pubkey,
)
from resources.data_objects import FixedSHAKE128, FixedSHAKE256
from resources.exceptions import (
    BadAlg,
    BadDataFormat,
    BadMacProtection,
    BadMessageCheck,
    InvalidKeyCombination,
    LwCMPViolation,
    UnknownOID,
)
from resources.oid_mapping import (
    get_alg_oid_from_key_hash,
    get_hash_from_oid,
    hash_name_to_instance,
    may_return_oid_to_name,
)
from resources.oidutils import (
    AES_GMAC_OID_2_NAME,
    ALL_KNOWN_OIDS_2_NAME,
    CMS_COMPOSITE03_OID_2_NAME,
    HKDF_OID_2_NAME,
    HMAC_OID_2_NAME,
    KMAC_OID_2_NAME,
    LWCMP_MAC_OID_2_NAME,
    MSG_SIG_ALG,
    PQ_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SHA2_NAME_2_OID,
    SHA_OID_2_NAME,
    SUPPORTED_MAC_OID_2_NAME,
    SYMMETRIC_PROT_ALGO,
    TRAD_SIG_OID_2_NAME,
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
    id_KemBasedMac,
)
from resources.suiteenums import ProtectedType, ProtectionAlgorithm
from resources.typingutils import (
    CertObjOrPath,
    ECDHPrivateKey,
    ECDHPublicKey,
    ECVerifyKey,
    KEMPrivateKey,
    KEMPublicKey,
    PrivateKey,
    PublicKey,
    SignKey,
    VerifyKey,
)


def _compare_alg_id(
    alg_id1: rfc9480.AlgorithmIdentifier, alg_id2: rfc9480.AlgorithmIdentifier, allow_null: bool = False
) -> bool:
    """Compare two `AlgorithmIdentifier` structures.

    If `allow_null` is True, the entire structures are DER-encoded and compared.

    :param alg_id1: The first `AlgorithmIdentifier` to compare.
    :param alg_id2: The second `AlgorithmIdentifier` to compare.
    :param allow_null: If True, allows absent values to have the value `NULL` for legacy systems.
    :return: True if equal; False otherwise.
    """
    if allow_null:
        alg_id1_der = encoder.encode(alg_id1)
        alg_id2_der = encoder.encode(alg_id2)
        return alg_id1_der == alg_id2_der

    if alg_id1["algorithm"] != alg_id2["algorithm"]:
        return False

    if alg_id2["parameters"].isValue:
        return False

    return True


def _compare_pbm_parameters(
    param1: rfc9480.PBMParameter, param2: bytes, same_salt: bool = False, allow_null: bool = False
) -> bool:
    """Compare the sent and received `rfc9480.PBMParameter` structure.

    :param param1: Our sent `PBMParameter` structure to compare.
    :param param2: The second `PBMParameter` structure as a byte sequence extracted from the
        `parameters` field of the `protectionAlg`.
    :param allow_null: If True, allows `parameters` fields in `owf` and `mac` to be either unset
        or set to NULL in `param2`.
    :param same_salt: A flag to indicate if the salt values in both parameters should match exactly.
    :return: True if all components match; False otherwise.
    """
    try:
        param2, _ = decoder.decode(param2, asn1Spec=rfc9480.PBMParameter())
    except pyasn1.error.PyAsn1Error:
        logging.info("Could not decode `PBMParameter` structure.")
        return False

    salt_mismatch = param1["salt"].asOctets() != param2["salt"].asOctets()  # type: ignore

    if (salt_mismatch and same_salt) or (not salt_mismatch and not same_salt):
        return False

    if int(param1["iterationCount"]) != int(param2["iterationCount"]):  # type: ignore
        return False

    if not _compare_alg_id(param1["owf"], param2["owf"], allow_null):  # type: ignore
        return False

    if not _compare_alg_id(param1["mac"], param2["mac"], allow_null):  # type: ignore
        return False

    return True


def _compare_pbkdf2_parameters(
    param1: rfc8018.PBKDF2_params,
    param2: rfc8018.PBKDF2_params,
    allow_null: bool = False,
    same_salt: bool = False,
) -> bool:
    """Compare the sent and received `PBKDF2_params` structure.

    :param param1: The first `PBKDF2Params` structure.
    :param param2: The second `PBKDF2Params` structure to compare.
    :param allow_null: If True, allows `parameters` fields for `prf` and `salt` `otherSource`
        to be NULL instead of absent.
    :param same_salt: A flag to indicate if the salt value must be the same or different.
    :return: True if all components match; False otherwise.
    """
    logging.info("Comparing PBKDF2Params:")
    logging.info("Sent PBKDF2Params:\n%s", param1.prettyPrint())
    logging.info("Server PBKDF2Params:\n%s", param2.prettyPrint())

    if param1["salt"].getName() != param2["salt"].getName():
        logging.info("Mismatch in `salt` CHOICE type.")
        return False

    if param2["salt"].getName() == "specified":
        is_eq = param1["salt"]["specified"] == param2["salt"]["specified"]
        if (not is_eq and same_salt) or (is_eq and not same_salt):
            return False

    elif param1["salt"].getName() == "otherSource":
        if not _compare_alg_id(param1["salt"]["otherSource"], param2["salt"]["otherSource"], allow_null):
            return False

    if int(param1["iterationCount"]) != int(param2["iterationCount"]):
        return False

    if param1["keyLength"].isValue or param2["keyLength"].isValue:
        if int(param1["keyLength"]) != int(param2["keyLength"]):
            return False

    return _compare_alg_id(param1["prf"], param2["prf"], allow_null)


def _compare_pbmac1_parameters(
    param1: bytes,
    param2: bytes,
    allow_null: bool = False,
    same_salt: bool = False,
) -> bool:
    """Compare the sent and received `PBMAC1_params` structure.

    :param param1: The first parameters `PBMAC1Parameters` structure.
    :param param2: The server's `PBMAC1Parameters` structure as bytes extracted directly from the
        `parameters` field of the `protectionAlg`.
    :param allow_null: If True, allows `parameters` fields in `keyDerivationFunc` and
        `messageAuthScheme` to be either unset or set to NULL in `param2`.
    :param same_salt: A flag to indicate if the salt value must be the same or different.
    :return: True if all components match; False otherwise.
    """
    logging.info("Comparing PBMAC1 `parameters`:")

    try:
        param1, _ = decoder.decode(param1, asn1Spec=rfc8018.PBMAC1_params())
        param2, _ = decoder.decode(param2, asn1Spec=rfc8018.PBMAC1_params())
    except pyasn1.error.PyAsn1Error:
        logging.info("Could not decode `PBMAC1_params` structure.")
        return False

    try:
        dec_key_der_func, _ = decoder.decode(
            (param1["keyDerivationFunc"]["parameters"]),  # type: ignore
            asn1Spec=rfc8018.PBKDF2_params(),  # type: ignore
        )
        dec_key_der_func2, _ = decoder.decode(
            (param2["keyDerivationFunc"]["parameters"]),  # type: ignore
            asn1Spec=rfc8018.PBKDF2_params(),  # type: ignore
        )
    except pyasn1.error.PyAsn1Error:
        logging.info("Could not decode `PBKDF2_params` structure.")
        return False

    is_eq = _compare_pbkdf2_parameters(dec_key_der_func, dec_key_der_func2, allow_null, same_salt)
    if not is_eq:
        raise ValueError(
            "Mismatch in `keyDerivationFunc` field between the sent and server PBMAC1Parameters structures."
        )

    if not _compare_alg_id(param1["messageAuthScheme"], param2["messageAuthScheme"], allow_null):  # type: ignore
        raise ValueError(
            "Mismatch in `messageAuthScheme` field between the sent and server PBMAC1Parameters structures."
        )

    return True


@not_keyword
def add_cert_to_pkimessage_used_by_protection(
    pki_message: PKIMessageTMP,
    private_key: PrivateKey,
    cert: Optional[rfc9480.CMPCertificate] = None,
):
    """Ensure that `extraCerts` of a signature-protected `PKIMessageTMP` starts with a CMP-protection certificate.

    If a certificate is provided, it checks that the first certificate matches the provided CMP-protection certificate.
    If no `cert` is provided, it generates a new one using the given `private_key`.

    :param pki_message: `PKIMessageTMP` to which the certificate protection is to be applied.
    :param private_key: The private key used for signing the structure.
    :param cert: A certificate to use as the CMP-protection certificate.
    :raises ValueError: If the first certificate in `extraCerts` is not the CMP-protection certificate as specified in
        RFC 9483, Section 3.3, or if there is a signature verification failure.
    :return: None
    """
    if cert is not None:
        if not pki_message["extraCerts"].hasValue():
            pki_message["extraCerts"] = cmputils.prepare_extra_certs([cert])
        else:
            first_cert = encoder.encode(pki_message["extraCerts"][0])
            cert_encoded = encoder.encode(cert)
            # RFC 9483, Section 3.3, the first certificate must be the CMP-protection certificate.
            if first_cert != cert_encoded:
                logging.warning(
                    "First Cert in PKIMessage: %s, \nCertificate Provided: %s",
                    pki_message["extraCerts"][0].prettyPrint(),
                    cert.prettyPrint(),
                )
                raise ValueError(
                    "The first certificate must be the CMP-protection certificate as specified "
                    "in RFC 9483, Section 3.3."
                )

    elif not pki_message["extraCerts"].hasValue():
        # Contains no certificates, so a new one is added.
        cert, private_key = certbuildutils.build_certificate(
            private_key=private_key,
        )
        pki_message["extraCerts"] = cmputils.prepare_extra_certs([cert])  # type: ignore

    else:
        # The first certificate must be a CMP-protection Certificate.
        # To ensure the signing key for the PKIMessage structure and
        # public key in the certificate matches, the following `data` is signed.
        data = b"test_if_keypair_matches"
        cert = pki_message["extraCerts"][0]
        signature = cryptoutils.sign_data(
            key=private_key,  # type: ignore
            data=data,
            hash_alg="sha256",
        )

        try:
            cryptoutils.verify_signature(
                public_key=certutils.load_public_key_from_cert(cert),  # type: ignore
                signature=signature,
                data=data,
                hash_alg="sha256",
            )
        except InvalidSignature as err:
            raise ValueError(
                "The first certificate must be the CMP-protection certificate, see RFC 9483, Section 3.3."
            ) from err


def _compute_pbmac1_from_param(
    prot_params: Union[bytes, rfc8018.PBMAC1_params],  # type: ignore
    password: bytes,
    data: bytes,
    unsafe_decoding: bool,
    enforce_lwcmp: bool = False,
) -> bytes:
    """Compute the PBMAC1 with the DER-encoded bytes or the structure.

    :param prot_params: The DER-encoded `parameters` or the `PBMAC1_params` structure.
    :param password: The shared secret used for the key derivation.
    :param data: The data to authenticate.
    :param unsafe_decoding: If True, allows extra data (rest) after decoding the structure.
    :param enforce_lwcmp: If True, enforces that the hash algorithm is the same for `prf` and `mac`.
    :return: The computed message authentication code value.
    """
    if not isinstance(prot_params, rfc8018.PBMAC1_params):
        prot_params, rest = decoder.decode(prot_params, rfc8018.PBMAC1_params())
        if rest != b"" and not unsafe_decoding:
            raise ValueError("The decoding of `PBMAC1_params` structure had a remainder!")

    prot_params: rfc8018.PBMAC1_params

    if not isinstance(prot_params["keyDerivationFunc"]["parameters"], rfc8018.PBKDF2_params):
        pbkdf2_param, rest = decoder.decode(prot_params["keyDerivationFunc"]["parameters"], rfc8018.PBKDF2_params())
        if rest != b"" and not unsafe_decoding:
            raise ValueError("The decoding of `PBKDF2_params` structure had a remainder!")

    else:
        pbkdf2_param = prot_params["keyDerivationFunc"]["parameters"]  # type: ignore

    hash_alg = HMAC_OID_2_NAME[prot_params["messageAuthScheme"]["algorithm"]].split("-")[1]  # type: ignore
    pbkdf2_hash_alg = get_hash_from_oid(pbkdf2_param["prf"]["algorithm"])
    if pbkdf2_hash_alg != hash_alg and enforce_lwcmp:
        raise LwCMPViolation(
            "The `owf` and `mac` fields in `PBMAC1Parameters` must be the same hash algorithm."
            f"MAC: {hash_alg}, PBKDF2: {pbkdf2_hash_alg}"
        )
    if enforce_lwcmp and hash_alg not in SHA2_NAME_2_OID:
        raise BadAlg("The `PBMAC1Parameters` must use SHA-2 (`enforce_lwcmp` is True).")

    derived_key = cryptoutils.compute_pbkdf2_from_parameter(pbkdf2_param, key=password)

    mac = cryptoutils.compute_hmac(key=derived_key, data=data, hash_alg=hash_alg)
    return mac


@not_keyword
def dh_based_mac_derive_key(
    basekey: bytes,
    desired_length: int,
    owf: str,
) -> bytes:
    """Derive a key for DHBasedMAC protection, if the key size is too short.

    :param basekey: The base key, which is the MAC of the shared secret.
    :param desired_length: The desired length of the derived key.
    :param owf: The one-way function name, to use for key derivation.
    :return: The derived key.
    """
    basekey_length_bytes = len(basekey)

    derived_key = bytearray(basekey)

    if desired_length <= basekey_length_bytes:
        return bytes(derived_key[:desired_length])

    rounds = math.ceil(desired_length / basekey_length_bytes)

    for i in range(1, rounds):
        next_input = f"{i}".encode("ascii") + basekey
        tmp = cryptoutils.compute_hash(alg_name=owf, data=next_input)
        derived_key.extend(tmp)

    return bytes(derived_key[:desired_length])


def _get_aes_length(alg_name: str) -> int:
    """Get the length of the AES key based on the algorithm name.

    :param alg_name: The name of the AES-GMAC algorithm.
    :return: The length of the AES key.
    """
    if "128" in alg_name:
        return 16
    if "192" in alg_name:
        return 24
    if "256" in alg_name:
        return 32
    raise ValueError(f"Unsupported AES-GMAC key length: {alg_name}")


@not_keyword
def compute_dh_based_mac_from_alg_id(
    shared_secret: bytes, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, ignore_parameters: bool = False
) -> bytes:
    """Compute the DHBasedMac message authentication code value.

    :param shared_secret: The shared secret used for the key derivation.
    :param alg_id: The `AlgorithmIdentifier` structure containing the DHBasedMac parameters.
    :param data: The data to authenticate.
    :param ignore_parameters: If True, do not check the parameters filed of the `alg_id` structure.
    :return: The computed message authentication code value.
    """
    if not isinstance(alg_id["parameters"], rfc9480.DHBMParameter):
        params, rest = decoder.decode(alg_id["parameters"], rfc9480.DHBMParameter())
        if rest != b"":
            raise ValueError("The decoding of `DHBMParameter` structure had a remainder!")
    else:
        params = alg_id["parameters"]

    owf_oid = params["owf"]
    if owf_oid["parameters"].isValue and ignore_parameters:
        raise ValueError("The `owf` field must not have parameters.")

    owf = SHA_OID_2_NAME[owf_oid["algorithm"]]
    derived_key = oid_mapping.compute_hash(alg_name=owf, data=shared_secret)

    mac_alg_oid = params["mac"]["algorithm"]

    if mac_alg_oid in HMAC_OID_2_NAME:
        mac_alg = HMAC_OID_2_NAME[mac_alg_oid].split("-")[1]
        mac = cryptoutils.compute_hmac(key=derived_key, data=data, hash_alg=mac_alg)
    elif mac_alg_oid in AES_GMAC_OID_2_NAME:
        length = _get_aes_length(AES_GMAC_OID_2_NAME[mac_alg_oid])

        derived_key = dh_based_mac_derive_key(basekey=shared_secret, desired_length=length, owf=owf)
        if not isinstance(params["mac"]["parameters"], rfc9044.GCMParameters):
            gmac_params, rest = decoder.decode(params["mac"]["parameters"], rfc9044.GCMParameters())
        else:
            gmac_params = params["mac"]["parameters"]

        nonce = gmac_params["nonce"].asOctets()
        mac = cryptoutils.compute_gmac(data=data, key=derived_key, iv=nonce)

    elif mac_alg_oid in KMAC_OID_2_NAME:
        derived_key = dh_based_mac_derive_key(basekey=shared_secret, desired_length=32, owf=owf)
        mac = cryptoutils.compute_kmac_from_alg_id(alg_id=params["mac"], data=data, key=derived_key)
    else:
        raise ValueError(f"Unsupported MAC algorithm for DHBasedMAC: {may_return_oid_to_name(mac_alg_oid)}")

    logging.info("Derived Key: %s", derived_key.hex())
    logging.info("Computed DHBasedMAC: %s", mac.hex())
    return mac


@not_keyword
def compute_and_prepare_mac(
    key: bytes, data: bytes, mac_alg: str, **params
) -> Tuple[rfc9480.AlgorithmIdentifier, bytes]:
    """Compute the MAC value and prepare the `AlgorithmIdentifier` structure.

    :param key: The key to use for the MAC computation.
    :param data: The data to authenticate.
    :param mac_alg: THe name of the MAC algorithm to use.
    :param params: Parameters to use for the MAC computation.
    :return: A tuple containing the `AlgorithmIdentifier` structure and the computed MAC value.
    """
    alg_id = _prepare_mac_alg_id(protection=mac_alg, **params)
    mac_value = compute_mac_from_alg_id(key=key, alg_id=alg_id, data=data)
    return alg_id, mac_value


@not_keyword
def compute_mac_from_alg_id(key: bytes, alg_id: rfc9480.AlgorithmIdentifier, data: bytes) -> bytes:
    """Compute the MAC value based on the provided `AlgorithmIdentifier` structure.

    :param key: The key to use for the MAC computation.
    :param alg_id: The `AlgorithmIdentifier` structure containing the MAC parameters.
    :param data: The data to authenticate.
    :return: The computed MAC value.
    """
    protection_type_oid = alg_id["algorithm"]
    prot_params = alg_id["parameters"]

    unsafe_decoding = True

    if protection_type_oid in HMAC_OID_2_NAME:
        hash_alg = HMAC_OID_2_NAME[protection_type_oid].split("-")[1]
        return cryptoutils.compute_hmac(data=data, key=key, hash_alg=hash_alg)

    if protection_type_oid in KMAC_OID_2_NAME:
        return cryptoutils.compute_kmac_from_alg_id(alg_id=alg_id, data=data, key=key)

    if protection_type_oid == rfc8018.id_PBMAC1:
        mac = _compute_pbmac1_from_param(
            prot_params=prot_params, password=key, data=data, unsafe_decoding=unsafe_decoding
        )

        return mac

    if protection_type_oid == rfc4210.id_PasswordBasedMac:
        if not isinstance(prot_params, rfc9480.PBMParameter):
            prot_params, rest = decoder.decode(prot_params, rfc9480.PBMParameter())
            if rest != b"":
                raise ValueError("The decoding of `PBMParameter` structure had a remainder!")

        salt = prot_params["salt"].asOctets()
        iterations = int(prot_params["iterationCount"])
        hash_alg = HMAC_OID_2_NAME[prot_params["mac"]["algorithm"]].split("-")[1]
        return cryptoutils.compute_password_based_mac(
            data=data, key=key, iterations=iterations, salt=salt, hash_alg=hash_alg
        )

    if protection_type_oid in AES_GMAC_OID_2_NAME:
        nonce = prot_params["nonce"].asOctets()
        return cryptoutils.compute_gmac(data=data, key=key, iv=nonce)

    if protection_type_oid == rfc9480.id_DHBasedMac:
        return compute_dh_based_mac_from_alg_id(shared_secret=key, alg_id=alg_id, data=data)

    raise ValueError(f"Unsupported Symmetric MAC Protection: {protection_type_oid}")


def _compute_symmetric_protection(
    pki_message: PKIMessageTMP,
    password: bytes,
    unsafe_decoding: bool = False,
    enforce_lwcmp: bool = False,
) -> bytes:
    """Compute the `PKIMessageTMP` protection.

    :param pki_message: `PKIMessageTMP` object to protect.
    :param password: A symmetric password to protect the message.
    :param unsafe_decoding: If True, allows extra data (rest) after decoding structures. Defaults to False.
    :param enforce_lwcmp: If True, enforces that the hash algorithm is the same, throughout the algorithm.
    Defaults to `False`.
    :return: The computed protection value.
    """
    encoded = prepare_protected_part(pki_message)

    alg_id = pki_message["header"]["protectionAlg"]
    protection_type_oid = alg_id["algorithm"]
    prot_params = alg_id["parameters"]

    if protection_type_oid in HMAC_OID_2_NAME:
        mac_hash_alg = SUPPORTED_MAC_OID_2_NAME[protection_type_oid].split("-")[1]
        return cryptoutils.compute_hmac(data=encoded, key=password, hash_alg=mac_hash_alg)

    if protection_type_oid in KMAC_OID_2_NAME:
        return cryptoutils.compute_kmac_from_alg_id(alg_id=alg_id, data=encoded, key=password)

    if protection_type_oid == rfc8018.id_PBMAC1:
        mac = _compute_pbmac1_from_param(
            prot_params=prot_params,
            password=password,
            data=encoded,
            unsafe_decoding=unsafe_decoding,
            enforce_lwcmp=enforce_lwcmp,
        )

        return mac

    if protection_type_oid == rfc4210.id_PasswordBasedMac:
        if not isinstance(prot_params, rfc9480.PBMParameter):
            prot_params, rest = decoder.decode(prot_params, rfc9480.PBMParameter())
            if rest != b"" and not unsafe_decoding:
                raise BadAsn1Data("PBMParameter")

        salt = prot_params["salt"].asOctets()
        iterations = int(prot_params["iterationCount"])

        hash_alg_owf = get_hash_from_oid(prot_params["owf"]["algorithm"])

        if hash_alg_owf is None:
            raise BadAlg(
                f"Unsupported hash algorithm in `owf`: {prot_params['owf']['algorithm']}"
                f"{may_return_oid_to_name(prot_params['owf']['algorithm'])}"
            )
        if prot_params["mac"]["algorithm"] not in HMAC_OID_2_NAME:
            raise BadAlg(
                "The `PBMParameter` must use HMAC. Other MAC algorithms are not supported. "
                f"Got: {may_return_oid_to_name(prot_params['mac']['algorithm'])}"
            )

        mac_hash_alg = HMAC_OID_2_NAME[prot_params["mac"]["algorithm"]].split("-")[1]

        if mac_hash_alg != hash_alg_owf and enforce_lwcmp:
            raise LwCMPViolation(
                f"The hash algorithm in `owf` and `mac` must be the same. Got {hash_alg_owf} and {mac_hash_alg}."
            )
        if enforce_lwcmp and mac_hash_alg not in SHA2_NAME_2_OID:
            raise BadAlg("The `PBMAC1Parameters` must use SHA-2 (`enforce_lwcmp` is True).")

        return cryptoutils.compute_password_based_mac(
            data=encoded,
            key=password,
            iterations=iterations,
            salt=salt,
            hash_alg=hash_alg_owf,
            mac_hash_alg=mac_hash_alg,
        )

    if protection_type_oid in AES_GMAC_OID_2_NAME:
        if not isinstance(prot_params, rfc9044.GCMParameters):
            prot_params, rest = decoder.decode(prot_params, rfc9044.GCMParameters())
            if rest != b"" and not unsafe_decoding:
                raise ValueError("The decoding of `GCMParameters` structure had a remainder!")

        nonce = prot_params["nonce"].asOctets()
        return cryptoutils.compute_gmac(data=encoded, key=password, iv=nonce)

    if protection_type_oid == rfc9480.id_DHBasedMac:
        return compute_dh_based_mac_from_alg_id(shared_secret=password, alg_id=alg_id, data=encoded)

    raise ValueError(f"Unsupported Symmetric MAC Protection: {protection_type_oid}")


@not_keyword
def sign_rsa_pss_data_with_alg_id(
    private_key: rsa.RSAPrivateKey,
    data: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
    hash_alg: Optional[str] = "sha256",
) -> bytes:
    """Sign data using RSASSA-PSS with the specified AlgorithmIdentifier.

    :param private_key: The RSA private key used for signing.
    :param data: The data to be signed.
    :param alg_id: The AlgorithmIdentifier specifying the RSASSA-PSS algorithm.
    :param hash_alg: The hash algorithm to use for the signature. Defaults to "sha256".
    :return: The signature as a byte string.
    """
    if not alg_id["parameters"].isValue:
        salt_length = None
    elif isinstance(alg_id["parameters"], rfc8017.RSASSA_PSS_params):
        salt_length = int(alg_id["parameters"]["saltLength"])
    elif isinstance(alg_id["parameters"], univ.Any):
        # TODO fix with unsafe param, for better negative testing in general.
        params, _ = try_decode_pyasn1(  # type: ignore
            alg_id["parameters"].asOctets(),
            rfc8017.RSASSA_PSS_params(),
        )
        params: rfc8017.RSASSA_PSS_params
        salt_length = int(params["saltLength"])

    else:
        salt_length = None

    return cryptoutils.sign_data_rsa_pss(
        data=data, private_key=private_key, hash_alg=hash_alg or "sha256", salt_length=salt_length
    )


def _compute_pkimessage_protection(
    pki_message: PKIMessageTMP,
    password: Optional[Union[str, bytes]] = None,
    private_key: Optional[PrivateKey] = None,
    shared_secret: Optional[bytes] = None,
    peer: Optional[Union[rfc9480.CMPCertificate, ECDHPublicKey]] = None,
) -> bytes:
    """Compute the protection for a `PKIMessageTMP` based on the specified protection algorithm.

    :param pki_message: `PKIMessageTMP` object to compute the protection for.
    :param password: Optional shared secret for MAC-based protection or a server private key for DHBasedMac.
    :param private_key: Optional PrivateKey used for signature-based protection or DH-based MAC computation.
    :param shared_secret: Optional shared secret for DH-based MAC computation.
    :raises ValueError: If the protection algorithm OID is not supported or required parameters are not provided.
    :returns bytes: The computed protection value for the `PKIMessage`.
    """
    protection_type_oid = pki_message["header"]["protectionAlg"]["algorithm"]
    alg_id = pki_message["header"]["protectionAlg"]

    if not pki_message["header"]["sender"].isValue:
        raise ValueError("You forgot to set a value for the sender!")

    if protection_type_oid == rfc9480.id_DHBasedMac:
        if not shared_secret:
            shared_secret = _perform_dh_based_mac_exchange(
                private_key=private_key,  # type: ignore
                public_key=peer,
                extra_certs=univ.Sequence(),
            )
        return _compute_symmetric_protection(pki_message=pki_message, password=shared_secret)

    if protection_type_oid in SYMMETRIC_PROT_ALGO:
        if password is None:
            raise ValueError("For symmetric protection, a password must be provided!")
        bytes_secret = convertutils.str_to_bytes(password)
        return _compute_symmetric_protection(pki_message=pki_message, password=bytes_secret)

    data = prepare_protected_part(pki_message)
    sign_key = ensure_is_sign_key(private_key)

    if protection_type_oid == rfc5480.id_dsa_with_sha256 and isinstance(sign_key, dsa.DSAPrivateKey):
        return cryptoutils.sign_data(data=data, key=sign_key, hash_alg="sha256")  # type: ignore

    if sign_key is not None:
        return sign_data_with_alg_id(alg_id=alg_id, data=data, key=sign_key)

    protection_type_oid = may_return_oid_to_name(protection_type_oid)
    raise ValueError(f"Cannot compute the `PKIMessage` protection. Unknown OID/algorithm: {protection_type_oid}")


def _prepare_signature_prot_alg_id(
    private_key: PrivateKey,
    hash_alg: Optional[str] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for signature-based protection in a PKIMessage.

    :param private_key: The private key used for signing.
    :param hash_alg: Optional. The hash algorithm to be used (e.g., "sha256"). If not provided, it is derived from the
                     certificate's signature hash algorithm or defaults to "sha256".
    :param cert: Optional. An x509 certificate used to determine the hash algorithm, if `hash_alg` is not provided.
    :return: The prepared `AlgorithmIdentifier` for signature-based protection, populated with the appropriate OID.
    :raises ValueError: If the private key is not of the expected `PrivateKey` type.
    """
    if not isinstance(private_key, PrivateKey):
        raise ValueError(f"private_key must be an instance of PrivateKey, but is of type: {type(private_key)}.")

    cert_hash_alg = None
    if cert is not None:
        cert_hash_alg = get_hash_from_oid(cert["signatureAlgorithm"]["algorithm"], only_hash=True)

    hash_alg = hash_alg or cert_hash_alg or "sha256"

    alg_oid = get_alg_oid_from_key_hash(private_key, hash_alg)
    prot_alg_id = rfc9480.AlgorithmIdentifier()
    prot_alg_id["algorithm"] = alg_oid
    return prot_alg_id


def _prepare_mac_alg_id(protection: str, **params) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for the protection of the PKIMessage.

    :param protection: The protection algorithm to use.
    :param params: Parameters to set for the protection algorithm.
    :return: The prepared `AlgorithmIdentifier` for the protection algorithm (untagged).
    """
    protection_type = ProtectionAlgorithm.get(protection)
    prot_alg_id = rfc9480.AlgorithmIdentifier()
    if protection_type == ProtectionAlgorithm.HMAC:
        prot_alg_id = prepare_alg_ids.prepare_hmac_alg_id(params.get("hash_alg", "sha256"))

    elif protection_type == ProtectionAlgorithm.KMAC:
        prot_alg_id = prepare_alg_ids.prepare_kmac_alg_id(params.get("hash_alg", "shake128"))

    elif protection_type == ProtectionAlgorithm.PBMAC1:
        prot_alg_id["algorithm"] = rfc8018.id_PBMAC1
        salt = convertutils.str_to_bytes(params.get("salt") or os.urandom(16))
        pbmac1_parameters = prepare_alg_ids.prepare_pbmac1_parameters(
            salt=salt,
            iterations=int(params.get("iterations", 262144)),
            length=int(params.get("length", 32)),
            hash_alg=params.get("hash_alg", "sha512"),
        )
        prot_alg_id["parameters"] = pbmac1_parameters

    elif protection_type == ProtectionAlgorithm.PASSWORD_BASED_MAC:
        salt = convertutils.str_to_bytes(params.get("salt") or os.urandom(16))

        prot_alg_id["algorithm"] = rfc4210.id_PasswordBasedMac
        pbm_parameters = prepare_alg_ids.prepare_password_based_mac_parameters(
            salt=salt, iterations=int(params.get("iterations", 1000)), hash_alg=params.get("hash_alg", "sha256")
        )
        prot_alg_id["parameters"] = pbm_parameters

    elif protection_type == ProtectionAlgorithm.AES_GMAC:
        salt = convertutils.str_to_bytes(params.get("salt", os.urandom(12)))
        prot_alg_id = prepare_alg_ids.prepare_aes_gmac_prot_alg_id(
            protection_type=protection,
            nonce=salt,
        )
    else:
        raise ValueError(f"Given protection type is not supported: {protection}.")

    return prot_alg_id


def _prepare_prot_alg_id(
    protection: str, private_key: Optional[PrivateKey] = None, **params
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for the protection of the PKIMessage.

    :param protection: A string representing the type of protection.
    :param private_key: A `cryptography` `PrivateKey` object. For signing or DHBasedMac.
    :param **params: Additional parameters that may be required for specific protection types,
        such as 'iterations', 'salt', 'length' or 'hash_alg'.
    """
    prot_alg_id = rfc5280.AlgorithmIdentifier()
    protection_type = ProtectionAlgorithm.get(protection)

    if protection_type == ProtectionAlgorithm.HMAC:
        prot_alg_id = prepare_alg_ids.prepare_hmac_alg_id(params.get("hash_alg", "sha256"))

    elif protection_type == ProtectionAlgorithm.KMAC:
        prot_alg_id = prepare_alg_ids.prepare_kmac_alg_id(params.get("hash_alg", "shake128"))

    elif protection_type == ProtectionAlgorithm.PBMAC1:
        prot_alg_id["algorithm"] = rfc8018.id_PBMAC1
        salt = convertutils.str_to_bytes(params.get("salt", os.urandom(16)))
        pbmac1_parameters = prepare_alg_ids.prepare_pbmac1_parameters(
            salt=salt,
            iterations=int(params.get("iterations", 262144)),
            length=int(params.get("length", 32)),
            hash_alg=params.get("hash_alg", "sha512"),
        )
        prot_alg_id["parameters"] = pbmac1_parameters

    elif protection_type == ProtectionAlgorithm.PASSWORD_BASED_MAC:
        salt = convertutils.str_to_bytes(params.get("salt", os.urandom(16)))

        prot_alg_id["algorithm"] = rfc4210.id_PasswordBasedMac
        pbm_parameters = prepare_alg_ids.prepare_password_based_mac_parameters(
            salt=salt, iterations=int(params.get("iterations", 1000)), hash_alg=params.get("hash_alg", "sha256")
        )
        prot_alg_id["parameters"] = pbm_parameters

    elif protection_type == ProtectionAlgorithm.AES_GMAC:
        salt = convertutils.str_to_bytes(params.get("salt", os.urandom(12)))
        prot_alg_id = prepare_alg_ids.prepare_aes_gmac_prot_alg_id(
            protection_type=protection,
            nonce=salt,
        )
    elif protection_type == ProtectionAlgorithm.SIGNATURE:
        if private_key is None:
            raise ValueError("private_key must be provided for PKIMessage signature protection.")

        prot_alg_id = _prepare_signature_prot_alg_id(
            private_key=private_key,
            cert=params.get("certificate"),
            hash_alg=params.get("hash_alg"),
        )
    elif protection_type == ProtectionAlgorithm.DH:
        prot_alg_id["algorithm"] = rfc9480.id_DHBasedMac
        prot_alg_id["parameters"] = prepare_alg_ids.prepare_dh_based_mac_params(
            hash_alg=params.get("hash_alg", "sha1"), mac_alg=params.get("mac_alg", "hmac"), nonce=params.get("salt")
        )

    elif protection_type == ProtectionAlgorithm.RSASSA_PSS:
        prot_alg_id = prepare_alg_ids.prepare_rsa_pss_alg_id(params.get("hash_alg", "sha256"))

    else:
        raise ValueError(f"Unknown or unsupported PKIMessage protection: {protection} {protection_type}")

    return prot_alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )


@not_keyword
def prepare_pki_protection_field(protection_value: bytes) -> rfc9480.PKIProtection:
    """Return the tagged `PKIProtection` structure."""
    wrapped_protection = (
        rfc9480.PKIProtection()
        .fromOctetString(protection_value)
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
    )
    return wrapped_protection


def _prepare_certificate_chain(
    cert: Optional[rfc9480.CMPCertificate] = None,
    certs_dir: Optional[str] = None,
    cert_chain_path: Optional[str] = None,
    cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
) -> Optional[list]:
    """Build a certificate chain from the provided certificate, directory of certificates, or a certificate chain file.

    :param cert: The end-entity certificate.
    :param certs_dir: The directory containing additional certificates to build the chain.
    :param cert_chain_path: The file path to a certificate chain file. The file should start with the root certificate.
    :return: A list representing the certificate chain or `None` if no chain is built.
    :raises ValueError: If there is an issue with loading or parsing the certificates.
    """
    if cert_chain is not None:
        return cert_chain

    if cert is not None:
        if certs_dir is not None:
            cert_chain = certutils.build_cert_chain_from_dir(cert, certs_dir)

    if cert_chain_path is not None:
        cert_chain = utils.load_certificate_chain(cert_chain_path)[::-1]

    return cert_chain


@not_keyword
def patch_sender_and_sender_kid(
    do_patch: bool, pki_message: PKIMessageTMP, cert: Optional[rfc9480.CMPCertificate]
) -> PKIMessageTMP:
    """Patch the `sender` and `senderKID` fields of the PKIMessage structure based on the provided certificate.

    :param do_patch: Whether to patch the `sender` and `senderKID` fields.
    :param pki_message: The PKIMessage structure to patch.
    :param cert: The certificate to use for patching.
    :return: The patched or unpached PKIMessage.
    """
    if not do_patch:
        logging.info("Skipped patch of sender and senderKID, for signature-based protection.")
    elif cert is None:
        logging.info(
            "Protect PKIMessage did not patch the sender and senderKID field,because the `cert` parameter was absent!"
        )
    else:
        sender_kid = certextractutils.get_field_from_certificate(cert, extension="ski")  # type: ignore
        if sender_kid is not None:
            pki_message = cmputils.patch_senderkid(pki_message, sender_kid)  # type: ignore
        else:
            logging.info("Certificate does not have a Subject Key Identifier (SKI) field!")
            if not pki_message["header"]["senderKID"].isValue:
                cm = utils.get_openssl_name_notation(cert["tbsCertificate"]["subject"])  # type: ignore
                cm: str
                pki_message = cmputils.patch_senderkid(pki_message=pki_message, sender_kid=cm.encode("utf-8"))

        pki_message = cmputils.patch_sender(pki_message, cert=cert)

    return pki_message


@keyword(name="Protect PKIMessage")
def protect_pkimessage(  # noqa: D417
    pki_message: PKIMessageTMP,
    protection: str,
    password: Optional[Union[bytes, str]] = None,
    private_key: Optional[PrivateKey] = None,
    cert: Optional[CertObjOrPath] = None,
    exclude_certs: bool = False,
    cert_chain_fpath: Optional[str] = None,
    certs_dir: str = "./data/cert_logs",
    shared_secret: Optional[Union[bytes, str]] = None,
    bad_message_check: bool = False,
    **params,
) -> PKIMessageTMP:
    """Apply protection to a PKIMessage based on the provided protection type (e.g., signature, PBMAC1).

    Includes:
         - Checks if the certificate is the first in the `extraCerts` field!
           If provided, otherwise adds a certificate! Unless `exclude_cert` is set to `True`.

    Excludes:
         - Certificate checks!

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to protect, which must have a populated body.
        - `protection`: The type of protection to apply (e.g., "signature", "pbmac1", "aes-gmac").
        - `password`: Shared secret for MAC-based protection, if applicable.
        - `private_key`: Cryptographic private key for signing or DH-based MAC protection.
        - `cert`: A certificate (or path to one) used for signing the PKIMessage,
            and patching of the `sender` and `senderKID` field, if allowed.
        - `exclude_cert`: Flag to exclude the certificate from the PKIMessage if set to `True`.
          Defaults to `False`, which includes the certificate in `extraCerts`.
        - `cert_chain_fpath`: Optional path to a file containing a chain of certificates for protection.
          This file should start with the trust anchor.
        - `certs_dir`: Directory containing intermediate certificates to build a certificate chain.
          Defaults to `"./cert_logs"`.
        - `shared_secret`: Shared secret for DH-based MAC protection, if applicable.
        - `bad_message_check`: Whether to manipulate the message protection. Defaults to `False`.

    `**params`: Additional options for customization:
        - `salt` (str, bytes): The salt value for key derivation functions (KDF).
            If given as a string, it will be converted to bytes using UTF-8 encoding unless it begins with "0x",
            in which case it is treated as a hexadecimal string.
        - `iterations` (int, str): Number of iterations for the KDF function.
        - `length` (int): Length of the derived key for KDF output.
        - `hash_alg` (str): Hashing algorithm name (e.g., "sha256") used for signature or MAC generation.
        - `no_patch` (bool): Indicate if the sender and senderKID field are patched for signature-based protection,
            as described by RFC 9483 Section 3.1. Defaults to `False` (so by default they are patched).
        - `mac_alg` (str): The MAC algorithm to use for DH-based MAC protection. Defaults to "hmac".
        - `cert_chain` (List[CMPCertificates]): The certificate chain to use for the PKIMessage, will be used to patch \
        the sender and senderKID fields, if `cert` is not provided. Defaults to `None`.
        - `peer` (CMPCertificate, ECDHPublicKey): The peer certificate or public key for DH-based MAC protection.

    Returns:
    -------
        - The protected pyasn1 `PKIMessage`.

    Raises:
    ------
        - `ValueError`: If the PKIMessage body is not set or if neither a password nor private key is provided.

    Examples:
    --------
    | ${prot_msg}= | Protect PKIMessage | ${pki_message} | pbmac1    | password=${secret} |
    | ${prot_msg}= | Protect PKIMessage | ${pki_message} | aes-gmac  | password=${secret} |
    | ${prot_msg}= | Protect PKIMessage | ${pki_message} | signature | private_key=${key} | cert=${cert} |
    | ${prot_msg}= | Protect PKIMessage | ${pki_message} | signature | private_key=${key} \
    | cert=${cert} | certs_dir=./certs |
    | ${prot_msg}= | Protect PKIMessage | ${pki_message} | dh | private_key=${key} | password=${password} |

    Notes:
    -----
        - The supported protection types include:
            - `hmac` (Defaults to sha256)
            - `pbmac1`
            - `password_based_mac`
            - `aes_gmac` (Defaults to sha256)
            - `signature`
            - `dh`
            - `rsassa_pss` (Defaults to sha256) Not all backends support shake!
        - If `hmac` and `rsassa_pss` are used, specify the `hash_alg` argument to indicate which hash algorithm to use.

    """
    if not pki_message["body"].isValue:
        raise ValueError("PKI Message body needs to be a value!")

    if (password or private_key or shared_secret) is None:
        raise ValueError(
            "Either a password, private key or shared shared secret must be provided for "
            "PKIMessage structure Protection"
        )

    if params.get("salt") is not None:
        params["salt"] = convertutils.str_to_bytes(params["salt"])

    if isinstance(cert, str):
        der_data = utils.load_and_decode_pem_file(cert)
        cert = certutils.parse_certificate(der_data)

    elif cert is None and params.get("cert_chain") is not None:
        cert = params["cert_chain"][0]
        if not isinstance(cert, rfc9480.CMPCertificate):
            raise ValueError("cert_chain must be a list of CMPCertificates.")

    if protection in ["signature", "rsassa-pss", "rsassa_pss", "dh"]:
        pki_message = patch_sender_and_sender_kid(
            do_patch=params.get("do_patch", True), pki_message=pki_message, cert=cert
        )

    pki_message["header"]["protectionAlg"] = _prepare_prot_alg_id(
        protection=protection,
        private_key=private_key,
        shared_secret=shared_secret,
        **params,
    )

    protection_value = _compute_pkimessage_protection(
        pki_message=pki_message,
        password=password,  # type: ignore
        private_key=private_key,
        shared_secret=shared_secret,  # type: ignore
        peer=params.get("peer"),  # type: ignore
    )

    cert_chain = _prepare_certificate_chain(
        cert,  # type: ignore
        certs_dir=certs_dir,
        cert_chain_path=cert_chain_fpath,
        cert_chain=params.get("cert_chain"),
    )

    if cert is None and isinstance(private_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
        pass

    elif cert_chain is not None and not exclude_certs:
        extra_certs = cmputils.prepare_extra_certs(cert_chain)
        pki_message["extraCerts"] = extra_certs

    elif not exclude_certs and private_key:
        add_cert_to_pkimessage_used_by_protection(
            pki_message=pki_message,
            private_key=private_key,  # type: ignore
            cert=cert,  # type: ignore
        )

    if bad_message_check:
        protection_value = utils.manipulate_first_byte(protection_value)

    pki_message["protection"] = prepare_pki_protection_field(protection_value)
    return pki_message


def _perform_dh_based_mac_exchange(
    private_key: PrivateKey,
    public_key: Optional[Union[PublicKey, rfc9480.CMPCertificate]],
    extra_certs: univ.Sequence,
) -> bytes:
    """Perform Diffie-Hellman Key exchange computation.

    :param private_key: The private key used for the Diffie-Hellman key exchange.
    :param public_key: The public key of the other party or a certificate containing the public key.
    :param extra_certs: Additional certificates to use for the Diffie-Hellman key exchange.
    :return: The computed shared secret.
    """
    if not extra_certs.isValue and public_key is None:
        raise ValueError("For `DHBasedMac`, the `extraCerts` field must be set or a `public_key` must be provided.")

    if isinstance(private_key, ECDHPrivateKey):
        if public_key is None and extra_certs is None:
            raise ValueError("For `DHBasedMac`, a `public_key` or `extra_certs` must be provided.")
        if public_key is None:
            public_key = extra_certs[0]

        if isinstance(public_key, rfc9480.CMPCertificate):
            public_key = certutils.load_public_key_from_cert(public_key)

        if not isinstance(public_key, ECDHPublicKey):
            raise ValueError("For `DHBasedMac`, the public key must be of type `ECDHPublicKey`.")

        return cryptoutils.perform_ecdh(private_key=private_key, public_key=public_key)

    raise ValueError(
        f"Unsupported private key type for DH-based MAC.Expected ECDHPrivateKey, but got: {type(private_key)}."
    )


def _verify_dh_based_protection(
    pki_message: PKIMessageTMP,
    private_key: ECDHPrivateKey,
    shared_secret: Optional[bytes] = None,
    public_key: Optional[Union[rfc9480.CMPCertificate, ECDHPublicKey]] = None,
) -> None:
    """Verify the DH-based protection of a PKIMessage.

    :param pki_message: The PKIMessage to verify.
    :param private_key: The private key used for verification.
    :param shared_secret: The shared secret for DH-based MAC protection.
    :param public_key: The public key of the other party or a certificate containing the public key.
    :raises ValueError: If the public key is not of the expected type or if the shared secret is not provided.
    :raises BadMessageCheck: If the protection value does not match the expected value.
    """
    if shared_secret is None and private_key is None:
        raise ValueError("For `DHBasedMac`, a `shared_secret` or `private_key` must be provided,")

    if not shared_secret:
        shared_secret = _perform_dh_based_mac_exchange(
            private_key=private_key,  # type: ignore
            public_key=public_key,  # type: ignore
            extra_certs=pki_message["extraCerts"],
        )

    expected_protection_value = _compute_symmetric_protection(pki_message, shared_secret)
    logging.debug("Computed protection value: %s for DHBasedMac", expected_protection_value.hex())

    protection_value: bytes = pki_message["protection"].asOctets()
    if protection_value != expected_protection_value:
        raise BadMessageCheck(
            f"PKIMessage Protection For `DHBasedMac` should be: "
            f"{expected_protection_value.hex()} but was: {protection_value.hex()}"
        )


@keyword(name="Verify PKIMessage Protection")
def verify_pkimessage_protection(  # noqa: D417 undocumented-param
    pki_message: PKIMessageTMP,
    private_key: Optional[PrivateKey] = None,
    password: Optional[Union[bytes, str]] = None,
    public_key: Optional[VerifyKey] = None,
    shared_secret: Optional[bytes] = None,
    *,
    enforce_lwcmp: bool = False,
) -> None:
    """Verify the `PKIProtection` of a given `PKIMessageTMP`.

    Note:
    ----
        - If the `PKIMessage` uses a Diffie-Hellman-based MAC (`DHBasedMac`) for protection, both the `private_key`
          and a password must be provided.
        - If the protection algorithm is signature-based, the certificate used for signing must be the first certificate
        in the `extraCerts` field of the `PKIMessage`, as per RFC 9483, Section 3.3. (is tested)

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` object whose protection needs to be verified.
        - `private_key`: The private key of the server or client. For Diffie-Hellman-based protection, this is needed to
                         compute the shared secret.
        - `password`: The shared secret for symmetric or Diffie-Hellman-based protection. This is used for computing the
                      derived keys for verifying the protection value.
        - `public_key`: The public key in case a self-signed certificate was used to sign the PKIMessage,
        and was omitted inside the extraCerts field, as specified in section 3.3.
        - `shared_secret`: The shared secret for DH-based MAC protection.
        - `enforce_lwcmp`: If True, enforces the LWCMP algorithm Profile for verification and the same hash algorithm.
        Defaults to `False`.

    Raises:
    ------
        - InvalidSignature: If the signature-based protection verification fails due to a mismatched signature.
        - ValueError: If the protection algorithm is unsupported.
        - ValueError: If the computed protection value does not match the expected value, indicating tampering \
        or data corruption.


    Examples:
    --------
    | Verify PKIMessage Protection | ${pki_message} | private_key=${private_key} | ${secret} |
    | Verify PKIMessage Protection | ${pki_message} | ${private_key} |
    | Verify PKIMessage Protection | ${pki_message} | password=${secret} |
    | Verify PKIMessage Protection | ${pki_message} | public_key=${public_key} |

    """
    protection_value: bytes = pki_message["protection"].asOctets()
    protection_type_oid = pki_message["header"]["protectionAlg"]["algorithm"]

    if enforce_lwcmp:
        protection_type_oid = get_protection_type_from_pkimessage(pki_message, enforce_lwcmp=True)

    if protection_type_oid == id_KemBasedMac:
        verify_kem_based_mac_protection(
            pki_message=pki_message,
            private_key=private_key,  # type: ignore
            shared_secret=shared_secret,
        )
        return

    if protection_type_oid == rfc9480.id_DHBasedMac:
        _verify_dh_based_protection(
            pki_message=pki_message,
            private_key=private_key,  # type: ignore
            shared_secret=shared_secret,
            public_key=public_key,  # type: ignore
        )
        return

    if protection_type_oid in SYMMETRIC_PROT_ALGO:
        if password is None:
            raise ValueError("For the symmetric protection a password has to be provided!")
        byte_secret = convertutils.str_to_bytes(password)
        expected_protection_value = _compute_symmetric_protection(pki_message, byte_secret, enforce_lwcmp=enforce_lwcmp)

    elif protection_type_oid in RSASSA_PSS_OID_2_NAME or protection_type_oid in TRAD_SIG_OID_2_NAME:
        _verify_pki_message_sig(pki_message, public_key)
        return
    else:
        raise ValueError(f"Unsupported protection algorithm for verification : {protection_type_oid}.")

    if protection_value != expected_protection_value:
        raise BadMacProtection(
            f"PKIMessage Protection should be: {expected_protection_value.hex()} but was: {protection_value.hex()}"
        )


def _verify_pki_message_sig(pki_message: PKIMessageTMP, public_key: Optional[VerifyKey] = None) -> None:
    """Verify the signature protection of a `PKIMessage`.

    :param pki_message: The PKIMessage to check the protection for.
    :param public_key: Optional public key in case a self-signed certificate was used and omitted.
    :raises InvalidSignature: If the signature-based protection verification fails due to a mismatched signature.
    """
    prot_alg_id = pki_message["header"]["protectionAlg"]
    protection_type_oid = prot_alg_id["algorithm"]
    protection_value: bytes = pki_message["protection"].asOctets()
    encoded = prepare_protected_part(pki_message)
    if protection_type_oid in RSASSA_PSS_OID_2_NAME:
        pub_key = public_key or certutils.load_public_key_from_cert(pki_message["extraCerts"][0])
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise ValueError(
                "The PKIMessage protectionAlg indicates `RSASSA_PSS`, but the public_key is not an RSA key. "
                f"Type received: {type(pub_key)}"
            )
        verify_rsassa_pss_from_alg_id(pub_key, data=encoded, signature=protection_value, alg_id=prot_alg_id)
    else:
        hash_alg = get_hash_from_oid(protection_type_oid)
        hash_alg = hash_alg if hash_alg is None else hash_alg.split("-")[-1]
        if public_key is not None:
            cryptoutils.verify_signature(
                public_key=public_key, data=encoded, signature=protection_value, hash_alg=hash_alg
            )
            return

        # Raises an InvalidSignature Exception if invalid.
        certutils.verify_signature_with_cert(
            asn1cert=pki_message["extraCerts"][0], data=encoded, signature=protection_value, hash_alg=hash_alg
        )


@keyword(name="Get ProtectionAlg Name")
def get_protection_alg_name(pki_message: PKIMessageTMP) -> str:  # noqa D417 undocumented-param
    """Get the protection algorithm name from a PKIMessage.

    Arguments:
    ---------
        - `ki_message`: The PKIMessage object to check.

    Returns:
    -------
        - A string indicating the protection algorithm name.

    Raises:
    ------
        - `UnknownOID`: If the OID is not valid or unsupported.
        - `ValueError`: If the protection algorithm is not a value.

    Examples:
    --------
    | ${alg_name}= | Get Protection Alg Name | ${pki_message} |

    """
    alg_id = pki_message["header"]["protectionAlg"]["algorithm"]
    # ensures that the OID is a value and a known protection algorithm.
    _ = get_protection_type_from_pkimessage(pki_message, enforce_lwcmp=False)
    return may_return_oid_to_name(alg_id)


def _enforce_lwcmp_protection_alg(pki_message: PKIMessageTMP, allow_dh: bool = True, allow_kem: bool = True) -> str:
    """Enforce the lightweight CMP protection algorithm, specified in RFC 9481.

    :param pki_message: The PKIMessage to check.
    :param allow_dh: Whether to allow DHBasedMAC protection. Defaults to `True`.
    :param allow_kem: Whether to allow KEMBasedMAC protection. Defaults to `True`.
    :raises ValueError: If the protection algorithm is not a value.
    :raises BadAlg: If the protection algorithm is not allowed as specified in RFC 9481.
    """
    if not pki_message["header"]["protectionAlg"].isValue:
        raise ValueError("The protectionAlg field is not a value!")

    alg_oid = pki_message["header"]["protectionAlg"]["algorithm"]
    prot_type = ProtectedType.get_protection_type(alg_oid)

    if prot_type == ProtectedType.KEM and allow_kem:
        logging.debug("Protection type is `kem_based_mac`.")
        return prot_type.value

    if prot_type == ProtectedType.DH and allow_dh:
        logging.debug("Protection type is `dh`.")
        return prot_type.value

    if prot_type == ProtectedType.MAC:
        if alg_oid in LWCMP_MAC_OID_2_NAME:
            return prot_type.value

        raise BadAlg(
            f"Expected 'pbmac1' or 'password_based_mac' protection, but got: {may_return_oid_to_name(alg_oid)}"
        )

    if prot_type == ProtectedType.TRAD_SIGNATURE:
        if alg_oid not in MSG_SIG_ALG:
            raise BadAlg(f"Expected to be a `MSG_SIG_ALG` algorithm, but got: {may_return_oid_to_name(alg_oid)}")
        return prot_type.value

    raise BadAlg(
        f"Expected to be a `MSG_SIG_ALG` or `LWCMP_MAC_OID_2_NAME` algorithm, "
        f"but got: {may_return_oid_to_name(alg_oid)}"
    )


@keyword(name="Get Protection Type From PKIMessage")
def get_protection_type_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    enforce_lwcmp: bool = False,
    allow_dh: bool = True,
    allow_kem: bool = True,
) -> str:
    """Determine the protection type in the PKIMessage (signature-based or MAC-based).

    Arguments:
    ---------
        - `pki_message`: The PKIMessage object to check.
        - `enforce_lwcmp`: Boolean flag to indicate if the lightweight CMP version is checked. Defaults to `False`.
        Then only "pbmac1" and "password-based-mac" are allowed (RFC 9481).
        - `allow_dh`: whether to allow `DHBasedMac` protection. Defaults to `True`.
        - `allow_kem`: whether to allow `KEMBasedMac` protection. Defaults to `True`.


    Returns:
    -------
        - A string indicating the protection type: 'mac', 'kem_based_mac', 'sig', 'composite-sig' or 'pq-sig'.

    Raises:
    ------
        - `UnknownOID`: If the OID is not valid, unsupported or not allowed.
        - `ValueError`: If the protection algorithm is not a value.
        - `BadAlg`: If the protection algorithm is not allowed as in RFC 9481 specified (for `enforce_lwcmp`).

    Examples:
    --------
    | Get Protection Type From PKIMessage | ${pki_message} |

    """
    alg_oid = pki_message["header"]["protectionAlg"]["algorithm"]
    alg_oid: univ.ObjectIdentifier

    if not alg_oid.isValue:
        raise ValueError("The protectionAlg field is not a value!")

    prot_type = ProtectedType.get_protection_type(alg_oid)

    if enforce_lwcmp:
        return _enforce_lwcmp_protection_alg(
            pki_message=pki_message,
            allow_dh=allow_dh,
            allow_kem=allow_kem,
        )

    if prot_type == ProtectedType.KEM:
        if not allow_kem:
            raise BadAlg("Protection type is `kem_based_mac`, but `allow_kem` is set to False.")

        return prot_type.value

    if prot_type == ProtectedType.DH:
        if not allow_dh:
            raise BadAlg("Protection type is `dh`, but `allow_dh` is set to False.")

        return prot_type.value

    if alg_oid in SYMMETRIC_PROT_ALGO:
        return "mac"

    if alg_oid in TRAD_SIG_OID_2_NAME:
        return "sig"

    if alg_oid in COMPOSITE_SIG03_OID_2_NAME or alg_oid in COMPOSITE_SIG04_OID_2_NAME:
        return "composite-sig"

    if alg_oid in PQ_SIG_OID_2_NAME:
        return "pq-sig"

    raise UnknownOID(oid=alg_oid, extra_info="Can not determine the protection type.")


def _compare_mac_params(
    first_param: rfc9480.AlgorithmIdentifier,
    second_param: rfc9480.AlgorithmIdentifier,
    allow_null: bool,
    same_salt: bool,
) -> None:
    """Compare the parameters used to compute the MAC for the `PKIMessage`.

    :param first_param: The first parameters field.
    :param second_param: The second parameters field, to compare to.
    :param allow_null: Indicates whether `NULL` is allowed instead of absent parameters.
    :param same_salt: Indicates whether the salt needs to be the same or different.
    :raises ValueError: If the parameters are different.
    """
    der_data = encoder.encode(first_param["parameters"])

    if not allow_null and same_salt:
        if der_data != second_param["parameters"].asOctets():
            raise ValueError("The parameters of the `protectionAlg` field are different.")

    name = may_return_oid_to_name(first_param["algorithm"])
    if name == "pbmac1":
        if not _compare_pbmac1_parameters(
            der_data,
            second_param["parameters"].asOctets(),
            same_salt=same_salt,
            allow_null=allow_null,
        ):
            raise ValueError("The parameters of the `protectionAlg` field are different.")
    elif name == "password_based_mac":
        if not _compare_pbm_parameters(
            first_param["parameters"],
            second_param["parameters"].asOctets(),
            same_salt=same_salt,
            allow_null=allow_null,
        ):
            raise ValueError("The parameters of the `protectionAlg` field are different.")
    else:
        if der_data != second_param["parameters"].asOctets():
            raise ValueError("The parameters of the `protectionAlg` field are different.")


# TODO: Remove 'strict' parameter if the specification is updated.
def _compare_not_strict_mac(
    request: PKIMessageTMP,
    response: PKIMessageTMP,
    enforce_lwcmp: bool = False,
    pkiconf: Optional[PKIMessageTMP] = None,
) -> None:
    """Compare protection algorithms in a non-strict manner.

    Check whether both messages are MAC-protected, but does not require
    the algorithms or parameters to match exactly.

    :param request: The original PKI request message.
    :param response: The server's PKI response message.
    :param enforce_lwcmp: Boolean flag indicating lightweight CMP version. Defaults to False.
    :param pkiconf: Optional PKI confirmation message. Defaults to None.
    :raises ValueError: If messages are not MAC-protected.
    """
    server_type = get_protection_type_from_pkimessage(response, enforce_lwcmp=enforce_lwcmp)
    our_type = get_protection_type_from_pkimessage(request, enforce_lwcmp=enforce_lwcmp)
    our_alg_id_name = may_return_oid_to_name(request["header"]["protectionAlg"]["algorithm"])

    if server_type != our_type:
        server_alg_id_name = may_return_oid_to_name(response["header"]["protectionAlg"]["algorithm"])

        raise ValueError(f"Both messages are not MAC protected. Our {our_alg_id_name}: Server {server_alg_id_name}")

    if pkiconf is not None:
        protection_type = get_protection_type_from_pkimessage(pkiconf, enforce_lwcmp=enforce_lwcmp)
        pkiconf_name = may_return_oid_to_name(pkiconf["header"]["protectionAlg"]["algorithm"])
        if server_type != protection_type:
            raise ValueError(
                f"Both messages are not MAC protected. Our {our_alg_id_name}: "
                f"PKI Confirmation Protection: {pkiconf_name}"
            )


@keyword(name="MAC Protection Algorithms Must Match")
def mac_protection_algorithms_must_match(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    response: PKIMessageTMP,
    pkiconf: Optional[PKIMessageTMP] = None,
    same_salt: bool = False,
    allow_null: bool = False,
    strict: bool = True,
    enforce_lwcmp: bool = True,
) -> None:
    """Ensure that the MAC protection algorithms in the request and response PKIMessages match.

    As per Section 1.6 of RFC 9483, both messages must use MAC-based protection.
    If you want to be more strict as per the new standard, options can be set.

    Arguments:
    ---------
        - `request`: The original PKI request message containing the protection algorithm used.
        - `response`: The server's PKI response message containing the protection algorithm received.
        - `pkiconf`: An optional PKIMessage for verifying additional protection algorithm
            parameters against the response message. Defaults to `None`.
        - `same_salt`: Indicates whether the salt value has to be the same or different.
            If set to `False`, it must be different. Defaults to `False`.
        - `allow_null`: Indicates whether `NULL` is accepted instead of absent parameters.
        - `strict`: Indicates whether all messages have to be MAC protected. If `False`, only checks
            that both messages use MAC protection, not necessarily the same algorithm. Defaults to `True`.
        - `enforce_lwcmp`: Indicates whether the lightweight CMP version is tested, meaning that only `pbmac1` and
            `password_based_mac` are allowed. Defaults to `True`.

    Raises:
    ------
        - `ValueError`: If the protection algorithms or their parameters between the request and response do not match,
            or if the `pkiconf` algorithm does not match the response algorithm when provided.

    Examples:
    --------
    | MAC Protection Algorithms Must Match | ${pki_message} | ${resp_pki_message} |
    | MAC Protection Algorithms Must Match | ${pki_message} | pkiconf=${pkiconf} |
    | MAC Protection Algorithms Must Match | ${pki_message} | ${resp_pki_message} | pkiconf=${pkiconf} |

    """
    request_algo = request["header"]["protectionAlg"]
    response_algo = response["header"]["protectionAlg"]
    logging.info("Our protectionAlg: %s", request_algo.prettyPrint())
    logging.info("Server's protectionAlg: %s", response_algo.prettyPrint())

    server_alg_id_name = may_return_oid_to_name(response_algo["algorithm"])
    our_alg_id_name = may_return_oid_to_name(request_algo["algorithm"])

    if not response_algo.isValue:
        raise ValueError("The server did not set a `protectionAlg`.")

    if not strict:
        _compare_not_strict_mac(request, response, enforce_lwcmp, pkiconf)
        return

    if get_protection_type_from_pkimessage(response) != "mac":
        raise ValueError("The server response was not MAC-based protected!")

    if enforce_lwcmp and server_alg_id_name not in ["pbmac1", "password_based_mac"]:
        raise ValueError("The protection algorithm is not allowed for the lightweight version.")

    if request_algo["algorithm"] != response_algo["algorithm"]:
        raise ValueError(f"Protection algorithm mismatch, we sent {our_alg_id_name}, we got {server_alg_id_name}")

    _compare_mac_params(request_algo, response_algo, same_salt=same_salt, allow_null=allow_null)

    if pkiconf is not None:
        pki_conf_id = pkiconf["header"]["protectionAlg"]
        # To just compare DER, because they must be the same.
        if same_salt:
            if not _compare_alg_id(pki_conf_id, response_algo, allow_null=False):
                logging.info("PKI Confirmation `protectionAlg`:\n %s", pki_conf_id.prettyPrint())
                raise ValueError("Protection algorithm mismatch between PKI Confirmation and CA response.")
        else:
            # For convenience, use the request, which must be equal.
            _compare_mac_params(request_algo, response_algo, same_salt=same_salt, allow_null=allow_null)


@not_keyword
def check_signature_alg_is_consistent(
    pki_response: PKIMessageTMP,
    pki_conf: Optional[PKIMessageTMP] = None,
    pki_polling: Optional[PKIMessageTMP] = None,
):
    """Check the consistency of the signature algorithm across PKI messages from the CA.

    Verifies that the `protectionAlg` used in the first PKI response matches
    the signature algorithm used in the optional `pki_conf` and `pki_polling` messages. It also
    ensures that the `protectionAlg` parameters are not present, as required for signature-based
    protection.

    :param pki_response: An `PKIMessageTMP` object representing the PKI response message to check.
    :param pki_conf: An optional `PKIMessageTMP` object representing the PKI confirmation message
        for comparison. Defaults to `None`.
    :param pki_polling: An optional `PKIMessageTMP` object representing the PKI polling message
        for comparison. Defaults to `None`.
    :raises ValueError: If the signature algorithms in the provided messages do not match, or if the
        `protectionAlg` field includes parameters when they should not be present.
    """
    protection_alg = pki_response["header"]["protectionAlg"]

    server_alg_id = ALL_KNOWN_OIDS_2_NAME.get(protection_alg["algorithm"], protection_alg["algorithm"])

    if pki_conf is not None:
        pki_conf_alg_id = pki_conf["header"]["protectionAlg"]
        pki_conf_oid = ALL_KNOWN_OIDS_2_NAME.get(pki_conf_alg_id["algorithm"], pki_conf_alg_id["algorithm"])
        if protection_alg["algorithm"] != pki_conf_alg_id["algorithm"]:
            logging.info("Initial ProtectionAlg OID was: %s but pkiConf OID was %s", server_alg_id, pki_conf_oid)
            raise ValueError("The `pkiConf` message has a different ObjectIdentifier!")

    if pki_polling is not None:
        pki_polling_alg_id = pki_polling["header"]["protectionAlg"]
        pki_polling_oid = ALL_KNOWN_OIDS_2_NAME.get(pki_polling_alg_id["algorithm"], pki_polling_alg_id["algorithm"])
        if protection_alg["algorithm"] != pki_polling_alg_id["algorithm"]:
            logging.info("Initial ProtectionAlg OID was: %s but pkiConf OID was %s", server_alg_id, pki_polling_oid)
            raise ValueError("The `pkiConf` message has a different ObjectIdentifier!")

    pki_conf_value = None
    pki_polling_value = None
    if pki_conf is not None:
        pki_conf_value = pki_conf["header"]["protectionAlg"]["parameters"].isValue

    if pki_polling is not None:
        pki_polling_value = pki_polling["header"]["protectionAlg"]["parameters"].isValue

    if protection_alg["parameters"].isValue or pki_conf_value or pki_polling_value:
        raise ValueError("The `protectionAlg` MUST not have parameters for PKIMessage signature-based protection.")


def _check_is_same_chain(
    extra_certs: univ.SequenceOf,
    pki_conf_certs: Optional[univ.SequenceOf] = None,
    polling_certs: Optional[univ.SequenceOf] = None,
) -> None:
    """Validate if the CMP protection certificate chain is consistent through all PKIMessages exchanged with the server.

    It is allowed to be cached, but if present, then the complete certificate chain must be the same.

    :param extra_certs: The `extraCerts` field of the first PKIMessage.
    :param pki_conf_certs: The optional `extraCerts` field of the PKI confirmation message.
    :param polling_certs: The optional `extraCerts` field of a PKI polling request or response.
    :return: `None`, if the certificate chain is absent or the same.
    :raises ValueError: If the chain is different from the first certificate chain.
    """
    cmp_cert = extra_certs[0]
    first_chain = certutils.build_chain_from_list(certs=extra_certs, ee_cert=cmp_cert)  # type: ignore
    der_data_first = b"".join([encoder.encode(cert) for cert in first_chain])

    if pki_conf_certs is not None:
        pki_conf_chain = certutils.build_chain_from_list(certs=pki_conf_certs, ee_cert=cmp_cert)  # type: ignore
        der_data_pki_conf = b"".join([encoder.encode(cert) for cert in pki_conf_chain])
        if der_data_first != der_data_pki_conf:
            raise ValueError("The PKI Confirmation message contains a different certificate chain.")

    if polling_certs is not None:
        polling_chain = certutils.build_chain_from_list(certs=polling_certs, ee_cert=cmp_cert)  # type: ignore
        der_data_polling = b"".join([encoder.encode(cert) for cert in polling_chain])
        if der_data_first != der_data_polling:
            raise ValueError("The Polling message contains a different certificate chain.")


# TODO: Check section.
# TODO: Maybe add 'allow_cache' as a parameter; currently default, or must be cached.


def signature_protection_must_match(  # noqa D417 undocumented-param
    response: PKIMessageTMP,
    pki_conf: Optional[PKIMessageTMP] = None,
    pki_polling: Optional[PKIMessageTMP] = None,
) -> None:
    """Check if the signature protection algorithms and the extraCerts, if present, are consistent.

    Verifies if the PKIMessage protection is valid throughout all messages and that
    the credentials used are the same. As per Section 4 and Section 3.3 of RFC 9483, the first
    `response` must have the `extraCerts` field set, optional for `pki_conf` and polling messages.
    The signature of each message is verified.

    Arguments:
    ---------
        - `response`: The CA message to check against, must have the `extraCerts` field set.
        - `pki_conf`: An optional PKI confirmation message.
        - `pki_polling`: An optional PKI polling message.

    Raises:
    ------
        - `ValueError`: If the `extraCerts` field is not set in `response` or is empty.
        - `ValueError`: If the first extraCert in `pki_conf` or `pki_polling` does not match `response`.
        - `ValueError`: If any signature verification fails.

    Examples:
    --------
    | Signature Protection Must Match | ${response_pki_message} | ${pki_conf_message} | ${pki_polling_message} |
    | Signature Protection Must Match | ${response_pki_message} | ${pki_conf_message} |
    | Signature Protection Must Match | ${response_pki_message} | ${pki_polling_message} |
    | Signature Protection Must Match | ${response_pki_message} |

    """
    if not response["extraCerts"].isValue:
        raise ValueError("The `extraCerts` field must be set and not empty in the first `response`.")

    if not pki_conf and not pki_polling:
        raise ValueError("Only `response` was provided! At least one of `pki_conf` or `pki_polling` must be provided.")

    check_signature_alg_is_consistent(response, pki_conf, pki_polling)
    first_msg_cert = response["extraCerts"][0]
    hash_alg = get_hash_from_oid(response["header"]["protectionAlg"]["algorithm"])
    hash_alg = None if hash_alg is None else hash_alg.split("-")[1]

    try:
        certutils.verify_signature_with_cert(
            asn1cert=first_msg_cert,
            data=prepare_protected_part(response),
            signature=response["protection"].asOctets(),
            hash_alg=hash_alg,
        )
    except InvalidSignature as err:
        raise ValueError("Signature verification failed for the `response`.") from err

    pki_conf_certs = None
    if pki_conf:
        if pki_conf["extraCerts"].isValue:
            pki_conf_certs = pki_conf["extraCerts"]
        try:
            certutils.verify_signature_with_cert(
                asn1cert=first_msg_cert,
                data=prepare_protected_part(pki_conf),
                signature=pki_conf["protection"].asOctets(),
                hash_alg=hash_alg,
            )
        except InvalidSignature as err:
            raise ValueError("Signature verification failed for `pki_conf`.") from err

    polling_certs = None
    if pki_polling:
        if pki_polling["extraCerts"].isValue:
            polling_certs = pki_polling["extraCerts"]

        try:
            certutils.verify_signature_with_cert(
                asn1cert=first_msg_cert,
                data=prepare_protected_part(pki_polling),
                signature=pki_polling["protection"].asOctets(),
                hash_alg=hash_alg,
            )
        except InvalidSignature as err:
            raise ValueError("Signature verification failed for `pki_polling`.") from err

    _check_is_same_chain(response["extraCerts"], pki_conf_certs, polling_certs)


@not_keyword
def verify_rsassa_pss_from_alg_id(
    public_key: rsa.RSAPublicKey, data: bytes, signature: bytes, alg_id: rfc9480.AlgorithmIdentifier
):
    """Verify an RSASSA-PSS signature with the `AlgorithmIdentifier`.

    :param public_key: The RSA public key.
    :param data: The original data that was signed.
    :param signature: The signature to verify.
    :param alg_id: The parsed `protectionAlg` from the `PKIMessage`
    :raises InvalidSignature: If the signature is invalid.
    """
    if alg_id["algorithm"] == rfc9481.id_RSASSA_PSS:
        if not alg_id["parameters"].isValue:
            raise ValueError("The `AlgorithmIdentifier` must have parameters for RSASSA-PSS set.")

        if not isinstance(alg_id["parameters"], rfc8017.RSASSA_PSS_params):
            params, rest = decoder.decode(alg_id["parameters"], rfc8017.RSASSA_PSS_params())
            if rest != b"":
                raise ValueError("The decoding of 'parameters' field inside the `protectionAlg` had a remainder!")
        else:
            params = alg_id["parameters"]
        salt_length = int(params["saltLength"])
        hash_alg = get_hash_from_oid(params["hashAlgorithm"]["algorithm"])
        hash_algorithm = hash_name_to_instance(hash_alg)  # type: ignore

        mgf_algorithm_encoded = params["maskGenAlgorithm"]["parameters"]
        mgf_oid = params["maskGenAlgorithm"]["algorithm"]

        if mgf_oid != rfc8017.id_mgf1:
            raise ValueError(f"The `maskGenAlgorithm` should be MGF1, but got `{mgf_oid}`!")

        if not isinstance(mgf_algorithm_encoded, rfc9480.AlgorithmIdentifier):
            mgf, rest = decoder.decode(mgf_algorithm_encoded, rfc9480.AlgorithmIdentifier())
            if rest != b"":
                raise ValueError("The decoding of 'mgf1' field inside the `maskGenAlgorithm` field had a remainder!")

        else:
            mgf = mgf_algorithm_encoded

        if mgf["algorithm"] != params["hashAlgorithm"]["algorithm"]:
            raise ValueError("Mismatch between the algorithm for MGF1 and hashAlgorithm!")

    elif alg_id["algorithm"] in [rfc9481.id_RSASSA_PSS_SHAKE128, rfc9481.id_RSASSA_PSS_SHAKE256]:
        verify_rsassa_pss_shake(public_key, data, signature, alg_id)
        return

    else:
        raise ValueError("Unknown RSASSA PSS OID")

    public_key.verify(
        signature=signature,
        data=data,
        padding=padding.PSS(
            mgf=padding.MGF1(algorithm=hash_algorithm), salt_length=salt_length or hash_algorithm.digest_size
        ),
        algorithm=hash_algorithm,
    )


@not_keyword
def verify_rsassa_pss_shake(
    public_key: rsa.RSAPublicKey,
    data: bytes,
    signature: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
    salt_length: Optional[int] = None,
):
    """Verify an RSASSA-PSS signature with the `AlgorithmIdentifier`.

    :param public_key: The RSA public key.
    :param data: The original data that was signed.
    :param signature: The signature to verify.
    :param alg_id: The parsed `protectionAlg` from the `PKIMessage`
    :param salt_length: The length of the salt to use. If not provided, defaults to the hash algorithm's digest size.
    :raises InvalidSignature: If the signature is invalid.
    """
    if alg_id["parameters"].isValue:
        raise BadDataFormat("The `AlgorithmIdentifier` for RSASSA-PSS with SHAKE must not have parameters set.")

    if alg_id["algorithm"] == rfc9481.id_RSASSA_PSS_SHAKE128:
        hash_for_verifying = FixedSHAKE128.new(data)
    else:
        hash_for_verifying = FixedSHAKE256.new(data)

    n, e = public_key.public_numbers().n, public_key.public_numbers().e
    pub_key_tmp = RSA.construct((n, e))

    if salt_length is None:
        salt_length = hash_for_verifying.digest_size

    verifier = pss.new(pub_key_tmp, salt_bytes=salt_length)
    try:
        verifier.verify(hash_for_verifying, signature)  # type: ignore
    except ValueError as err:
        raise InvalidSignature("Signature verification failed for RSASSA-PSS with SHAKE.") from err


@keyword(name="Patch protectionAlg")
def patch_protection_alg(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    protection: str = "password_based_mac",
    private_key: Optional[PrivateKey] = None,
    **params,
) -> PKIMessageTMP:
    """Patch the `protectionAlg` field of a `PKIMessage` for testing purposes.

    Modifies the `protectionAlg` field in the header of a `PKIMessage`, allowing
    for negative testing by changing the protection algorithm type. After first protection the `PKIMessage`.
    The function initially protects the `PKIMessage` using a specified algorithm and optionally patches it with another,
    such as switching between RSA and ECC private keys. This allows verification that the
    `protectionAlg` field and CMP protection certificate are consistent.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` object to modify.
        - `protection`: The type of protection algorithm to apply (e.g., `"password_based_mac"` or `"signature"`).
                         Defaults to `"password_based_mac"`.
        - `private_key`: Optional private key for signature-based protection. If not provided, a default Ed25519 key
                         is generated.
        - `alg_id`: Optional `AlgorithmIdentifier` object to use for the protection algorithm. Defaults to `None`.
        - `**params`: Additional parameters for MAC-based protection or `RSASSA-PSS`.

    Returns:
    -------
        - The `PKIMessage` with an updated `protectionAlg` field.

    Raises:
    ------
        - `ValueError`: If an invalid protection type is provided.

    Examples:
    --------
    | ${patched_message}= | Patch protectionAlg | ${pki_message} | protection=signature |
    | ${patched_message}= | Patch protectionAlg | ${pki_message} | protection=pbmac1 | salt=salt |

    """
    protection_type = ProtectionAlgorithm.get(protection)
    if protection_type == ProtectionAlgorithm.SIGNATURE:
        private_key = private_key or keyutils.generate_key("ed25519")

    pki_message["header"]["protectionAlg"] = _prepare_prot_alg_id(
        protection=protection, private_key=private_key, **params
    )
    return pki_message


@keyword(name="Modify PKIMessage Protection")
def modify_pkimessage_protection(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
) -> PKIMessageTMP:
    """Modify the `protection` field of a `PKIMessage` for negative testing.

    Alters the `protection` field in a `PKIMessage`, if a value is set, then the first byte is
    modified, else a random 32-byte value is set.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` object to be modified for testing.

    Returns:
    -------
        - The `PKIMessage` with an updated `protection` field.

    Raises:
    ------
        - `ValueError`: If an invalid `wrong_type` option is provided.

    Examples:
    --------
    | ${patched_message}= | Patch PKIMessage Protection | ${pki_message} |

    """
    protection_value = os.urandom(32)
    if pki_message["protection"].isValue:
        protection_value = pki_message["protection"].asOctets()
        protection_value = utils.manipulate_first_byte(protection_value)

    pki_message["protection"] = prepare_pki_protection_field(protection_value)
    return pki_message


@keyword(name="Get CMP Protection Salt")
def get_cmp_protection_salt(  # noqa D417 undocumented-param
    protection_alg: rfc9480.AlgorithmIdentifier,
) -> bytes:
    """Extract the salt used in a CMP message protection algorithms.

    Only supports `pbmac1` and `password-based-mac`.

    Extracts the salt from the first `PKIMessage` to ensure that the protection is consistent
    throughout a PKI message exchange. It is also used to verify that the salt differs when using
    the Password-Based Key Management Technique, as described in Section 4.1.6 of the Rfc9483.

    Arguments:
    ---------
        - `protection_alg`: The `AlgorithmIdentifier` structure containing the protection salt.

    Returns:
    -------
        - The extracted salt as bytes.

    Raises:
    ------
        - `ValueError`: If the salt is not of type `specified` for `PBMAC1`.
        - `NotImplementedError`: If the protection algorithm is neither `PBMAC1` nor `Password-Based-Mac`.

    Examples:
    --------
    | ${salt}= | Get CMP Protection Salt | ${pki_message} |

    """
    if protection_alg["algorithm"] == rfc9481.id_PBMAC1:
        if not isinstance(protection_alg["parameters"], rfc8018.PBMAC1_params):
            prot_params, _ = decoder.decode(protection_alg["parameters"], rfc8018.PBMAC1_params())
            pbkdf2_params, _ = decoder.decode(prot_params["keyDerivationFunc"]["parameters"], rfc8018.PBKDF2_params())

            if pbkdf2_params["salt"].getName() != "specified":
                raise ValueError("The salt is only supported when of type `specified`")

            salt = pbkdf2_params["salt"]["specified"].asOctets()
        else:
            salt = protection_alg["parameters"]["keyDerivationFunc"]["parameters"]["salt"]["specified"].asOctets()

        return salt

    if protection_alg["algorithm"] == rfc9481.id_PasswordBasedMac:
        if not isinstance(protection_alg["parameters"], rfc9480.PBMParameter):
            prot_params, _ = decoder.decode(protection_alg["parameters"], rfc9480.PBMParameter())
        else:
            prot_params = protection_alg["parameters"]

        salt = prot_params["salt"].asOctets()
        return salt

    raise NotImplementedError("Only implemented for `PBMAC1` and `Password-Based-Mac`.")


@not_keyword
def compute_kdf_from_alg_id(kdf_alg_id: rfc9480.AlgorithmIdentifier, ss: bytes, length: int, ukm: bytes) -> bytes:
    """Compute the key derivation function using the provided `AlgorithmIdentifier`.

    Supported are PBKDF2, HKDF, KDF2, and KDF3.
    For PBKDF2, the parameters are extracted from the `AlgorithmIdentifier` structure
    (only ss is needed).

    :param kdf_alg_id: The `AlgorithmIdentifier` structure containing the KDF parameters.
    :param ss: The shared secret to use as key material.
    :param length: The length of the derived key.
    :param ukm: The user keying material to use.
    :return: The derived key.
    :raises ValueError: If the KDF algorithm is not supported, or if the hash algorithm is not recognized.
    """
    if kdf_alg_id["algorithm"] in HKDF_OID_2_NAME:
        hash_alg = HKDF_OID_2_NAME[kdf_alg_id["algorithm"]].split("-")[1]
        return cryptoutils.compute_hkdf(hash_alg=hash_alg, length=length, key_material=ss, info=ukm)

    if kdf_alg_id["algorithm"] in [rfc5990.id_kdf_kdf2, rfc5990.id_kdf_kdf3]:
        if not isinstance(kdf_alg_id["parameters"], rfc9480.AlgorithmIdentifier):
            sha_alg_id = decoder.decode(kdf_alg_id["parameters"], asn1Spec=rfc9480.AlgorithmIdentifier())[0]
        else:
            sha_alg_id = kdf_alg_id["parameters"]

        hash_alg = get_hash_from_oid(sha_alg_id["algorithm"])
        if hash_alg is None:
            _name = may_return_oid_to_name(sha_alg_id["algorithm"])
            raise ValueError(f"Unsupported hash algorithm: {_name}")

        return cryptoutils.compute_ansi_x9_63_kdf(
            shared_secret=ss,
            hash_alg=hash_alg,
            key_length=length,
            other_info=ukm,
            use_version_2=(kdf_alg_id["algorithm"] == rfc5990.id_kdf_kdf2),
        )

    if kdf_alg_id["algorithm"] == rfc9481.id_PBKDF2:
        if not isinstance(kdf_alg_id["parameters"], rfc8018.PBKDF2_params):
            pbkdf2_params = decoder.decode(kdf_alg_id["parameters"], asn1Spec=rfc9480.AlgorithmIdentifier())[0]
        else:
            pbkdf2_params = kdf_alg_id["parameters"]

        return cryptoutils.compute_pbkdf2_from_parameter(key=ss, parameters=pbkdf2_params)

    raise ValueError(f"Unsupported KDF algorithm: {kdf_alg_id['algorithm']}")


@not_keyword
def compute_kem_based_mac_from_alg_id(
    data: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
    ss: bytes,
) -> bytes:
    """Compute a `KEMBasedMac` using the provided AlgorithmIdentifier.

    :param data: The data to be protected.
    :param ss: The shared secret to use as key material.
    :param alg_id: The `AlgorithmIdentifier` structure containing the KEMBasedMac parameters.
    :return: The computed MAC value.
    """
    if not isinstance(alg_id["parameters"], KemBMParameterAsn1):
        parameters = decoder.decode(alg_id["parameters"], asn1Spec=KemBMParameterAsn1())[0]
    else:
        parameters = alg_id["parameters"]

    ukm = b"" if not parameters["kemContext"].isValue else parameters["kemContext"].asOctets()

    if ukm != b"":
        _process_kem_other_info(parameters["kemContext"])

    kdf_alg_id = parameters["kdf"]
    length = int(parameters["len"])

    mac_key = compute_kdf_from_alg_id(kdf_alg_id=kdf_alg_id, ss=ss, length=length, ukm=ukm)

    logging.info("KEMBasedMac MAC-key: %s", mac_key.hex())

    mac_alg_id = parameters["mac"]
    mac_oid = mac_alg_id["algorithm"]

    if mac_oid in HMAC_OID_2_NAME:
        mac_alg = HMAC_OID_2_NAME[mac_oid].split("-")[1]
        return cryptoutils.compute_hmac(key=mac_key, data=data, hash_alg=mac_alg)

    if mac_oid in KMAC_OID_2_NAME:
        return cryptoutils.compute_kmac_from_alg_id(key=mac_key, data=data, alg_id=mac_alg_id)

    raise ValueError(f"Unsupported MAC algorithm: {may_return_oid_to_name(mac_oid)}")


@keyword(name="Prepare KEMCiphertextInfo")
def prepare_kem_ciphertextinfo(  # noqa: D417 Missing argument description in the docstring
    key: Union[KEMPublicKey, KEMPrivateKey],
    ct: Optional[bytes] = None,
) -> rfc9480.InfoTypeAndValue:
    """Prepare a `KemCiphertextInfo` structure.

    Used to encapsulate a secret, so that one party can ask for the necessary information for the
    KEMBasedMac.

    Arguments:
    ---------
       - `key`: The private key of the client to get the KEM algorithm.
       - `ct`: The ciphertext data to be encapsulated.

    Returns:
    -------
        - The populated `InfoTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: if the `key` is not a `KEMPublicKey` or `KEMPrivateKey`.

    Examples:
    --------
    | ${info_value}= | Prepare KEM CiphertextInfo | ${key} |
    | ${info_value}= | Prepare KEM CiphertextInfo | ${key} | ${ct} |

    """
    oid = get_kem_oid_from_key(key)

    kem_ct_info = KemCiphertextInfoAsn1()
    kem_ct_info["kem"]["algorithm"] = oid
    if ct is not None:
        kem_ct_info["ct"] = univ.OctetString(ct)

    info_value = rfc9480.InfoTypeAndValue()
    info_value["infoType"] = id_it_KemCiphertextInfo
    info_value["infoValue"] = kem_ct_info

    return info_value


@not_keyword
def prepare_kem_other_info(
    transaction_id: bytes, context: Optional[bytes] = None, static_string: Union[List[str], str] = "CMP-KEM"
) -> KemOtherInfoAsn1:
    """Prepare a `KemOtherInfo` structure.

    Constructs the context information for the KEM operation, including the transaction ID and
    optional static string.

    :param transaction_id: The transaction ID to use.
    :param context: Optional context information for the KEM operation.
    :param static_string: Optional static string to use.
    :return: The populated `KemOtherInfo` object.
    """
    other_info = KemOtherInfoAsn1()
    other_info["transactionID"] = univ.OctetString(transaction_id)
    if context is not None:
        other_info["kemContext"] = univ.OctetString(context)

    if isinstance(static_string, str):
        static_string = [static_string]

    other_info["staticString"].extend(static_string)

    return other_info


@keyword(name="Protect PKIMessage KEMBasedMAC")
def protect_pkimessage_kem_based_mac(  # noqa: D417 Missing argument description in the docstring
    pki_message: PKIMessageTMP,
    private_key: Optional[KEMPrivateKey] = None,
    shared_secret: Optional[Union[bytes, str]] = None,
    peer_cert: Optional[rfc9480.CMPCertificate] = None,
    kem_ct_info: Optional[KemCiphertextInfoAsn1] = None,
    kdf: str = "kdf3",
    kem_context: Optional[KemOtherInfoAsn1] = None,
    context: Optional[bytes] = None,
    hash_alg: str = "sha256",
    bad_message_check: bool = False,
) -> PKIMessageTMP:
    """Protect a `PKIMessage` using KEMBasedMac.

    If the shared secret new encapsulated will the `KemCiphertextInfo` be added to the `generalInfo` field.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` to protect.
        - `private_key`: The private key of the sender. Defaults to `None`.
        - `shared_secret`: The shared secret to use for protection. Defaults to `None`.
        (can be provided as a string or bytes, if starts with "0x it will be  interpreted as hex,
        If provided, the `private_key` and `peer_cert` fields are ignored.)
        - `peer_cert`: The peer's certificate containing the public key. Defaults to `None`.
        - `kem_ct_info`: The KEM ciphertext information structure. Defaults to `None`.
        - `kdf`: The key derivation function to use (e.g., "pbkdf2", "kdf2", "kdf3"). Defaults to "kdf3".
        - `kem_context`: The `KemOtherInfoAsn1` structure for the KEM operation. Defaults to `None`.
        - `context`: context information for the KEM operation. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for key derivation. Defaults to "sha256".
        - `bad_message_check`: Whether to manipulate the message protection value. Defaults to `True`.

    Returns:
    -------
        - The protected `PKIMessage`.

    Raises:
    ------
        - `ValueError`: If neither `kem_ct_info`, `shared_secret` nor (`private_key` and `peer_cert`) are provided.

    Examples:
    --------
    | ${protected_message}= | Protect PKIMessage KEMBasedMAC | ${pki_message} | ${private_key} | ${peer_cert} |
    | ${protected_message}= | Protect PKIMessage KEMBasedMAC | ${pki_message} | ${ss} |

    """
    if private_key is None and kem_ct_info is None and not peer_cert and shared_secret is None:
        raise ValueError("Either `kem_ct_info` and `private_key` or `peer_cert` or `shared_secret` must be provided.")

    if shared_secret is not None:
        shared_secret = str_to_bytes(shared_secret)

    elif kem_ct_info is not None:
        private_key = ensure_is_kem_priv_key(private_key)
        ct = kem_ct_info["ct"].asOctets()
        shared_secret = private_key.decaps(ct)
    else:
        public_key = keyutils.load_public_key_from_spki(
            peer_cert["tbsCertificate"]["subjectPublicKeyInfo"]  # type: ignore
        )
        public_key = ensure_is_kem_pub_key(public_key)
        shared_secret, kem_ct = public_key.encaps()
        info_val = prepare_kem_ciphertextinfo(key=public_key, ct=kem_ct)
        pki_message["header"]["generalInfo"].append(info_val)
        kem_context = kem_context or prepare_kem_other_info(
            transaction_id=pki_message["header"]["transactionID"].asOctets(), context=context, static_string="CMP-KEM"
        )

    prot_alg_id = prepare_alg_ids.prepare_kem_based_mac_alg_id(
        hash_alg=hash_alg, length=32, kem_context=kem_context, kdf=kdf
    )
    pki_message["header"]["protectionAlg"] = prot_alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )

    data = prepare_protected_part(pki_message)
    mac = compute_kem_based_mac_from_alg_id(data=data, alg_id=prot_alg_id, ss=shared_secret)

    if bad_message_check:
        mac = utils.manipulate_first_byte(mac)

    pki_message["protection"] = prepare_pki_protection_field(mac)
    return pki_message


def _process_kem_other_info(kem_other_info: bytes, expected_tx_id: Optional[bytes] = None) -> None:
    """Process the KEMOtherInfo structure from bytes.

    :param kem_other_info: The KEMOtherInfo structure as bytes.
    :param expected_tx_id: The expected transaction ID. Defaults to `None`.
    """
    kem_info, rest = decoder.decode(kem_other_info, asn1Spec=KemOtherInfoAsn1())
    if rest:
        raise ValueError("The decoding of the `KemOtherInfo` had a remainder.")

    kem_info["transactionID"] = kem_info["transactionID"].asOctets()

    if expected_tx_id is not None and kem_info["transactionID"] != expected_tx_id:
        raise ValueError("The transactionID does not match the expected value.")

    static_string = kem_info["staticString"][0]
    if static_string != "CMP-KEM":
        raise ValueError(f"Unexpected static string: {static_string}. MUST be 'CMP-KEM'.")

    if kem_info["kemContext"].isValue:
        raise NotImplementedError("KEMContext inside the `KemOtherInfo` structure is not yet supported.")


@not_keyword
def verify_kem_based_mac_protection(
    pki_message: PKIMessageTMP,
    private_key: Optional[KEMPrivateKey] = None,
    shared_secret: Optional[bytes] = None,
) -> None:
    """Verify the KEMBasedMac protection of a `PKIMessage`.

    :param pki_message: The `PKIMessage` to verify.
    :param private_key: The private key kem used to verify the KEMBasedMac.
    :param shared_secret: The shared secret to use for verification. Defaults to `None`.
    :raises ValueError: If the KEMBasedMac verification fails.
    ValueError: If neither `private_key` nor `shared_secret` is provided.
    ValueError: If the KEM algorithm OID does not match the private key's OID.
    ValueError: If the decoding of the `KemCiphertextInfoValue` had a remainder.
    """
    if private_key is None and shared_secret is None:
        raise ValueError("Either `private_key` or `shared_secret` must be provided.")

    if private_key is not None:
        private_key = convertutils.ensure_is_kem_priv_key(private_key)

    if shared_secret is not None:
        pass

    elif private_key is not None:
        kem_ct_info = None
        for x in pki_message["header"]["generalInfo"]:
            if x["infoType"] == id_it_KemCiphertextInfo:
                kem_ct_info = x["infoValue"]
                break

        if kem_ct_info is None:
            raise ValueError("The `KemCiphertextInfo` field is missing in the `PKIMessage`.")

        kem_ct_info_val, rest = decoder.decode(kem_ct_info, asn1Spec=KemCiphertextInfoValue())

        if rest:
            raise ValueError("The decoding of the `KemCiphertextInfoValue` had a remainder.")

        kem_oid = kem_ct_info_val["kem"]["algorithm"]

        if kem_oid != get_kem_oid_from_key(private_key):
            oid_name = may_return_oid_to_name(kem_oid)
            key_name = private_key.name
            raise ValueError(
                f"The KEM algorithm OID does not match the private key's OID. Expected: {key_name} Got:{oid_name}"
            )

        kem_ct = kem_ct_info_val["ct"].asOctets()
        shared_secret = private_key.decaps(kem_ct)
        logging.info("Shared Secret %s", shared_secret.hex())

    if shared_secret is None:
        raise ValueError("Either `private_key` or `shared_secret` must be provided.")

    data = prepare_protected_part(pki_message)
    alg_id = pki_message["header"]["protectionAlg"]
    computed_mac = compute_kem_based_mac_from_alg_id(data, alg_id, shared_secret)
    logging.debug("Computed MAC: %s", computed_mac.hex())
    logging.debug("Received MAC: %s", pki_message["protection"].asOctets().hex())
    if computed_mac != pki_message["protection"].asOctets():
        raise BadMessageCheck("The KEMBasedMac verification failed.")


@not_keyword
def get_rsa_oaep_padding(param: rfc4055.RSAES_OAEP_params) -> padding.OAEP:
    """Generate the appropriate RSA OAEP padding configuration based on the `RSAES_OAEP_params`.

    :param param: The `RSAES_OAEP_params` structure that defines the padding scheme, including the hash function,
                  mask generation function, and optional pSourceFunc.
    :return: A `cryptography` library `OAEP` padding object configured with the specified parameters.
    :raises ValueError: If there is an error decoding the mask generation function parameters.
    :raises NotImplementedError: If the pSourceFunc parameter is present (not supported by the implementation).
    """
    hash_name = get_hash_from_oid(param["hashFunc"]["algorithm"])
    hash_fun = hash_name_to_instance(hash_name)  # type: ignore

    data = param["maskGenFunc"]["parameters"]
    oid, rest = decoder.decode(data, univ.ObjectIdentifier())
    if rest != b"":
        raise ValueError("Error decoding MGF parameters")

    mgf_hash_alg = hash_name_to_instance(get_hash_from_oid(oid))  # type: ignore

    if param["pSourceFunc"].isValue:
        raise NotImplementedError("pSourceFunc is not supported")

    return padding.OAEP(mgf=padding.MGF1(algorithm=mgf_hash_alg), algorithm=hash_fun, label=None)


@keyword(name="Sign Data With AlgID")
def sign_data_with_alg_id(  # noqa: D417 Missing argument descriptions in the docstring
    key: SignKey, alg_id: rfc9480.AlgorithmIdentifier, data: bytes
) -> bytes:
    """Sign the provided data using the given algorithm identifier.

    Arguments:
    ---------
        - `key`: The private key used to sign the data.
        - `alg_id`: The algorithm identifier specifying the algorithm and any associated parameters for signing.
        - `data`: The data to sign.

    Returns:
    -------
        - The digital signature.

    Raises:
    ------
        - `ValueError`: If the private key type is unsupported.

    Examples:
    --------
    | ${signature} = | Sign Data With Alg ID | ${key} | ${alg_id} | ${data} |

    """
    oid = alg_id["algorithm"]

    if isinstance(key, CompositeSig04PrivateKey):
        name: str = COMPOSITE_SIG04_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = "hash-" in name
        return key.sign(data=data, use_pss=use_pss, pre_hash=pre_hash)
    if isinstance(key, CompositeSig03PrivateKey):
        name: str = CMS_COMPOSITE03_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = "hash-" in name
        return key.sign(data=data, use_pss=use_pss, pre_hash=pre_hash)

    # TODO fix this
    if oid in RSASSA_PSS_OID_2_NAME and isinstance(key, rsa.RSAPrivateKey):
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        return cryptoutils.sign_data(key=key, data=data, hash_alg=hash_alg, use_rsa_pss=True)

    if oid in PQ_OID_2_NAME or oid in TRAD_SIG_OID_2_NAME:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        return cryptoutils.sign_data(key=key, data=data, hash_alg=hash_alg, use_rsa_pss=False)
    raise ValueError(f"Unsupported private key type: {type(key).__name__} oid:{may_return_oid_to_name(oid)}")


def _verify_composite_sig(
    public_key: CompositeSig03PublicKey,
    data: bytes,
    signature: bytes,
    name: str,
) -> None:
    """Verify a composite signature.

    :param public_key: The public key used for verification.
    :param data: The original data that was signed.
    :param signature: The signature to verify.
    :param name: The name of the signature algorithm.
    :raises InvalidSignature: If the signature is invalid.
    """
    use_pss = name.endswith("-pss")
    logging.debug(name)
    pre_hash = "hash-" in name
    public_key.verify(
        data=data,
        signature=signature,
        use_pss=use_pss,
        pre_hash=pre_hash,
    )


@keyword(name="Verify Signature With AlgID")
def verify_signature_with_alg_id(  # noqa: D417 Missing argument descriptions in the docstring
    public_key: VerifyKey, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, signature: bytes
) -> None:
    """Verify the provided data and signature using the given algorithm identifier.

    Supports traditional-, pq- and composite signature algorithm.

    Arguments:
    ---------
        - `public_key`: The public key to verify the signature.
        - `alg_id`: An `AlgorithmIdentifier` specifying the algorithm and any associated parameters for
        signature verification.
        - `data`: The original message or data whose signature needs verification, as a byte string.
        - `signature`: The digital signature to verify, as a byte string.

    Raises:
    ------
        - `ValueError`: If the algorithm identifier is unsupported or invalid.
        - `InvalidSignature`: If the signature is invalid.

    Examples:
    --------
    | Verify Signature With Alg ID | ${public_key} | ${alg_id} | ${data} | ${signature} |

    """
    oid = alg_id["algorithm"]

    if oid in CMS_COMPOSITE03_OID_2_NAME or oid in COMPOSITE_SIG04_OID_2_NAME:
        name: str = CMS_COMPOSITE03_OID_2_NAME.get(oid) or COMPOSITE_SIG04_OID_2_NAME[oid]
        if not isinstance(public_key, CompositeSig03PublicKey):
            raise ValueError(
                f"The public key must be a CompositeSigPublicKey. Got: {keyutils.get_key_name(public_key)}"
            )
        _verify_composite_sig(public_key=public_key, data=data, signature=signature, name=name)

    elif oid in RSASSA_PSS_OID_2_NAME and isinstance(public_key, rsa.RSAPublicKey):
        verify_rsassa_pss_from_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)

    elif oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME or oid in TRAD_SIG_OID_2_NAME:
        try:
            hash_alg = get_hash_from_oid(oid, only_hash=True)
            keyutils.check_consistency_sig_alg_id_and_key(alg_id, public_key)

        except ValueError as e:
            raise BadAlg(f"Algorithm identifier and key mismatch: {e}. Could not determine the hash algorithm.") from e

        except BadAlg as e:
            raise InvalidSignature(e.message) from e
        cryptoutils.verify_signature(public_key=public_key, signature=signature, data=data, hash_alg=hash_alg)
    else:
        raise BadAlg(f"Unsupported public key type: {type(public_key).__name__}.")


def _prepare_catalyst_info_vals(
    prot_alg_id: rfc9480.AlgorithmIdentifier, public_key: Optional[VerifyKey]
) -> Tuple[rfc9480.InfoTypeAndValue, Optional[rfc9480.InfoTypeAndValue]]:
    """Prepare the InfoTypeAndValue objects for the catalyst protection scheme.

    :param prot_alg_id: The protection algorithm identifier.
    :param public_key: The alternative public key to include in the message.
    :return: The InfoTypeAndValue objects.
    """
    info_val_type_pub_key = None

    info_val_type = rfc9480.InfoTypeAndValue()
    info_val_type["infoType"] = id_ce_altSignatureAlgorithm
    info_val_type["infoValue"] = encoder.encode(prot_alg_id)

    if public_key is not None:
        info_val_type_pub_key = rfc9480.InfoTypeAndValue()
        info_val_type_pub_key["infoType"] = id_ce_subjectAltPublicKeyInfo
        spki = subject_public_key_info_from_pubkey(public_key)
        info_val_type_pub_key["infoValue"] = encoder.encode(spki)

    return info_val_type, info_val_type_pub_key


def _compute_and_prepare_pkimessage_sig_protection(
    signing_key: SignKey,
    pki_message: PKIMessageTMP,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
    bad_message_check: bool = False,
) -> PKIMessageTMP:
    """Compute the protection for a PKIMessage.

    :param signing_key: The private key used for signing.
    :param pki_message: The PKIMessage to protect.
    :param hash_alg: The hash algorithm to use for signing.
    :param use_rsa_pss: Whether to use RSA-PSS padding for signing.
    :param use_pre_hash: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :return: The protected PKIMessage.
    :raises ValueError: If the PKIMessage is missing required fields.
    """
    prot_alg_id = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )
    prot_alg_id = prot_alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )
    pki_message["header"]["protectionAlg"] = prot_alg_id

    der_data = prepare_protected_part(pki_message)
    signature = sign_data_with_alg_id(
        alg_id=pki_message["header"]["protectionAlg"],
        data=der_data,
        key=signing_key,
    )

    if bad_message_check:
        signature = utils.manipulate_bytes_based_on_key(signature, signing_key)

    pki_message["protection"] = prepare_pki_protection_field(signature)
    return pki_message


def _patch_extra_certs(
    pki_message: PKIMessageTMP,
    cert: Optional[rfc9480.CMPCertificate],
    certs_path: str,
    exclude_certs: bool,
) -> PKIMessageTMP:
    """Patch the `extraCerts` field of the PKIMessage.

    :param pki_message: The PKIMessage.
    :param certs_path: The directory path to the certificate chain.
    :param exclude_certs: Whether to exclude the certificates from the message.
    :return: The may patched PKIMessage.
    """
    if cert and not exclude_certs:
        certs = certutils.load_certificates_from_dir(certs_path)
        if certs:
            certs = pq_verify_logic.build_migration_cert_chain(cert=cert, certs=certs, allow_self_signed=True)
            logging.info("Loaded %d certificates from the directory.", len(certs))
            pki_message["extraCerts"].extend(certs)
    return pki_message


@keyword(name="Protect Hybrid PKIMessage")
def protect_hybrid_pkimessage(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP,
    private_key: SignKey,
    protection: str = "signature",
    do_patch: bool = True,
    alt_signing_key: Optional[SignKey] = None,
    include_alt_pub_key: bool = False,
    bad_message_check: bool = False,
    **params,
):
    """Protect a PKIMessage with a hybrid protection scheme.

    Supports the following protection types:
    ----------------------------------------
    - `signature`: Protect the message with a pq or traditional signature.
    - `composite`: Protect the message with a composite signature (must not be a single key).
    - `catalyst`: Protect the message with an alternative signature (can be done with a secondary key).

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to protect.
        - `private_key`: The private key used for the primary signature.
        - `protection`: The protection type to use. Defaults to `signature`.
        - `do_patch`: Whether to patch the sender and senderKID fields.
        - `alt_signing_key`: The alternative signing key to use for composite protection,
        or the catalyst signature.
        - `include_alt_pub_key`: Whether to include the alternative public key in the message.
        - `bad_message_check`: Whether to manipulate the signature. Defaults to `False`.

    **params:
    --------
        - `cert`: The certificate to patch the sender and senderKID fields.
        - `certs_path`: The path to the certificates directory, to build the certificate chain.
        - `exclude_certs`: Whether to exclude the certificates from the message.
        - `do_patch`: Whether to patch the sender and senderKID fields. Defaults to `True`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to `sha256`.
        - `use_rsa_pss`: Whether to use RSA-PSS padding for signing. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.

    Raises:
    ------
        - `ValueError`: If the protection type is not supported.
        - `ValueError`: If the PKIMessage is missing required fields (sender, pvno, recipient).

    Examples:
    --------
    | Protect Hybrid PKIMessage | ${pki_message} | ${private_key} | do_patch=True | alt_signing_key=${alt_signing_key} |
    | Protect Hybrid PKIMessage | ${pki_message} | ${private_key} | bad_message_check=True | protection=composite |

    """
    pki_message = patch_sender_and_sender_kid(
        do_patch=do_patch,
        pki_message=pki_message,
        cert=params.get("cert"),
    )

    if private_key is None:
        raise ValueError("The private key must be provided, to protect the `PKIMessage`.")

    if protection not in ["signature", "composite", "catalyst"]:
        raise ValueError("Only 'signature', 'composite', and 'catalyst' protection types are supported.")

    pki_message = _patch_extra_certs(
        pki_message=pki_message,
        cert=params.get("cert"),
        certs_path=params.get("certs_path", "data/cert_logs/"),
        exclude_certs=params.get("exclude_certs", False),
    )

    if protection == "signature":
        return _compute_and_prepare_pkimessage_sig_protection(
            signing_key=private_key,
            pki_message=pki_message,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
            bad_message_check=bad_message_check,
        )

    if protection == "composite":
        if alt_signing_key is not None:
            if isinstance(alt_signing_key, PQSignaturePrivateKey):
                private_key, alt_signing_key = alt_signing_key, private_key

            private_key = CompositeSig04PrivateKey(
                pq_key=private_key,  # type: ignore
                trad_key=alt_signing_key,  # type: ignore
            )

        return _compute_and_prepare_pkimessage_sig_protection(
            signing_key=private_key,
            pki_message=pki_message,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
            bad_message_check=bad_message_check,
        )

    if alt_signing_key is None:
        raise ValueError("The alternative signing key must be provided for `catalyst` protection.")

    alt_prot_alg_id = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=alt_signing_key,
        hash_alg=params.get("hash_alg", "sha256"),
        use_rsa_pss=params.get("use_rsa_pss", True),
        use_pre_hash=params.get("use_pre_hash", False),
    )
    prot_alg_id = prepare_alg_ids.prepare_sig_alg_id(
        signing_key=private_key,
        hash_alg=params.get("hash_alg", "sha256"),
        use_rsa_pss=params.get("use_rsa_pss", True),
        use_pre_hash=params.get("use_pre_hash", False),
    )

    prot_alg_id = prot_alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )
    pki_message["header"]["protectionAlg"] = prot_alg_id

    if not alt_signing_key:
        raise ValueError("The alternative signing key must be provided for `catalyst` protection.")

    info_val_type, info_val_type_pub_key = _prepare_catalyst_info_vals(
        prot_alg_id=alt_prot_alg_id,
        public_key=alt_signing_key.public_key() if include_alt_pub_key else None,  # type: ignore
    )
    pki_message["header"]["generalInfo"].append(info_val_type)
    if info_val_type_pub_key is not None:
        pki_message["header"]["generalInfo"].append(info_val_type_pub_key)

    der_data = prepare_protected_part(pki_message)

    signature = sign_data_with_alg_id(
        alg_id=alt_prot_alg_id,
        data=der_data,
        key=alt_signing_key,
    )

    if bad_message_check:
        signature = utils.manipulate_first_byte(signature)

    info_val_type_sig = rfc9480.InfoTypeAndValue()
    info_val_type_sig["infoType"] = id_ce_altSignatureValue
    info_val_type_sig["infoValue"] = encoder.encode(univ.BitString.fromOctetString(signature))
    pki_message["header"]["generalInfo"].append(info_val_type_sig)

    der_data = prepare_protected_part(pki_message)

    signature = sign_data_with_alg_id(
        alg_id=prot_alg_id,
        data=der_data,
        key=private_key,
    )
    pki_message["protection"] = prepare_pki_protection_field(signature)

    return pki_message


@keyword(name="Prepare ProtectedPart")
def prepare_protected_part(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
) -> bytes:
    """Prepare the parts of the PKIMessage for verification.

    Arguments:
    ---------
       - `pki_message`: The PKIMessage to prepare the protected part for.

    Returns:
    -------
       - The data to verify.

    Raises:
    ------
         - `ValueError`: If the PKIMessage is missing required fields (sender, pvno, recipient).

    Examples:
    --------
    | ${der_data}= | Prepare ProtectedPart | ${pki_message} |

    """
    for x in ["sender", "pvno", "recipient"]:
        if x not in pki_message["header"]:
            raise ValueError(f"The `{x}` field has no value, can not protect the `PKIMessage`.")

    if not pki_message["body"].isValue:
        raise ValueError("The `body` field has no value, can not protect the `PKIMessage`.")

    protected_part = ProtectedPartTMP()
    protected_part["header"] = pki_message["header"]
    protected_part["body"] = pki_message["body"]
    try:
        return encoder.encode(protected_part)
    except pyasn1.error.PyAsn1Error as e:
        raise ValueError("The encoding of the `ProtectedPart` failed.") from e


@not_keyword
def verify_composite_signature_with_keys(
    data: bytes,
    signature: bytes,
    alg_id: rfc5280.AlgorithmIdentifier,
    first_key: Optional[PublicKey],
    second_key: Optional[PublicKey],
) -> None:
    """Verify the composite signature.

    :param data: The data to verify.
    :param alg_id: The algorithm identifier.
    :param signature: The signature to verify.
    :param first_key: The first key to cast be used in the composite signature key.
    :param second_key: The second key to be used in the composite signature key.
    :raises InvalidSignature: If the signature is invalid.
    """
    if first_key is None or second_key is None:
        raise ValueError("Both keys must be provided.")

    if not isinstance(first_key, PQSignaturePublicKey):
        first_key, second_key = second_key, first_key

    if not isinstance(first_key, MLDSAPublicKey):
        raise InvalidKeyCombination("The Composite signature pq-key is not a MLDSA key.")

    if not isinstance(second_key, (ECVerifyKey, RSAPublicKey)):
        raise InvalidKeyCombination("The Composite signature trad-key is not a EC or RSA key.")

    if alg_id["algorithm"] in CMS_COMPOSITE03_OID_2_NAME:
        public_key = CompositeSig03PublicKey(pq_key=first_key, trad_key=second_key)  # type: ignore

    elif alg_id["algorithm"] in COMPOSITE_SIG04_OID_2_NAME:
        public_key = CompositeSig04PublicKey(pq_key=first_key, trad_key=second_key)  # type: ignore

    else:
        raise BadAlg(f"Invalid algorithm for composite signature: {alg_id['algorithm']}")

    verify_signature_with_alg_id(
        public_key=public_key,
        alg_id=alg_id,
        data=data,
        signature=signature,
    )
