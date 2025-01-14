# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the logic, which allows a Client to have more flexibility in issuing a key.

Because some keys like ML-KEM are not signing keys and need a different Proof-of-Possession mechanism.
Also sometimes a user CA, RA wants to see the private key.

"""

import logging

# TODO update for better explanation, if time or after thesis.
from typing import Optional, Tuple, Union

import pyasn1.error
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pq_logic.kem_mechanism import ECDHKEM
from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey
from pq_logic.migration_typing import HybridKEMPrivateKey
from pq_logic.trad_typing import ECDHPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import constraint, tag, univ
from pyasn1.type.base import Asn1Type
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5652, rfc6955, rfc9480, rfc9629
from robot.api.deco import keyword, not_keyword
from unit_tests.asn1_wrapper_class.pki_message_wrapper import PKIMessage, prepare_name

from resources import asn1utils, protectionutils
from resources.asn1_structures import POPODecKeyChallContentAsn1
from resources.ca_kga_logic import validate_enveloped_data
from resources.certutils import load_public_key_from_cert
from resources.cmputils import _prepare_pki_message, compare_general_name_and_name, prepare_general_name
from resources.convertutils import str_to_bytes
from resources.cryptoutils import compute_hmac, perform_ecdh
from resources.envdatautils import (
    build_env_data_for_exchange,
    prepare_issuer_and_serial_number,
    prepare_one_asymmetric_key,
)
from pq_logic.pq_utils import is_kem_public_key
from resources.exceptions import InvalidKeyCombination
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import compute_hash
from resources.protectionutils import compute_and_prepare_mac
from resources.typingutils import ECDHPrivKeyTypes, EnvDataPrivateKey, PrivateKey, Strint
from resources.utils import get_openssl_name_notation


@keyword(name="Prepare PKMAC POPO")
def prepare_pkmac_popo(
    cert_request: rfc4211.CertRequest,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    private_key: Optional[PrivateKey] = None,
    shared_secret: Optional[Union[bytes, str]] = None,
    mac_alg: str = "password_based_mac",
    salt: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    iterations: int = 100.000,
) -> rfc4211.ProofOfPossession:
    """Prepare the Proof-of-Possession structure for the PKMAC value.

    :param cert_request: The certificate request to prepare the PoP structure.
    :param ca_cert: The CA certificate to use for `DH` key exchange. Defaults to `None`.
    :param private_key: The private key to use `DH` key exchange. Defaults to `None`.
    :param shared_secret: The shared secret to use for the `ProofOfPossession` structure. Defaults to `None`.
    :param mac_alg: The MAC algorithm to use for the `ProofOfPossession` structure. Defaults to `password_based_mac`.
    :param salt: The salt to use for the MAC algorithm. Defaults to `None`.
    :param hash_alg: The hash algorithm to use for the MAC algorithm. Defaults to `sha256`.
    :param iterations: The number of iterations to use for the MAC algorithm. Defaults to `100.000`.
    :return: The populated `ProofOfPossession` structure.
    """
    if shared_secret is None:
        if private_key is None or ca_cert is None:
            raise ValueError("The shared secret or the private key and CA certificate are required.")
        shared_secret = _compute_ss(client_key=private_key, ca_cert=ca_cert)

    shared_secret = str_to_bytes(shared_secret)
    data = encoder.encode(cert_request)
    return _prepare_pkmac_val(
        shared_secret=shared_secret,
        data=data,
        mac_alg=mac_alg,
        for_agreement=False,
        hash_alg=hash_alg,
        iterations=iterations,
        salt=salt,
    )


# TODO fix doc for RF.
@keyword(name="Prepare Private Key For POP")
def prepare_private_key_for_pop(
    private_key: PrivateKey, sender: Optional[str] = None, use_string: bool = False
) -> rfc4211.EncKeyWithID:
    """Prepare the private key for the Proof-of-Possession structure.

    :param private_key: A private key to prepare for the PoP structure. Should be a non-signing key.
    :param sender: The sender name to include in the PoP structure. Defaults to `None`.
    (must be present if PoP)
    :param use_string: Whether to use a string for the sender name. Defaults to `False`.
    Otherwise, a `GeneralName` structure is used, which sets the distinguished name.
    :return: The DER-encoded PoP structure.
    """
    one_asym_key = prepare_one_asymmetric_key(private_key)

    data = rfc4211.EncKeyWithID()

    tmp = rfc4211.PrivateKeyInfo()
    tmp["privateKeyAlgorithm"]["algorithm"] = one_asym_key["privateKeyAlgorithm"]["algorithm"]
    tmp["privateKey"] = one_asym_key["privateKey"]
    tmp["version"] = 0

    data["privateKey"] = tmp
    if sender is not None:
        # MUST be present, if pop.
        if use_string:
            data["identifier"]["string"] = sender
        else:
            data["identifier"]["generalName"] = prepare_general_name("directoryName", sender)

    logging.debug(f"Private key for PoP: {data.prettyPrint()}")
    return data


# TODO fix doc for RF.
@keyword(name="Prepare KEM Env Data For POPO")
def prepare_kem_env_data_for_popo(
    ca_cert: rfc9480.CMPCertificate,
    data: Optional[Union[Asn1Type, bytes, str]] = None,
    client_key: Optional[PrivateKey] = None,
    rid_sender: str = "Null-DN",
    cert_req_id: int = 0,
    enc_key_sender: str = "CN=CMP-Test-Suite",
    cek: Optional[bytes] = None,
    key_encipherment: bool = True,
    hybrid_key_recip: Optional[HybridKEMPrivateKey] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare a `ProofOfPossession` structure for a KEM-based key exchange.

    :param ca_cert: The CA certificate to use for the KEM-based key exchange.
    :param data: The data to encrypt with the KEM-based key exchange.
    :param client_key: The client's private key to send to the CA/RA.
    :param rid_sender: The sender name to use for the `RecipientIdentifier` structure. Defaults to `Null-DN`.
    :param cert_req_id: The certificate request ID to use for the `RecipientIdentifier` structure. Defaults to `0`.
    :param enc_key_sender: The sender name to use for the `EncKeyWithID` structure. Defaults to `CN=CMP-Test-Suite`.
    :param cek: The Content Encryption Key (CEK) to use for the KEM-based key exchange. Defaults to `None`.
    :param key_encipherment: Whether to use the `keyEncipherment` or `keyAgreement` option for the `ProofOfPossession`
    structure. Defaults to `True`.
    :param hybrid_key_recip:  The hybrid key recipient to use for the KEM-based key exchange. Defaults to `None`.
    :return: The `ProofOfPossession` structure for the KEM-based key exchange.
    """
    if data is not None:
        if isinstance(data, Asn1Type):
            data = encoder.encode(data)

        data = str_to_bytes(data)

    elif data is None and client_key is None:
        raise ValueError("Either the data to encrypt is required, or the client key.")

    else:
        data = prepare_private_key_for_pop(private_key=client_key, sender=enc_key_sender)
        data = encoder.encode(data)

    issuer_and_ser = prepare_issuer_and_serial_number(serial_number=cert_req_id, issuer=rid_sender)

    env_data = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))

    ca_public_key = load_public_key_from_spki(ca_cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not is_kem_public_key(ca_public_key):
        raise InvalidKeyCombination(f"The KEM env data got an invalid key: {type(ca_public_key).__name__}")

    env_data = build_env_data_for_exchange(
        public_key_recip=ca_public_key,
        cert_recip=ca_cert,
        cek=cek,
        target=env_data,
        data=data,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=hybrid_key_recip,
    )

    if key_encipherment:
        index = 2
        option = "keyEncipherment"
    else:
        index = 3
        option = "keyAgreement"

    popo_priv_key = rfc4211.POPOPrivKey().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, index)
    )
    popo_priv_key["encryptedKey"] = env_data

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option] = popo_priv_key
    return popo_structure


@not_keyword
def is_null_dn(name: rfc5280.Name) -> bool:
    """Check if the given Name is a NULL-DN, meaning it has no RDNs."""
    return encoder.encode(name) == b"\x30\x00"


def _extract_rid(
    recipient_info: rfc5652.RecipientInfo, allow_pwri: bool = False, kari_index: int = 0
) -> Optional[rfc5652.IssuerAndSerialNumber]:
    """Extract and return the 'rid' field as an IssuerAndSerialNumber or RecipientKeyIdentifier.

    :param recipient_info:
    :param allow_pwri: Whether to allow the pwri structure to extract the challenge. Defaults to `False`.
    :param kari_index: The index inside the `RecipientEncryptedKeys` structure to extract the rid of.
    :return: The `IssuerAndSerialNumber` structure if not pwri.
    :raises ValueError: If the 'rid' field type is invalid or not `issuerAndSerialNumber`,
        If the recipient_info type is `PasswordRecipientInfo` and `allow_pwri`.
    """
    if recipient_info.getName() == "ktri":
        rid = recipient_info["rid"]
        if rid.getName() == "issuerAndSerialNumber":
            raise ValueError("Invalid 'rid' type found in KeyTransRecipientInfo.")

        return rid["issuerAndSerialNumber"]

    elif recipient_info.getName() == "ori":
        if recipient_info["ori"]["oriType"] != rfc9629.id_ori_kem:
            raise NotImplementedError("Unsupported `oriType` in OriginatorRecipientInfo. Expected `id_ori_kem`.")

        kemri, _ = decoder.decode(recipient_info["ori"]["oriValue"], rfc9629.KEMRecipientInfo())
        rid = recipient_info["rid"]
        if rid.getName() != "issuerAndSerialNumber":
            raise ValueError("Invalid 'rid' type found in KEMRecipientInfo. Expected `issuerAndSerialNumber`.")

        return rid["issuerAndSerialNumber"]

    elif recipient_info.getName() == "PasswordRecipientInfo":
        if not allow_pwri:
            raise ValueError("The CA/RA responded with the `PasswordRecipientInfo`.")

        return None

    elif recipient_info.getName() == "kari":
        recipient_encrypted_key = recipient_info["recipientEncryptedKeys"][kari_index]
        rid = recipient_encrypted_key["rid"]
        if rid.getName() != "issuerAndSerialNumber":
            raise ValueError("Invalid 'rid' type in KeyAgreeRecipientIdentifier.")

        return rid["issuerAndSerialNumber"]

    else:
        raise ValueError("Unsupported recipient information type.")


@not_keyword
def validate_issuer_is_null_dn_and_cert_req_id(
    env_data: rfc5652.EnvelopedData,
    cert_req_id: int,
    recip_index: int = 0,
    kari_index: int = 0,
    allow_pwri: bool = False,
) -> None:
    """Validate the `issuerAndSerialNumber` field inside the encryptRand EnvelopedData structure.

    :param env_data: The EnvelopedData structure containing the encryptedRand.
    :param cert_req_id: The certificate request ID to validate against the serialNumber.
    :param recip_index: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
    :param kari_index: The index of the recipientEncryptedKeys to extract the `rid` field from. Defaults to `0`.
    :param allow_pwri: Whether to allow the `PasswordRecipientInfo` structure to extract the
    challenge. Defaults to `False`.
    """
    recipient_infos: rfc9480 = env_data["recipientInfos"]
    recipient_info: rfc5652.RecipientInfo = recipient_infos[recip_index]

    rid = _extract_rid(recipient_info=recipient_info, kari_index=kari_index, allow_pwri=allow_pwri)

    # The sender MUST populate the rid field in the EnvelopedData sequence using the
    # issuerAndSerialNumber choice containing a NULL-DN as issuer and the certReqId
    # as serialNumber. The client MAY ignore the rid field

    if rid is not None:
        issuer = rid["issuer"]
        if is_null_dn(issuer):
            raise ValueError("`rid` field is not correctly populated with `NULL-DN`")

        if int(rid["serialNumber"]) == cert_req_id:
            raise ValueError("`rid` field serialNumber si not equal to the `certReqId`")


def _parse_pkimessage_from_der(raw_bytes: bytes) -> Tuple[rfc9480.PKIMessage, POPODecKeyChallContentAsn1]:
    """Decode the `PKIMessage` and `POPODecKeyChallContent` from the DER-encoded bytes.

    :param raw_bytes: The DER-encoded `PKIMessage` as bytes.
    :return: The parsed `PKIMessage` object and the `POPODecKeyChallContent` object.
    """
    # TODO fix if pyasn1-alt-modules is updated.
    pki_header, rest = decoder.decode(raw_bytes, rfc9480.PKIHeader())
    popdecc, rest = decoder.decode(
        rest, POPODecKeyChallContentAsn1().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
    )

    pki_protection = rfc9480.PKIProtection().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    extra_certs = (
        univ.SequenceOf(componentType=rfc9480.CMPCertificate())
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, float("inf")))
        .subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    )

    if rest:
        pki_protection, rest = decoder.decode(rest, pki_protection)

    if rest:
        extra_certs, rest = decoder.decode(rest, extra_certs)

    if rest != b"":
        raise ValueError("Decoding the PKIMessage had a remainder.")

    msg = rfc9480.PKIMessage()
    msg["header"] = pki_header
    msg["extraCerts"] = extra_certs
    msg["protection"] = pki_protection
    return msg, popdecc


@keyword(name="Process PKIMessage With Popdecc")
def process_pkimessage_with_popdecc(
    pki_message: bytes,
    ee_key: Optional[EnvDataPrivateKey] = None,
    password: Optional[Union[str, bytes]] = None,
    index: int = 0,
    cert_req_id: int = 0,
    recip_index: int = 0,
    expected_size: int = 1,
    allow_pwri: bool = False,
    expected_sender: Optional[str] = None,
    request: Optional[rfc9480.PKIMessage] = None,
    use_dhbased_mac: bool = False,
) -> rfc9480.PKIMessage:
    """Process the POPODecKeyChallContent structure by decrypting the encryptedRand field or decapsulating the challenge

    :param pki_message: The DER-encoded PKIMessage as bytes.
    :param ee_key: The private key of the end-entity to process the challenge.
    :param password: Optional password for compute the PKIMessage protection.
    :param index: The index
    :param cert_req_id: The certificate request ID to validate against the serialNumber.
    :param recip_index: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
    :param expected_size: The expected size inside the `EnvelopedData` structure.
    :param allow_pwri: The flag to allow the `PasswordRecipientInfo` structure to extract the
    challenge. Defaults to `False`.
    :param expected_sender: The expected sender name to validate in the `Rand` structure.
    :param request: The original PKIMessage request to build the new one for the `challenge`.
    :param use_dhbased_mac: Whether to use the DH-based MAC for the `challenge` field,
    and then update the old request. Otherwise, update the old request Proof-of-Possession.
    :return: The updated PKIMessage as DER-encoded bytes, so send over the wire.

    :raises ValueError: If the PKIMessage decoding has a remainder.
    :raises NotImplementedError: If the challenge is not encryptedRand.
    :raises ValueError: If the PKIMessage version is invalid for the encryptedRand presence.
    :raises ValueError: If the `rid` field is not correctly populated with NULL-DN and
    `cert_req_id` as `serialNumber`.
    """
    msg, popdecc = _parse_pkimessage_from_der(pki_message)

    challenge = popdecc[index]
    validate_pki_message_version(msg, popdecc)

    env_data = challenge["encryptedRand"]
    if env_data is not None:
        rand = _process_encrypted_rand(
            env_data, msg, password, ee_key, recip_index, cert_req_id, allow_pwri, expected_size
        )
        num = rand["int"]
        if expected_sender is not None:
            sender = prepare_name(expected_sender)
            if compare_general_name_and_name(rand["sender"], sender):
                rand_name = get_openssl_name_notation(rand["sender"])
                raise ValueError(f"Expected sender name: {expected_sender}. Got: {rand_name}")

    else:
        ss = _process_challenge(challenge, ee_key)
        if request is None:
            raise ValueError("The original PKIMessage request is required to build the new one for the challenge.")

        pki_message = _prepare_pki_message(
            sender=request["header"]["sender"],
            recipient=request["header"]["recipient"],
            transaction_id=request["header"]["transactionID"].asOctets(),
            sender_nonce=request["header"]["senderNonce"].asOctets(),
            recip_nonce=request["header"]["recipNonce"].asOctets(),
            recip_kid=request["header"]["recipKID"].asOctets(),
            sender_kid=request["header"]["senderKID"].asOctets(),
            pvno=int(request["header"]["pvno"]),
        )
        if use_dhbased_mac:
            pki_message["body"] = request["body"]
            pki_message["extraCerts"] = request["extraCerts"]
            return protectionutils.protect_pkimessage(pki_message, shared_secret=ss)

        else:
            body_name = request["body"].getName()
            for x in request["body"][body_name]:
                popo = prepare_pkmac_popo(
                    request["body"][body_name][x]["certReq"], private_key=ee_key, shared_secret=ss
                )
                pki_message["body"][body_name][x]["popo"] = popo

            return pki_message

    msg["body"]["popdecr"].append(num)

    return msg


def validate_pki_message_version(pki_message: PKIMessage, popdecc: POPODecKeyChallContentAsn1) -> None:
    """Validate the PKIMessage version against the presence of the encryptedRand and challenge fields.

    :param pki_message: The PKIMessage to validate.
    :param popdecc: The `POPODecKeyChallContent` structure which contains the challenges.
    """
    is_enc_present = any(c["encryptedRand"].isValue for c in popdecc)

    if pki_message["pvno"] != 3 and is_enc_present:
        raise ValueError("Invalid PKIMessage version for encryptedRand presence")

    if pki_message["pvno"] != 2 and not is_enc_present:
        raise ValueError("Invalid PKIMessage version for challenge presence")


def _process_encrypted_rand(
    env_data: rfc9480.EnvelopedData,
    pki_message: PKIMessage,
    password: Optional[Union[str, bytes]],
    ee_key: Optional[Union[PQKEMPrivateKey, ECDHPrivateKey, RSAPrivateKey]],
    recip_index: int,
    cert_req_id: int,
    allow_pwri: bool,
    expected_size: int,
) -> rfc9480.Rand:
    """Process the encryptedRand field by decrypting it with the end-entity private key.

    :param env_data: The `EnvelopedData` structure containing the encryptedRand.
    :param pki_message: The PKIMessage containing the encryptedRand.
    :param password: The password to decrypt the encryptedRand.
    :param ee_key: The private key to decrypt the encryptedRand or perform the decapsulation.
    :param recip_index: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
    :param cert_req_id: The certificate request ID to validate against the serialNumber.
    :param allow_pwri: Whether to allow the `PasswordRecipientInfo` structure to extract
    the challenge. Defaults to `False`.
    :param expected_size: The expected size inside the `EnvelopedData` structure.
    :return: The decrypted challenge as a `Rand` object.
    """
    validate_issuer_is_null_dn_and_cert_req_id(
        env_data, recip_index=recip_index, cert_req_id=cert_req_id, allow_pwri=allow_pwri
    )
    raw_bytes = validate_enveloped_data(
        env_data=env_data,
        pki_message=pki_message,
        password=password,
        ee_key=ee_key,
        expected_raw_data=True,
        expected_size=expected_size,
    )

    obj, rest = decoder.decode(raw_bytes, asn1Spec=rfc9480.Rand())
    if rest:
        raise ValueError("Extra data after decoding Rand object")

    return obj


def _process_challenge(challenge_val: bytes, ee_key) -> bytes:
    """Process the challenge value by decrypting or decapuslation it with the end-entity private key.

    :param challenge_val: The `Challenge` to process.
    :param ee_key: The private key to decrypt the challenge.
    :return: The shared secret as the password field in the PKIMessage.
    """
    if isinstance(ee_key, rsa.RSAPrivateKey):
        ss = ee_key.decrypt(challenge_val, padding=padding.PKCS1v15())
    elif isinstance(ee_key, ECDHPrivateKey):
        ss = ECDHKEM(private_key=ee_key).decaps(challenge_val)
    elif isinstance(ee_key, PQKEMPrivateKey):
        ss = ee_key.decaps(challenge_val)
    elif isinstance(ee_key, AbstractCompositeKEMPrivateKey):
        ss = ee_key.decaps(challenge_val)
    else:
        raise ValueError("Unsupported key type")

    return ss


def _compute_ss(client_key, ca_cert):
    """Compute the shared secret (SS) between the client's private key and the CA's public key.

    This function handles different types of client keys:
    - Elliptic Curve Diffie-Hellman (ECDH) keys are processed using the `perform_ecdh` function.
    - Post-Quantum Key Encapsulation Mechanism (PQKEM) keys are processed via the `encaps` method.

    :param client_key: The client's private key (either ECDH or PQKEM).
    :param ca_cert: The CA's certificate used to obtain the CA's public key.

    :return: The computed shared secret.
    :raises ValueError: If the client key is of an unsupported type.
    """
    pub_key = load_public_key_from_cert(ca_cert)
    if isinstance(client_key, ECDHPrivKeyTypes):
        return perform_ecdh(client_key, pub_key)
    else:
        raise ValueError(f"The provided public key type is not expected: {type(client_key).__name__}")


# TODO fix doc
def _prepare_pkmac_val(
    shared_secret: bytes, data: bytes, mac_alg: str, for_agreement: bool = True, **mac_params
) -> rfc4211.ProofOfPossession:
    """Prepare the PKMAC value for the Proof-of-Possession structure.

    :param shared_secret: The shared secret to use for the MAC.
    :param data: The data to authenticate with the MAC.
    :param mac_alg: The MAC algorithm to use for the PKMAC value.
    :param for_agreement: The flag to indicate whether the PKMAC value is for key agreement. Defaults to `True`.
    :param mac_params: The additional parameters to use for the MAC algorithm.
    :return: The populated Proof-of-Possession structure with the `agreeMAC` field set.
    """
    pkmac_value = rfc4211.PKMACValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    alg_id, mac_value = compute_and_prepare_mac(key=shared_secret, data=data, mac_alg=mac_alg, **mac_params)
    pkmac_value["algId"]["algorithm"] = alg_id["algorithm"]
    pkmac_value["algId"]["parameters"] = alg_id["parameters"]
    pkmac_value["value"] = univ.BitString.fromOctetString(mac_value)

    if for_agreement:
        index = 3
        option = "keyAgreement"
    else:
        index = 2
        option = "keyEncipherment"

    popo_priv_key = rfc4211.POPOPrivKey().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, index)
    )
    popo_priv_key["agreeMAC"] = pkmac_value
    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option] = popo_priv_key
    return popo_structure


def prepare_agree_key_popo(
    use_encr_cert: bool = True,
    env_data: Optional[rfc9480.EnvelopedData] = None,
    client_key: Optional[ECDHPrivKeyTypes] = None,
    shared_secret: Optional[bytes] = None,
    cert_request: Optional[bytes] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    mac_alg: str = "password_based_mac",
    **mac_params,
) -> rfc4211.ProofOfPossession:
    """Prepare a Proof-of-Possession (PoP) structure for a Key Agreement (KA) key.

    This function creates a `ProofOfPossession` structure for key agreement, which may include:
    - An HMAC-based PoP using the client's private key and CA's public key.
    - An encrypted key or subsequent message depending on the `use_encr_cert` flag.

    :param use_encr_cert: A flag indicating whether to use an encrypted certificate (`True`)
                          or a challenge-based message (`False`). Defaults to `True`.
    :param env_data: Optional `EnvelopedData` object containing encrypted key material.
    :param client_key: Optional client-side private key for key agreement (ECDH).
    :param ca_cert: Optional CA certificate containing the public key for key agreement.
    :return: A populated `rfc4211.ProofOfPossession` structure for key agreement.
    """
    if client_key is not None and ca_cert is not None:
        shared_secret = _compute_ss(client_key, ca_cert=ca_cert)

    popo_priv_key = rfc4211.POPOPrivKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    if env_data is None and shared_secret:
        option = "encrCert" if use_encr_cert else "challenge"
        popo_priv_key["subsequentMessage"] = rfc4211.SubsequentMessage(option).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
    elif shared_secret is not None:
        return _prepare_pkmac_val(
            shared_secret=shared_secret, cert_request=cert_request, for_agreement=True, mac_alg=mac_alg, **mac_params
        )
    else:
        popo_priv_key["encryptedKey"] = env_data

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure["keyAgreement"] = popo_priv_key
    return popo_structure


def compute_dh_static_pop(
    ca_cert: rfc9480.CMPCertificate,
    cert_request: rfc4211.CertRequest,
    ss: Optional[bytes] = None,
    private_key: Optional[ECDHPrivateKey] = None,
    use_pkmac: bool = False,
):
    """Compute a static Diffie-Hellman Proof-of-Possession (PoP) value for certificate requests.

    :param ss: The shared secret used for generating the MAC (if not provided, it's computed).
    :param ca_cert: The CA's certificate containing the issuer's public key.
    :param cert_request: The certificate request to be authenticated with the MAC.
    :param private_key: Optionally, the private key used for Diffie-Hellman.
    :param use_pkmac: A flag indicating whether to use the PKMAC value in the PoP structure.

    :return: A populated Proof-of-Possession structure, including either a DH MAC or PKMAC value.
    :raises ValueError: If neither the shared secret nor the private key is provided.
    """
    if not ss and not private_key:
        raise ValueError("Both the shared secret and private key cannot be None")

    elif not ss:
        public_key = load_public_key_from_cert(ca_cert)
        ss = perform_ecdh(private_key=private_key, public_key=public_key)

    # as of rfc 2875
    # If either the subject or
    # issuer name in the CA certificate is empty, then the alternative name
    # should be used in its place.

    subject_dn_bytes = encoder.encode(ca_cert["tbsCertificate"]["subject"])
    issuer_dn_bytes = encoder.encode(ca_cert["tbsCertificate"]["issuer"])
    concatenated_data = subject_dn_bytes + ss + issuer_dn_bytes
    key = compute_hash(alg_name="sha1", data=concatenated_data)
    mac = compute_hmac(hash_alg="sha1", key=key, data=encoder.encode(cert_request))

    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc6955.id_dhPop_static_sha1_hmac_sha1
    # names differs, but same structure.
    dh_pop_static = rfc6955.DhSigStatic()
    dh_pop_static["hashValue"] = rfc6955.MessageDigest(mac)
    dh_pop_static["issuerAndSerial"] = prepare_issuer_and_serial_number(ca_cert)
    alg_id["algorithm"]["parameters"] = rfc6955.DhSigStatic()

    popo_priv_key = rfc4211.POPOPrivKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

    if use_pkmac:
        pk_mac_val = rfc4211.PKMACValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

        pk_mac_val["algId"] = alg_id
        pk_mac_val["value"] = univ.BitString().fromOctetString(mac)
        popo_priv_key["agreeMAC"] = pk_mac_val
    else:
        popo_priv_key["dhMAC"] = popo_priv_key["dhMAC"].fromOctetString(mac)

    return popo_priv_key


@keyword(name="Get EncCert From PKIMessage")
def get_enc_cert_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    cert_number: Strint = 0,
    ee_private_key: Optional[PrivateKey] = None,
    server_cert: Optional[rfc9480.CMPCertificate] = None,
    password: Optional[Union[str, bytes]] = None,
    expected_recip_type: Optional[str] = None,
) -> rfc9480.CMPCertificate:
    """Decrypt an encrypted certificate.

    Extract the decrypted certificate and then decrypts the certificate by processing the recipient info type.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the EncCert to be extracted.
        - `cert_number`: The index of the certified key pair in the response to extract. Defaults to `0`.
        - `ee_private_key`: The end-entity private key to decrypt the EncCert if it is encrypted.
        - `server_cert`: The server's CMPCertificate used for validating the EncCert.
        - `password`: A password for decryption if required by the enveloped data.
        - `expected_recip_type`: Expected recipient type to validate the encrypted data.

    Returns:
    -------
       - The decrypted certificate.

    Raises:
    ------
       - ValueError: If the envelopedData structure is incorrectly populated.
       - InvalidUnwrap: If the encrypted data cannot be unwrapped.

    Examples:
    --------
    | ${enc_cert}= | Get EncCert From PKIMessage | pki_message=${pki_message} | cert_number=0 | ee_private_key=${key} |
    | ${enc_cert}= | Get EncCert From PKIMessage | pki_message=${pki_message} | cert_number=0 | password=${password} |

    """
    body_name = pki_message["body"].getName()
    cert_key_pair: rfc9480.CertifiedKeyPair = asn1utils.get_asn1_value(
        pki_message, query=f"body.{body_name}.response/{cert_number}.certifiedKeyPair"
    )
    if cert_key_pair["certOrEncCert"].getName() != "envelopedData":
        raise ValueError("The enc certificate field MUST be an `envelopedData` structure")

    env_data = cert_key_pair["certOrEncCert"]["envelopedData"]

    data = validate_enveloped_data(
        env_data=env_data,
        pki_message=pki_message,
        password=password,
        ee_key=ee_private_key,
        cmp_protection_cert=server_cert,
        expected_raw_data=True,
        expected_type=expected_recip_type,
    )

    try:
        cert, rest = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())

        if rest != b"":
            raise ValueError(f"Unexpected data after decoding the encrypted certificate: {rest.hex()}")

    except pyasn1.error.PyAsn1Error:
        raise ValueError(f"The decrypted certificate was not decoded-able: {data.hex()}")  # type: ignore

    return cert
