# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionally which is only needed to test a client CMP-implementation."""

import logging
import os
from typing import List, Optional, Sequence, Tuple, Union

import pyasn1.error
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pq_logic.key_pyasn1_utils import parse_key_from_one_asym_key
from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey
from pq_logic.pq_compute_utils import verify_csr_signature, verify_signature_with_alg_id
from pq_logic.pq_utils import is_kem_public_key
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5652, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import certbuildutils, cmputils
from resources.asn1_structures import CAKeyUpdContent, ChallengeASN1
from resources.ca_kga_logic import validate_enveloped_data
from resources.certbuildutils import build_cert_from_cert_template, build_cert_from_csr
from resources.certextractutils import get_extension, get_field_from_certificate
from resources.certutils import (
    build_cmp_chain_from_pkimessage,
    cert_in_list,
    certificates_must_be_trusted,
    check_is_cert_signer,
    load_certificates_from_dir,
    validate_certificate_pkilint,
    validate_cmp_extended_key_usage,
)
from resources.cmputils import compare_general_name_and_name, prepare_general_name, prepare_pkistatusinfo
from resources.convertutils import copy_asn1_certificate, str_to_bytes
from resources.cryptoutils import compute_aes_cbc, perform_ecdh
from resources.envdatautils import build_env_data_for_exchange
from resources.exceptions import BadAsn1Data, BadPOP, BadRequest, NotAuthorized
from resources.extra_issuing_logic import is_null_dn
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import compute_hash, get_hash_from_oid, sha_alg_name_to_oid
from resources.prepareutils import prepare_name
from resources.protectionutils import (
    compute_mac_from_alg_id,
    prepare_kem_ciphertextinfo,
    prepare_sha_alg_id,
)
from resources.typingutils import PrivateKey, PublicKey
from resources.utils import manipulate_first_byte


def _prepare_issuer_and_ser_num_for_challenge(cert_req_id: int) -> rfc5652.IssuerAndSerialNumber:
    """Prepare the issuer and serial number for the challenge.

    :param cert_req_id: The certificate request ID.
    :return: The populated `IssuerAndSerialNumber` structure.
    """
    issuer_and_ser_num = rfc5652.IssuerAndSerialNumber()
    issuer_and_ser_num["issuer"] = prepare_name("Null-DN")
    issuer_and_ser_num["serialNumber"] = univ.Integer(cert_req_id)
    return issuer_and_ser_num


def _prepare_rand(sender: Optional[Union[rfc9480.GeneralName, str]], rand_int: Optional[int] = None) -> rfc9480.Rand:
    """Prepare the `Rand` structure for the challenge.

    :param sender: The sender of the message.
    :param rand_int: The random number to use. Defaults to `None`.
    :return: The populated `Rand` structure.
    """
    rand_obj = rfc9480.Rand()
    if rand_int is None:
        rand_int = int.from_bytes(os.urandom(4), "big")

    if isinstance(sender, str):
        sender = prepare_general_name("directoryName", sender)
    rand_obj["sender"] = sender
    rand_obj["int"] = rand_int
    return rand_obj


def _prepare_witness_val(
    challenge_obj: ChallengeASN1, hash_alg: Optional[str], rand: rfc9480.Rand, bad_witness: bool
) -> ChallengeASN1:
    """Get the witness value for the challenge.

    :return: The updated challenge object.
    """
    witness = b""
    if hash_alg:
        challenge_obj["owf"] = prepare_sha_alg_id(hash_alg or "sha256")
        num_bytes = (int(rand["int"])).to_bytes(4, "big")
        witness = compute_hash(hash_alg, num_bytes)
        logging.info("valid witness value: %s", witness.hex())

    if bad_witness:
        if not hash_alg:
            witness = os.urandom(32)
        else:
            witness = manipulate_first_byte(witness)

    challenge_obj["witness"] = univ.OctetString(witness)
    return challenge_obj


@not_keyword
def prepare_challenge(
    public_key: PublicKey,
    ca_key: Optional[PrivateKey] = None,
    bad_witness: bool = False,
    hash_alg: Optional[str] = None,
    sender: str = "CN=CMP-Test-Suite CA",
    rand_int: Optional[int] = None,
    iv: Union[str, bytes] = b"AAAAAAAAAAAAAAAA",
) -> Tuple[ChallengeASN1, Optional[bytes], Optional[rfc9480.InfoTypeAndValue]]:
    """Prepare a challenge for the PKIMessage.

    :param public_key: The public key of the end-entity (EE).
    :param ca_key: The private key of the CA/RA.
    :param bad_witness: Whether to manipulate the witness value. Defaults to `False`.
    :param hash_alg: The hash algorithm to use. Defaults to `None`.
    :param sender: The sender inside the Rand structure. Defaults to "CN=CMP-Test-Suite CA".
    :param rand_int: The random number to use. Defaults to `None`.
    :param iv: The initialization vector to use, for AES-CBC. Defaults to `b"AAAAAAAAAAAAAAAA"`.
    :return: The populated `Challenge` structure, the shared secret, and the info value (for KEMs/HybridKEMs).
    """
    challenge_obj = ChallengeASN1()
    info_val: Optional[rfc9480.InfoTypeAndValue] = None

    rand = _prepare_rand(sender=sender, rand_int=rand_int)
    data = encoder.encode(rand)
    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand, hash_alg=hash_alg, bad_witness=bad_witness
    )

    if isinstance(public_key, RSAPublicKey):
        enc_data = public_key.encrypt(data, padding=padding.PKCS1v15())
        challenge_obj["challenge"] = univ.OctetString(enc_data)
        return challenge_obj, None, None

    if isinstance(public_key, ECDHPublicKey):
        shared_secret = perform_ecdh(ca_key, public_key)
    elif isinstance(public_key, PQKEMPublicKey):
        shared_secret, ct = public_key.encaps()
        info_val = prepare_kem_ciphertextinfo(key=public_key, ct=ct)
    elif is_kem_public_key(public_key):
        shared_secret, ct = public_key.encaps(ca_key)
        info_val = prepare_kem_ciphertextinfo(key=public_key, ct=ct)
    else:
        raise ValueError(f"Invalid public key type, to prepare a challenge: {type(public_key).__name__}")

    enc_data = compute_aes_cbc(key=shared_secret, data=data, iv=str_to_bytes(iv), decrypt=False)

    challenge_obj["challenge"] = univ.OctetString(enc_data)
    return challenge_obj, shared_secret, info_val


def prepare_challenge_enc_rand(
    public_key: PublicKey,
    sender: Optional[Union[rfc9480.GeneralName, str]],
    rand_int: Optional[int] = None,
    hash_alg: Optional[str] = None,
    bad_witness: bool = False,
    cert_req_id: int = 0,
    private_key: Optional[PrivateKey] = None,
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None,
) -> ChallengeASN1:
    """Prepare a `Challenge` structure with an encrypted random number.

    :param public_key: The public key of the end-entity (EE), used to create the `EnvelopedData`
    structure.
    :param sender: The sender of the message. Either a `GeneralName` or a string.
    :param rand_int: The random number to be encrypted. Defaults to `None`.
    :param private_key: The private key of the server (CA/RA). Defaults to `None`.
    :param hash_alg: The hash algorithm to use to hash the challenge (e.g., "sha256"). Defaults to `None`.
    :param bad_witness: The hash of the challenge. Defaults to an empty byte string.
    :param cert_req_id: The certificate request ID. Defaults to `0`.
    :param hybrid_kem_key: The hybrid KEM key to use. Defaults to `None`.
    :return: The populated `Challenge` structure.
    """
    challenge_obj = ChallengeASN1()

    rand_obj = _prepare_rand(sender, rand_int)

    env_data = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    issuer_and_ser = _prepare_issuer_and_ser_num_for_challenge(cert_req_id)
    env_data = build_env_data_for_exchange(
        public_key_recip=public_key,
        data=encoder.encode(rand_obj),
        private_key=private_key,
        target=env_data,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=hybrid_kem_key,
    )

    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand_obj, hash_alg=hash_alg, bad_witness=bad_witness
    )

    challenge_obj["encryptedRand"] = env_data
    challenge_obj["challenge"] = univ.OctetString(b"")
    return challenge_obj


def prepare_oob_cert_hash(ca_cert: rfc9480.CMPCertificate, hash_alg: str = "sha256") -> rfc9480.OOBCertHash:
    """Prepare an `OOBCertHash` from a CA certificate.

    :param ca_cert: The OOB CA certificate.
    :param hash_alg: The hash algorithm to use (e.g., "sha256").
    :return: The populated `OOBCertHash` structure.
    """
    sig = compute_hash(hash_alg, encoder.encode(ca_cert))

    oob_cert_hash = rfc9480.OOBCertHash()
    oob_cert_hash["hashAlg"]["algorithm"] = sha_alg_name_to_oid(hash_alg)
    oob_cert_hash["certId"] = rfc9480.CertId()
    oob_cert_hash["certId"]["issuer"] = ca_cert["tbsCertificate"]["issuer"]
    oob_cert_hash["certId"]["serialNumber"] = ca_cert["tbsCertificate"]["serialNumber"]
    oob_cert_hash["hashVal"] = univ.BitString.fromOctetString(sig)

    return oob_cert_hash


def validate_oob_cert(ca_cert: rfc9480.OOBCert, oob_cert_hash: rfc9480.OOBCertHash) -> None:
    """Validate an `OOBCertHash` against a CA certificate.

    :param ca_cert: The OOB CA certificate.
    :param oob_cert_hash: The OOB cert hash to validate.
    :return: None.
    """
    hash_name = get_hash_from_oid(oob_cert_hash["hashAlg"]["algorithm"])
    sig = compute_hash(hash_name, encoder.encode(oob_cert_hash))

    if sig != oob_cert_hash["hashVal"].asOctets():
        raise ValueError("Invalid OOB cert hash")

    if ca_cert["tbsCertificate"]["issuer"] != oob_cert_hash["certId"]["issuer"]:
        raise ValueError("Invalid OOB cert issuer")

    if ca_cert["tbsCertificate"]["serialNumber"] != oob_cert_hash["certId"]["serialNumber"]:
        raise ValueError("Invalid OOB cert serial number")

    # Validate as of rfc4210bis-15 Section 5.2.5. Out-of-band root CA Public Key:
    #
    # 1. MUST be self-signed
    # 2. MUST have the same issuer and subject.
    if not check_is_cert_signer(ca_cert, ca_cert):
        raise ValueError("CA cert is not self-signed")

    # 3. If the subject field contains a "NULL-DN", then both subjectAltNames and issuerAltNames
    # extensions MUST be present and have exactly the same value

    if is_null_dn(ca_cert["tbsCertificate"]["subject"]):
        logging.info("Subject is NULL-DN")
        extn_san = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectAltName)
        extn_ian = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_issuerAltName)

        logging.info("SubjectAltName: %s", extn_san.prettyPrint())
        logging.info("IssuerAltName: %s", extn_ian.prettyPrint())

        if extn_ian is None:
            raise ValueError("IssuerAltName missing")
        if extn_san is None:
            raise ValueError("SubjectAltName missing")

        if extn_san["critical"] != extn_ian["critical"]:
            raise ValueError("SubjectAltName and IssuerAltName must have same criticality.")

        if extn_san["extnValue"].asOctets() != extn_ian["extnValue"].asOctets():
            raise ValueError("SubjectAltName and IssuerAltName must have same value")

    # Validate other self-signed features.
    # 4. The values of all other extensions must be suitable for a self-signed certificate
    # (e.g., key identifiers for subject and issuer must be the same).
    validate_certificate_pkilint(ca_cert)


def _prepare_cert_with_cert(
    cert: rfc9480.CMPCertificate,
    signing_key,
    use_rsa_pss: bool = True,
    hash_alg: str = "sha256",
    issuer: Optional[rfc9480.Name] = None,
) -> rfc9480.CMPCertificate:
    """Prepare a `CMPCertificate` with a `CMPCertificate`

    :param cert: The `CMPCertificate` to create the new one from and sign.
    :param signing_key: The key to sign the certificate with.
    :param use_rsa_pss: Whether to use RSA-PSS or not. Defaults to True.
    :param hash_alg: The hash algorithm to use (e.g. "sha256").
    :param issuer: The certificate issuer to sign the certificate with.
    :return:
    """
    cert_with_cert = rfc9480.CMPCertificate()
    cert = copy_asn1_certificate(cert, cert_with_cert)

    if issuer is not None:
        cert["tbsCertificate"]["issuer"] = issuer

    sig_alg = certbuildutils.prepare_sig_alg_id(signing_key=signing_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)

    cert["tbsCertificate"]["signature"] = sig_alg
    cert_with_cert["tbsCertificate"] = cert["tbsCertificate"]

    cert_with_cert["signature"] = certbuildutils.sign_cert(
        signing_key, cert=cert, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
    )
    return cert_with_cert


# New structure as of RFC4210bis-15.


def build_ckuann(
    new_cert: rfc9480.CMPCertificate,
    old_cert: rfc9480.CMPCertificate,
    new_key,
    old_key,
    use_new: bool = False,
    use_root_ca_key_update: bool = False,
    sender: str = "",
    recipient: str = "",
    pvno: int = 3,
    **kwargs,
):
    """Build a `CAKeyUpdAnnContent` PKIMessage.

    :param new_cert: The new CA certificate to be installed as trust anchor.
    :param old_cert: The old CA certificate, which was the trust anchor.
    :param new_key: The private key corresponding to the new CA certificate.
    :param old_key: The private key corresponding to the old CA certificate.
    :param use_new: Whether to use the new structure or the old one.
    :param use_root_ca_key_update: Whether to use the root CA key update or not.
    :param sender: The sender of the message.
    :param recipient: The recipient of the message.
    :param pvno: The version of the message.
    :return: The populated `PKIMessage` structure.
    """
    body = rfc9480.PKIBody()

    # if ckuann, the pvno cmp2021 (3) MUST be used.
    # for RootCaKeyUpdateContent else pvno 2
    body_content = rfc9480.CAKeyUpdAnnContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15)
    )

    body["ckuann"] = body_content

    if not check_is_cert_signer(new_cert, new_cert):
        new_with_new = _prepare_cert_with_cert(new_cert, signing_key=new_key)
    else:
        new_with_new = new_cert

    old_with_new = _prepare_cert_with_cert(old_cert, signing_key=new_key, issuer=new_cert["tbsCertificate"]["issuer"])
    new_with_old = _prepare_cert_with_cert(new_cert, issuer=old_cert["tbsCertificate"]["issuer"], signing_key=old_key)

    if not use_new:
        body_content["newWithNew"] = new_with_new
        body_content["oldWithNew"] = old_with_new
        body_content["newWithOld"] = new_with_old

    else:
        body_content = CAKeyUpdContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15))

        body_name = "cAKeyUpdAnnV3" if use_root_ca_key_update else "cAKeyUpdAnnV2"

        body_content[body_name]["newWithNew"] = new_with_new
        body_content[body_name]["oldWithNew"] = old_with_new
        body_content[body_name]["newWithOld"] = new_with_old

    pki_message = cmputils._prepare_pki_message(pvno=pvno, sender=sender, recipient=recipient, **kwargs)
    pki_message["body"] = body
    return pki_message

@keyword("Get CertReqMsg From PKIMessage")
def get_cert_req_msg_from_pkimessage(pki_message: rfc9480.PKIMessage, index: int = 0) -> rfc4211.CertReqMsg:
    """Extract the certificate request from a PKIMessage.

    Arguments:
    ----------
        - `pki_message`: The PKIMessage to extract the certificate request from.
        - `index`: The index of the certificate request to extract. Defaults to `0`.

    Returns:
    --------
        - The certificate request message.

    Raises:
    -------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - IndexError: If the index is out of range.

    """
    body_name = pki_message["body"].getName()
    if body_name in {"ir", "cr", "kur", "crr"}:
        return pki_message["body"][body_name][index]

    raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr")


def validate_cert_request_cert_id(pki_message: rfc9480.PKIMessage, cert_req_id: Union[str, int] = 0) -> None:
    """Validate the certificate request certificate ID.

    Used for LwCMP to ensure the certReqId in the PKIMessage matches
    either one or minus one for p10cr.

    Arguments:
    ----------
        - `pki_message`: The PKIMessage to validate.
        - `cert_req_id`: The index of the certificate request to validate. Defaults to `0`.

    """
    cert_req_id = int(cert_req_id)
    cert_req = get_cert_req_msg_from_pkimessage(pki_message)
    body_name = pki_message["body"].getName()
    cert_id = cert_req["certReqId"]
    if body_name in {"ir", "cr", "kur", "crr"}:
        if cert_id != pki_message["body"][body_name][cert_req_id]["certReqId"]:
            raise ValueError("Invalid certReqId in PKIMessage.")
    elif body_name == "p10cr":
        if -1 != pki_message["body"]["p10cr"]["certReqId"]:
            raise ValueError("Invalid certReqId in PKIMessage,`p10cr` expects -1.")
    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


@not_keyword
def get_public_key_from_cert_req_msg(cert_req_msg: rfc4211.CertReqMsg) -> PublicKey:
    """Extract the public key from a certificate request message.

    :param cert_req_msg: The certificate request message.
    :return: The extracted public key.
    """
    spki = cert_req_msg["certReq"]["certTemplate"]["publicKey"]

    old_spki = rfc5280.SubjectPublicKeyInfo()
    old_spki["algorithm"] = spki["algorithm"]
    old_spki["subjectPublicKey"] = spki["subjectPublicKey"]

    return load_public_key_from_spki(old_spki)


def _verify_pop_signature(
    pki_message: rfc9480.PKIMessage,
) -> None:
    """Verify the POP signature in the PKIMessage.

    :param pki_message: The PKIMessage to verify the POP signature for.
    :return: `None`.
    """
    body_name = pki_message["body"].getName()

    try:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise ValueError("POP signature is missing in the PKIMessage.")

        popo_sig = popo["signature"]
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        verify_signature_with_alg_id(
            public_key=public_key,
            alg_id=popo_sig["algorithmIdentifier"],
            data=encoder.encode(cert_req_msg["certReq"]),
            signature=popo_sig["signature"].asOctets(),
        )

        if cert_req_msg["regInfo"].isValue:
            logging.debug("regInfo is present in the CertReqMsg,but server logic is not supported yet.")

    except pyasn1.error.PyAsn1Error as err:
        raise BadAsn1Data("Failed to encode the CertRequest.", overwrite=True) from err

    except InvalidSignature as err:
        raise BadPOP(f"POP verification for `{body_name}` failed.") from err


def prepare_enc_key(env_data: rfc5652.EnvelopedData, explicit_tag: int = 0) -> rfc9480.EncryptedKey:
    """Prepare an EncryptedKey structure by encapsulating the provided EnvelopedData.

    :param env_data: The EnvelopedData to wrap in the `EncryptedKey` structure.
    :param explicit_tag: The explicitTag id set for the `EncryptedKey` structure
    :return: An `EncryptedKey` object with encapsulated EnvelopedData.
    """
    enc_key = rfc9480.EncryptedKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, explicit_tag)
    )

    enc_key["envelopedData"] = env_data
    return enc_key


def prepare_cert_or_enc_cert(
    cert: rfc9480.CMPCertificate, enc_cert: Optional[rfc5652.EnvelopedData] = None
) -> rfc9480.CertOrEncCert:
    """Prepare a CertOrEncCert structure containing either a certificate or encrypted certificate.

    :param cert: A certificate object representing the certificate to include.
    :param enc_cert: An optional EnvelopedData object representing an encrypted certificate.
    :return: A populated CertOrEncCert structure.
    """
    cert_or_enc_cert = rfc9480.CertOrEncCert()
    if cert is not None:
        cert2 = rfc9480.CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        cert_or_enc_cert["certificate"] = copy_asn1_certificate(cert, cert2)

    if enc_cert is not None:
        enc_key = prepare_enc_key(env_data=enc_cert, explicit_tag=1)
        cert_or_enc_cert["encryptedCert"] = enc_key

    return cert_or_enc_cert


def prepare_certified_key_pair(
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
) -> rfc9480.CertifiedKeyPair:
    """Prepare a CertifiedKeyPair structure containing certificate or encrypted certificate and an optional private key.

    :param cert: An optional certificate representing the certificate.
    :param enc_cert: An optional EnvelopedData object for the encrypted certificate.
    :param private_key: An optional EnvelopedData object representing the private key.
    :raises ValueError: If both cert and enc_cert are not provided.
    :return: A populated CertifiedKeyPair structure.
    """
    if not cert and not enc_cert:
        raise ValueError("At least one of `cert` or `enc_cert` must be provided to prepare a CertifiedKeyPair.")

    certified_key_pair = rfc9480.CertifiedKeyPair()
    certified_key_pair["certOrEncCert"] = prepare_cert_or_enc_cert(cert=cert, enc_cert=enc_cert)

    if private_key is not None:
        enc_key = rfc9480.EncryptedKey().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        enc_key["envelopedData"] = private_key
        certified_key_pair["privateKey"] = enc_key

    return certified_key_pair


@keyword(name="Prepare CertResponse")
def prepare_cert_response(
    cert_req_id: Union[str, int] = 0,
    status: str = "accepted",
    text: str = None,
    failinfo: str = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[PrivateKey] = None,
    rspInfo: Optional[bytes] = None,
) -> rfc9480.CertResponse:
    """Prepare a CertResponse structure for responding to a certificate request.

    :param cert_req_id: The ID of the certificate request being responded to.
    :param status: The status of the certificate request (e.g., "accepted" or "rejected").
    :param text: Optional status text.
    :param failinfo: Optional failure information.
    :param cert: An optional certificate object.
    :param enc_cert: Optional encrypted certificate as EnvelopedData.
    :param private_key: Optional private key as EnvelopedData.
    :return: A populated CertResponse structure.
    """
    cert_response = rfc9480.CertResponse()
    cert_response["certReqId"] = univ.Integer(int(cert_req_id))
    cert_response["status"] = prepare_pkistatusinfo(texts=text, status=status, failinfo=failinfo)

    if cert or enc_cert or private_key:
        cert_response["certifiedKeyPair"] = prepare_certified_key_pair(cert, enc_cert, private_key)

    if rspInfo:
        cert_response["rspInfo"] = univ.OctetString(rspInfo)

    return cert_response


def _verify_encrypted_key_popo(
    popo_priv_key: rfc4211.POPOPrivKey,
    client_public_key: PublicKey,
    ca_key: Optional[PrivateKey] = None,
    password: Optional[str] = None,
    client_cert: Optional[rfc9480.CMPCertificate] = None,
    protection_salt: Optional[bytes] = None,
    expected_name: Optional[str] = None,
):
    data = validate_enveloped_data(
        env_data=popo_priv_key["encryptedKey"],
        password=password,
        ee_key=ca_key,
        for_pop=False,
        cmp_protection_cert=client_cert,
        protection_salt=protection_salt,
    )
    enc_key, rest = decoder.decode(data, rfc4211.EncKeyWithID())

    if rest:
        raise BadAsn1Data("EncKeyWithID")

    if not enc_key["identifier"].isValue:
        raise ValueError("EncKeyWithID identifier is missing.")

    if expected_name is not None:
        if enc_key["identifier"]["string"].isValue:
            idf_name = str(enc_key["identifier"]["string"])
            if idf_name != expected_name:
                raise ValueError(f"EncKeyWithID identifier name mismatch. Expected: {expected_name}. Got: {idf_name}")
        else:
            result = compare_general_name_and_name(enc_key["identifier"]["generalName"], prepare_name(expected_name))
            if not result:
                logging.debug(enc_key["identifier"].prettyPrint())
                raise ValueError("EncKeyWithID identifier name mismatch.")

    data = encoder.encode(enc_key["privateKeyInfo"])

    private_key = parse_key_from_one_asym_key(data)

    if private_key.public_key() != client_public_key:
        raise ValueError("The decrypted key does not match the public key in the certificate request.")


def process_popo_priv_key(
@keyword(name="Build pkiconf from CertConf")
def build_pki_conf_from_cert_conf(
    request: rfc9480.PKIMessage,
    issued_certs: List[rfc9480.CMPCertificate],
    exclude_fields: Optional[str] = None,
    enforce_lwcmp: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> rfc9480.PKIMessage:
    """Build a PKIConf message from a CertConf message.

    Arguments:
    ----------
       - `request`: The CertConf message to build the PKIConf message from.
       - `issued_certs`: The certificates that were issued.
       - `exclude_fields`: The fields to exclude from the PKIConf message. Defaults to `None`.
       - `enforce_lwcmp`: Whether to enforce LwCMP rules. Defaults to `True`.
       - `set_header_fields`: Whether to set the header fields. Defaults to `True`.

    Returns:
    --------
         - The built PKI Confirmation message.

    Raises:
    -------
        - `ValueError`: If the request is not a CertConf message.
        - `ValueError`: If the number of CertConf entries does not match the number of issued certificates.
        - `BadRequest`: If the number of CertStatus's is not one (for LwCMP).
        - `BadRequest`: If the CertReqId is not zero (for LwCMP).
        - `BadRequest`: If the certificate status is not `accepted` or `rejection`.
        - `BadPOP`: If the certificate hash is invalid in the CertConf message.

    """
    if request["body"].getName() != "certConf":
        raise ValueError("Request must be a `certConf` to build a `PKIConf` message from it.")

    cert_conf: rfc9480.CertConfirmContent = request["body"]["certConf"]

    if len(cert_conf) != 1 and enforce_lwcmp:
        raise BadRequest(f"Invalid number of entries in CertConf message.Expected 1 for LwCMP, got {len(cert_conf)}")

    if len(cert_conf) != len(issued_certs):
        raise ValueError("Number of CertConf entries does not match the number of issued certificates.")

    entry: rfc9480.CertStatus
    for entry, issued_cert in zip(cert_conf, issued_certs):
        if entry["certReqId"] != 0 and enforce_lwcmp:
            raise BadRequest("Invalid CertReqId in CertConf message.")

        if entry["statusInfo"].isValue:
            if str(entry["status"]) == "rejection":
                logging.debug("Certificate status was rejection.")
                continue

            elif str(entry["status"]) != "accepted":
                raise BadRequest(
                    "Invalid certificate status in CertConf message."
                    f"Expected 'accepted' or 'rejection', got {entry['status'].getName()}"
                )

        if entry["hashAlg"]["algorithm"].isValue:
            if int(request["header"]["pvno"]) != 3:
                raise BadRequest("Hash algorithm is missing in CertConf message,but the version is not 3.")
            hash_alg = get_hash_from_oid(entry["hashAlg"]["algorithm"], only_hash=False)
        else:
            alg_oid = issued_cert["tbsCertificate"]["signature"]["algorithm"]
            hash_alg = get_hash_from_oid(alg_oid, only_hash=True)

        computed_hash = compute_hash(
            alg_name=hash_alg,
            data=encoder.encode(issued_cert),
        )

        if entry["certHash"].asOctets() != computed_hash:
            raise BadPOP("Invalid certificate hash in CertConf message.")

    if request and set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    pki_message = cmputils._prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"]["pkiconf"] = rfc9480.PKIConfirmContent("").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 19)
    )

    return pki_message


@not_keyword
def get_correct_ca_body_name(request: rfc9480.PKIMessage) -> str:
    """Get the correct body name for the response.

    :param request: The PKIMessage with the request.
    :return: The correct body name for the response.
    :raises ValueError: If the body name is invalid (allowed are `ir`, `cr`, `kur`, `ccr`).
    """
    body_name = request["body"].getName()
    if body_name == "ir":
        return "ip"

    if body_name in ["cr", "p10cr"]:
        return "cp"

    if body_name == "kur":
        return "kup"

    if body_name == "ccr":
        return "ccp"

    raise ValueError(f"Invalid body name: {body_name}")
