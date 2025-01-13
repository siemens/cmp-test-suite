# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionally which is only needed to test a client CMP-implementation."""

import logging
import os
from typing import Optional, Union

from pq_logic.migration_types import HybridKEMPrivateKey
from pyasn1.codec.der import encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc9480

from resources import certbuildutils, cmputils
from resources.asn1_structures import CAKeyUpdContent, ChallengeASN1
from resources.prepareutils import prepare_name
from resources.certextractutils import get_extension
from resources.certutils import check_is_cert_signer, validate_certificate_pkilint
from resources.cmputils import prepare_general_name
from resources.convertutils import copy_asn1_certificate
from resources.envdatautils import build_env_data_for_exchange
from resources.extra_issuing_logic import is_null_dn
from resources.oid_mapping import compute_hash, get_hash_from_oid, sha_alg_name_to_oid
from resources.protectionutils import prepare_sha_alg_id
from resources.typingutils import PrivateKey, PublicKey


def _prepare_issuer_and_ser_num_for_challenge(cert_req_id: int) -> rfc5652.IssuerAndSerialNumber:
    """Prepare the issuer and serial number for the challenge.

    :param cert_req_id: The certificate request ID.
    :return: The populated `IssuerAndSerialNumber` structure.
    """
    issuer_and_ser_num = rfc5652.IssuerAndSerialNumber()
    issuer_and_ser_num["issuer"] = prepare_name("Null-DN")
    issuer_and_ser_num["serialNumber"] = univ.Integer(cert_req_id)
    return issuer_and_ser_num


def prepare_challenge_enc_rand(
    public_key: PublicKey,
    sender: Optional[Union[rfc9480.GeneralName, str]],
    rand: Optional[int] = None,
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
    :param rand: The random number to be encrypted. Defaults to `None`.
    :param private_key: The private key of the server (CA/RA). Defaults to `None`.
    :param hash_alg: The hash algorithm to use to hash the challenge (e.g., "sha256"). Defaults to `None`.
    :param bad_witness: The hash of the challenge. Defaults to an empty byte string.
    :param cert_req_id: The certificate request ID. Defaults to `0`.
    :param hybrid_kem_key: The hybrid KEM key to use. Defaults to `None`.
    :return: The populated `Challenge` structure.
    """
    challenge_obj = ChallengeASN1()

    rand_obj = rfc9480.Rand()
    if rand is None:
        rand = int.from_bytes(os.urandom(4), "big")

    if isinstance(sender, str):
        sender = prepare_general_name("directoryName", sender)
    rand_obj["sender"] = sender
    rand_obj["int"] = rand

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

    witness = b""

    if bad_witness:
        challenge_obj["owf"] = prepare_sha_alg_id(hash_alg or "sha256")
        witness = os.urandom(32)

    challenge_obj["encryptedRand"] = env_data
    challenge_obj["challenge"] = univ.OctetString(b"")
    challenge_obj["witness"] = univ.OctetString(witness)
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
