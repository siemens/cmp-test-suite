# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


"""Contains logic to perform all kinds of verification tasks.

Either has functionality to verify signatures of PKIMessages or certificates.


"""

import logging
from typing import List, Optional, Sequence, Tuple

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import constraint, tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480, rfc9481, rfc5480
from resources import keyutils
from resources.certutils import load_public_key_from_cert
from resources.exceptions import BadMessageCheck, UnknownOID
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, MSG_SIG_ALG, PQ_OID_2_NAME, TRAD_STR_OID_TO_KEY_NAME
from resources.typingutils import PublicKeySig

from pq_logic import pq_compute_utils
from pq_logic.hybrid_sig import sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig.catalyst_logic import (
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
)
from pq_logic.keys.abstract_composite import AbstractCompositeSigPublicKey
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.migration_typing import CertOrCerts
from pq_logic.pq_key_factory import PQKeyFactory

# TODO fix to include CRL-Verification
# currently only works for PQ and traditional signatures.
# But in the next update will be Completely support CRL-Verification.


# TODO fix parse catalyst directly.


def verify_cert_hybrid_signature(
    ee_cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    other_cert: rfc9480.CMPCertificate,
    catalyst_key: PQSignaturePrivateKey = None,
) -> None:
    """Verify the hybrid signature of an end-entity (EE) certificate using the appropriate composite methode.

    :param ee_cert: The end-entity certificate (`CMPCertificate`) to be verified. This certificate
                    contains the hybrid signature and its algorithm identifier.
    :param issuer_cert: The issuer certificate providing the traditional public key or composite signature key.
    :param other_cert: The secondary certificate containing the
                       post-quantum public key (e.g., ML-DSA or another PQ signature algorithm)
                       used in the composite signature. (as an example, use-case for cert discovery)
    :param catalyst_key: Optional. A post-quantum private key (`PQSignaturePrivateKey`) used for creating
                         a composite key dynamically when `other_cert` is not provided.

    :raises ValueError:
        - If the OID in the `ee_cert` is unsupported or invalid.
        - If neither `other_cert` nor `catalyst_key` is provided when required.
    :raises NotImplementedError: If the signature algorithm OID is not supported for verification.
    :raises InvalidSignature: If the signature verification fails.
    """
    oid = ee_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
    alg_id = ee_cert["tbsCertificate"]["signature"]
    spki = other_cert["tbsCertificate"]["subjectPublicKeyInfo"]
    if oid in CMS_COMPOSITE_OID_2_NAME:
        if other_cert is None and catalyst_key is None:
            composite_key = PQKeyFactory.load_public_key_from_spki(spki)
            if not isinstance(composite_key, CompositeSigCMSPublicKey):
                raise ValueError()
        elif other_cert is not None:
            trad_key = keyutils.load_public_key_from_spki(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            pq_key = PQKeyFactory.load_public_key_from_spki(other_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            composite_key = CompositeSigCMSPublicKey(pq_key, trad_key=trad_key)

        else:
            trad_key = keyutils.load_public_key_from_spki(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            composite_key = CompositeSigCMSPublicKey(catalyst_key, trad_key=trad_key)

        data = encoder.encode(ee_cert["tbsCertificate"])
        signature = ee_cert["signature"].asOctets()
        CompositeSigCMSPrivateKey.validate_oid(oid, composite_key)
        pq_compute_utils.verify_signature_with_alg_id(composite_key, alg_id=alg_id, signature=signature, data=data)

    else:
        raise NotImplementedError(f"Unsupported algorithm OID: {oid}. Verification not implemented.")


def _verify_signature_with_other_cert(
    cert: rfc9480.CMPCertificate,
    sig_alg: rfc9480.AlgorithmIdentifier,
    data: bytes,
    signature: bytes,
    other_certs: Optional[CertOrCerts] = None,
) -> None:
    """Verify a Composite Signature Certificate using two certificates.

    :param cert: The certificate to verify.
    :param sig_alg: The signature algorithm identifier.
    :param data: The data to verify.
    :param signature: The signature to verify.
    :param other_certs: A single certificate or a sequence of certificates to extract
    the related certificate.
    :raises ValueError: If the related certificate is not provided.
    :raises UnknownOID: If the signature algorithm OID is not supported.
    :raises InvalidSignature: If the signature verification fails.
    """
    sig_alg_oid = sig_alg["algorithm"]

    if sig_alg_oid not in CMS_COMPOSITE_OID_2_NAME:
        raise ValueError("The signature algorithm is not a composite signature one.")

    if other_certs is not None:
        other_certs = other_certs if not isinstance(other_certs, rfc9480.CMPCertificate) else [other_certs]

    pq_key = pq_compute_utils.may_extract_alt_key_from_cert(cert=cert, other_certs=other_certs)
    if pq_key is None:
        raise ValueError("No alternative issuer key found.")

    trad_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not isinstance(pq_key, PQSignaturePublicKey):
        trad_key, pq_key = pq_key, trad_key

    if sig_alg_oid in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey(pq_key=pq_key, trad_key=trad_key)
        CompositeSigCMSPublicKey.validate_oid(sig_alg_oid, public_key)

    else:
        raise UnknownOID(sig_alg_oid, extra_info="Composite signature can not be verified, with 2-certs.")

    pq_compute_utils.verify_signature_with_alg_id(public_key, sig_alg, data, signature)


def verify_composite_signature_with_hybrid_cert(
    data: bytes,
    signature: bytes,
    sig_alg: rfc9480.AlgorithmIdentifier,
    cert: rfc9480.CMPCertificate,
    other_certs: Optional[CertOrCerts] = None,
) -> None:
    """Verify a signature using a hybrid certificate.

    Expected to either get a composite signature certificate or a certificate with a related certificate extension.
    or a certificate with a cert discovery extension. So that the second certificate can be extracted.

    :param data: The data to verify.
    :param signature: The signature to verify against the data.
    :param sig_alg: The signature algorithm identifier.
    :param cert: The certificate may contain a composite signature key or a single key.
    :param other_certs: A single certificate or a sequence of certificates to extract
    the related certificate from.
    :raises ValueError: If the alternative key cannot be obtained.
    :raises UnknownOID: If the signature algorithm OID is not supported.
    :raises InvalidSignature: If the signature verification fails.
    :raises ValueError: If the `cert` contains a PQ signature algorithm.
    It Should be a traditional algorithm for migration strategy.
    """
    if sig_alg["algorithm"] not in CMS_COMPOSITE_OID_2_NAME:
        raise ValueError("The signature algorithm is not a composite signature.")

    cert_sig_alg = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]

    if cert_sig_alg in MSG_SIG_ALG or str(cert_sig_alg) in TRAD_STR_OID_TO_KEY_NAME:
        logging.info("The certificate contains a traditional signature algorithm.")
        _verify_signature_with_other_cert(cert, sig_alg, data, signature, other_certs=other_certs)
        return

    elif cert_sig_alg in PQ_OID_2_NAME:
        raise ValueError(
            "The certificate contains a post-quantum signature algorithm."
            "please use traditional signature algorithm"
            "because the migration should test use case of "
            "having the certificate with traditional signature algorithm."
        )

    elif cert_sig_alg in CMS_COMPOSITE_OID_2_NAME:
        logging.info("The certificate contains a composite signature algorithm.")
        public_key = CompositeSigCMSPublicKey.from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
        CompositeSigCMSPublicKey.validate_oid(cert_sig_alg, public_key)
        pq_compute_utils.verify_signature_with_alg_id(public_key, sig_alg, data, signature)

    else:
        raise UnknownOID(sig_alg["algorithm"], extra_info="Composite signature can not be verified.")


def verify_sun_hybrid_cert(
    cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    alt_issuer_key: Optional[PublicKeySig] = None,
    check_alt_sig: bool = True,
    other_certs: Optional[List[rfc9480.CMPCertificate]] = None,
):
    """Verify a Sun hybrid certificate.

    Validates the primary and alternative signatures in a certificate.
    The main signature is verified using the issuer's tradition key inside the certificate public key.
    And the alternative signature is verified using the issuer's alternative key.

    :param cert: The SUN hybrid certificate to verify.
    :param issuer_cert: The issuer's certificate for verifying the main signature.
    :param check_alt_sig: Whether to validate the alternative signature (default: True).
    :param alt_issuer_key: The issuer's public key for verifying the alternative signature.
    Otherwise, will need to get the public key from the issuer's certificate.
    :param other_certs: A list of other certificates to search for the related certificate.
    :raises ValueError: If validation fails for the certificate or its extensions.
    :raises ValueError: If the alternative issuer key is not found.
    :raises BadAsn1Data: If the AlternativePublicKeyInfo extension contains remainder data.
    """
    if alt_issuer_key is None:
        alt_issuer_key = pq_compute_utils.may_extract_alt_key_from_cert(issuer_cert, other_certs=other_certs)
        if alt_issuer_key is None:
            raise ValueError("No alternative issuer key found.")

    alt_pub_key = sun_lamps_hybrid_scheme_00.validate_alt_pub_key_extn(cert)
    if check_alt_sig:
        sun_lamps_hybrid_scheme_00.validate_alt_sig_extn(cert, alt_pub_key, alt_issuer_key)

    public_key = load_public_key_from_cert(issuer_cert)
    data = encoder.encode(cert["tbsCertificate"])
    alg_id = cert["tbsCertificate"]["signature"]
    signature = cert["signature"].asOctets()
    pq_compute_utils.verify_signature_with_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)


def _get_catalyst_info_vals(
    general_info: Sequence[rfc9480.InfoTypeAndValue],
) -> Tuple[
    rfc9480.AlgorithmIdentifier, Optional[rfc5280.SubjectPublicKeyInfo], bytes, Sequence[rfc9480.InfoTypeAndValue]
]:
    """Extract the catalyst protection mechanism values from the `generalInfo` field.

    :param general_info: The general info field.
    :return: The protection algorithm identifier, the optional public key, and the alternative signature.
    and the other fields to overwrite the generalInfo field.
    """
    prot_alg_id = None
    public_key_info = None
    alt_sig = None

    other_fields = (
        univ.SequenceOf(componentType=rfc9480.InfoTypeAndValue())
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(1, float("inf")))
        .subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))
    )

    for info in general_info:
        if info["infoType"] == id_ce_altSignatureAlgorithm:
            other_fields.append(info)
            prot_alg_id = decoder.decode(info["infoValue"], asn1Spec=rfc9480.AlgorithmIdentifier())[0]
        elif info["infoType"] == id_ce_subjectAltPublicKeyInfo:
            other_fields.append(info)
            public_key_info = decoder.decode(info["infoValue"], asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
        elif info["infoType"] == id_ce_altSignatureValue:
            alt_sig = decoder.decode(info["infoValue"], asn1Spec=univ.BitString())[0]
            alt_sig = alt_sig.asOctets()
        else:
            other_fields.append(info)

    if alt_sig is None:
        raise ValueError("No alternative signature found in the message.")

    if prot_alg_id is None:
        raise ValueError("No protection algorithm found in the message.")

    if public_key_info is not None:
        logging.info("Public key found in the message.")

    return prot_alg_id, public_key_info, alt_sig, other_fields


def verify_hybrid_pkimessage_protection(
    pki_message: rfc9480.PKIMessage,
    public_key: Optional[PublicKeySig] = None,
) -> None:
    """Verify the protection of a PKIMessage with a hybrid protection scheme.

    :param pki_message: The PKIMessage to verify.
    :param public_key: The public key to use for verification.
    (allowed in case of self-signed certificates.)
    :raises InvalidSignature: If the protection of the PKIMessage is invalid.
    """
    prot_alg_id = pki_message["header"]["protectionAlg"]

    if not prot_alg_id.isValue:
        raise BadMessageCheck("The `PKIMessage` does not contain a protection algorithm.")

    if not pki_message["protection"].isValue:
        raise BadMessageCheck("The `PKIMessage` does not contain a protection value.")

    if not pki_message["extraCerts"].isValue and public_key is None:
        raise BadMessageCheck(
            "The `PKIMessage` does not contain any certificatesand no public key was provided for verification."
        )

    data = encoder.encode(pki_message["header"]) + encoder.encode(pki_message["body"])

    oid = prot_alg_id["algorithm"]
    if isinstance(public_key, AbstractCompositeSigPublicKey) and oid in CMS_COMPOSITE_OID_2_NAME:
        pq_compute_utils.verify_signature_with_alg_id(
            public_key=public_key,
            alg_id=prot_alg_id,
            data=data,
            signature=pki_message["protection"].asOctets(),
        )

    elif oid in CMS_COMPOSITE_OID_2_NAME:
        other_certs = None
        if len(pki_message) > 1:
            other_certs = pki_message["extraCerts"][1:]

        verify_composite_signature_with_hybrid_cert(
            data=data,
            sig_alg=prot_alg_id,
            signature=pki_message["protection"].asOctets(),
            cert=pki_message["extraCerts"][0],
            other_certs=other_certs,
        )
    else:
        cert = pki_message["extraCerts"][0]
        other_certs = None
        if len(pki_message) > 1:
            other_certs = pki_message["extraCerts"][1:]

        pq_compute_utils.verify_signature_with_alg_id(
            public_key=load_public_key_from_cert(pki_message["extraCerts"][0]),
            alg_id=prot_alg_id,
            data=data,
            signature=pki_message["protection"].asOctets(),
        )

        sig_alg_id, public_key_info, alt_sig, other_fields = _get_catalyst_info_vals(
            pki_message["header"]["generalInfo"]
        )
        if public_key_info is not None:
            other_key = keyutils.load_public_key_from_spki(public_key_info)
        else:
            other_key = pq_compute_utils.may_extract_alt_key_from_cert(cert=cert, other_certs=other_certs)

        pki_message["header"]["generalInfo"] = other_fields
        data = encoder.encode(pki_message["header"]) + encoder.encode(pki_message["body"])

        pq_compute_utils.verify_signature_with_alg_id(
            public_key=other_key,
            alg_id=sig_alg_id,
            data=data,
            signature=alt_sig,
        )
