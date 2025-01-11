
"""Contains logic to perform all kind of verification tasks.

Either has functionality to verify signatures of PKIMessages or certificates.


"""
import logging
# TODO fix to include CRL-Verification
# currently only works for PQ and traditional signatures.
# But in the next update will be Completely support CRL-Verification.

from typing import Optional, List

from pq_logic.custom_oids import id_relatedCert
from pq_logic.hybrid_sig.catalyst_logic import id_ce_subjectAltPublicKeyInfo, \
    SubjectAltPublicKeyInfoExt
from pq_logic.hybrid_sig.certdiscovery import extract_sia_extension_for_cert_discovery, get_secondary_certificate, \
    validate_alg_ids
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import validate_alt_pub_key_extn, validate_alt_sig_extn
from pq_logic.keys.abstract_pq import PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPublicKey
from pq_logic.pq_compute_utils import verify_signature_with_alg_id
from resources.certextractutils import get_extension
from resources.certutils import load_public_key_from_cert
from resources.exceptions import BadAsn1Data
from resources.keyutils import load_public_key_from_spki
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME
from resources.typingutils import PublicKeySig

from pyasn1_alt_modules import rfc9480, rfc5280
from pyasn1.codec.der import encoder, decoder


def may_extract_alt_key_from_cert(cert: rfc9480.CMPCertificate,
                                  other_certs: Optional[List[rfc9480.CMPCertificate]] = None) -> Optional[PQSignaturePublicKey]:
    """May extract the alternative public key from a certificate.

    Either extracts the alternative public key from the issuer's certificate or from the certificate discovery extension.
    Alternative extracts the pq_key of the related certificate from the issuer's certificate or
    if the issuer's certificate is a composite signature certificate, extracts the pq_key from the composite signature
    keys.

    :param cert: The certificate from which to extract the alternative public key.
    :param other_certs: A list of other certificates to search for the related certificate.
    :return: The extracted alternative public key or None if not found.
    """

    extensions = cert["tbsCertificate"]["extensions"]
    extn_rel_cert = get_extension(extensions, id_relatedCert)
    extn_sia = get_extension(extensions, rfc5280.id_pe_subjectInfoAccess)
    extn_alt_spki = get_extension(extensions, id_ce_subjectAltPublicKeyInfo)

    try:
        rel_cert_desc = extract_sia_extension_for_cert_discovery(extn_sia)
    except ValueError:
        rel_cert_desc = None

    # TODO fix try to validate both.

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    oid = spki["algorithm"]["algorithm"]

    if extn_rel_cert is not None and other_certs is not None:
        logging.info("Validate signature with related certificate.")
        related_cert = get_related_cert_from_list(other_certs, cert)  # type: ignore
        pq_key = load_public_key_from_spki(related_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        return pq_key

    if extn_rel_cert is not None and other_certs is None:
        logging.warning("Related certificate extension found but no other certificates provided.")

    if extn_alt_spki is not None:
        logging.info("Validate signature with alternative public key.")
        spki, rest = decoder.decode(extn_alt_spki["extnValue"].asOctets(), SubjectAltPublicKeyInfoExt())
        if rest:
            raise BadAsn1Data("The alternative public key extension contains remainder data.", overwrite=True)
        alt_issuer_key = load_public_key_from_spki(spki)
        return alt_issuer_key

    if rel_cert_desc is not None:
        logging.info("Validate signature with cert discovery.")
        uri = str(rel_cert_desc["uniformResourceIdentifier"])
        other_cert = get_secondary_certificate(uri)
        validate_alg_ids(other_cert, rel_cert_desc=rel_cert_desc)
        pq_key = load_public_key_from_spki(other_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        return pq_key


    if oid in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey.from_spki(spki)
        CompositeSigCMSPublicKey.validate_oid(oid, public_key)
        return CompositeSigCMSPublicKey.pq_key

    return None

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
        alt_issuer_key = may_extract_alt_key_from_cert(issuer_cert, other_certs=other_certs)
        if alt_issuer_key is None:
            raise ValueError("No alternative issuer key found.")

    alt_pub_key = validate_alt_pub_key_extn(cert)
    if check_alt_sig:
        validate_alt_sig_extn(cert, alt_pub_key, alt_issuer_key)

    public_key = load_public_key_from_cert(issuer_cert)
    data = encoder.encode(cert["tbsCertificate"])
    alg_id = cert["tbsCertificate"]["signature"]
    signature = cert["signature"].asOctets()
    verify_signature_with_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)


