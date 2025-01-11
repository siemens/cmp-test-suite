# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""

Related Certificates for Use in Multiple Authentications within a Protocol

Based on:
draft-ietf-lamps-cert-binding-for-multi-auth-06

https://datatracker.ietf.org/doc/draft-ietf-lamps-cert-binding-for-multi-auth/
"""

import logging
import time
from datetime import datetime
from email import message_from_bytes
from typing import List, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480
from pyasn1_alt_modules.rfc7906 import BinaryTime
from resources import cmputils, utils
from resources.asn1utils import get_set_bitstring_names
from resources.ca_kga_logic import validate_issuer_and_serial_number_field
from resources.certextractutils import get_extension, get_field_from_certificate
from resources.certutils import (
    build_cert_chain_from_dir,
    certificates_are_trustanchors,
    load_public_key_from_cert,
    parse_certificate,
    verify_cert_chain_openssl,
)
from resources.convertutils import pyasn1_time_obj_to_py_datetime
from resources.cryptoutils import sign_data, verify_signature
from resources.envdatautils import prepare_issuer_and_serial_number
from resources.oid_mapping import get_hash_from_oid, may_return_oid_to_name
from resources.typingutils import PrivateKey
from resources.utils import manipulate_first_byte
from robot.api.deco import keyword, not_keyword
from unit_tests.utils_for_test import convert_to_crypto_lib_cert

from pq_logic.custom_oids import id_aa_relatedCertRequest, id_relatedCert
from pq_logic.hybrid_structures import RelatedCertificate, RequesterCertificate


def prepare_requester_certificate(
    cert_a: rfc9480.CMPCertificate,
    cert_a_key: PrivateKey,
    uri: str,
    bad_pop: bool = False,
    hash_alg: Optional[str] = None,
    invalid_serial_number: bool = False,
    invalid_issuer: bool = False,
    freshness: int = 0,
    request_time: Optional[int] = None,
) -> RequesterCertificate:
    """Prepare the RequesterCertificate structure.

    Used to provide an association to `cert_A` for the newly generated certificate.
    If the CA is a different one the URI SHOULD be a dataURI, containing inline degenerate PKCS#7 consisting
    of all the certificates and CRLs required to validate Cert A. If same CA SHOULD be a URL.

    :param cert_a: Certificate A as CMPCertificate.
    :param cert_a_key: The private key corresponding to the related certificate.
    :param uri: URL location of Cert A or the complete chain of Cert A, all certificate contained must be DER-encoded.
    :param bad_pop: Whether to manipulate the signature. Defaults to `False`.
    :param hash_alg: The hash algorithm to use for the certificate, if the
    private key is ecc. Defaults to `None`. if required takes the hash algorithm, from the signature algorithm.
    :param invalid_serial_number: Whether to manipulate the serial number. Defaults to `False`.
    :param invalid_issuer: Whether to manipulate the issuer. Defaults to `False`.
    :param freshness: A value to modify The freshness of the BinaryTime. Defaults to `0`.
    :param request_time: The time of the request. Defaults to `None`.
    :return: Prepared RequesterCertificate.
    """
    # get current UNIX time
    current_time = request_time or (int(time.time()) + freshness)
    bin_time = BinaryTime(current_time)
    cert_id = prepare_issuer_and_serial_number(
        cert=cert_a, invalid_serial_number=invalid_serial_number, invalid_issuer=invalid_issuer
    )

    req_cert = RequesterCertificate()
    req_cert["requestTime"] = bin_time
    req_cert["certID"] = cert_id
    req_cert["locationInfo"] = uri

    # As of section 3.1
    # last part: the signature field contains a digital signature over the concatenation of
    # DER encoded requestTime and IssuerAndSerialNumber.
    data = encoder.encode(bin_time) + encoder.encode(cert_id)

    # As of section 3.q signed with the signature algorithm associated with the private key
    # of the certificate.
    if hash_alg is None:
        # could be None for ed25519, ed448, and ML-DSA, SLH-DSA and maybe more in the
        # future.
        oid = cert_a["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
        hash_alg = get_hash_from_oid(oid, only_hash=True)

    if isinstance(cert_a_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) and hash_alg is None:
        # This solution is not inside the draft.
        # TODO maybe file an issue on github or aks if this is allowed solution.
        hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"])

    signature = sign_data(data=data, key=cert_a_key, hash_alg=hash_alg)

    logging.info(f"Signature: {signature}")
    if bad_pop:
        signature = manipulate_first_byte(signature)

    req_cert["signature"] = univ.BitString.fromOctetString(signature)
    return req_cert


@keyword(name="Add CSR relatedCertRequest Attribute")
def add_csr_related_cert_request_attribute(csr: rfc6402.CertificationRequest, requester_cert: RequesterCertificate):
    """Add the relatedCertRequest attribute to the CSR.

    :param csr: The CSR to which the attribute will be added.
    :param requester_cert: The RequesterCertificate to include.
    :return: The updated CSR.

    """
    rel_cert_req_attr = rfc5652.Attribute()
    rel_cert_req_attr["attrType"] = id_aa_relatedCertRequest
    attr_val = rfc5652.AttributeValue(encoder.encode(requester_cert))
    rel_cert_req_attr["attrValues"].append(attr_val)

    csr["certificationRequestInfo"]["attributes"].append(rel_cert_req_attr)

    return csr


def _get_related_cert_sig(cert: rfc9480.CMPCertificate) -> Optional[bytes]:
    """Extract the signature from the `RelatedCertificate` extension.

    :param cert: The certificate from which to extract the extension.
    :return: The signature value (as bytes) if the extension is present, otherwise `None`.
    """
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == id_relatedCert:
            if ext["critical"]:
                logging.info("This extension SHOULD NOT be marked critical.")

            sig = ext["extnValue"].asOctets()
            return sig

    return None


def validate_related_cert_extension(
    cert_a: rfc9480.CMPCertificate, related_cert: rfc9480.CMPCertificate, hash_alg: Optional[str] = None
):
    """Extract the `RelatedCertificate` extension from a given certificate.

    This function retrieves the RelatedCertificate extension from a certificate,
    if present, and extracts the hash of the related certificate and then validates
    the hash against the hash algorithm used by signing the certificate.

    :param cert_a: The certificate from which to extract the RelatedCertificate extension.
                 It should be a parsed ASN.1 object (e.g., `rfc5280.Certificate`).
    :param related_cert: The related certificate which should contain the hash of the
    related certificate.
    :param hash_alg: Currently supports adding a hash for ML-DSA or Ed-keys as an example.
    :return: The hash value of the related certificate (as bytes) if the extension is present,
             otherwise `None`.
    """
    signature = _get_related_cert_sig(cert_a)
    if not signature:
        raise ValueError("The Certificate did not contain the RelatedCertificate extension.")

    hash_alg = hash_alg or get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)
    cert_hash = cmputils.calculate_cert_hash(cert=cert_a, hash_alg=hash_alg)
    if cert_hash != signature:
        raise ValueError(f"The certificate hash is not the same, we used hash_alg: {hash_alg}")

    validate_ku_and_eku_related_cert(cert_a=cert_a, related_cert=related_cert)


@not_keyword
def get_related_cert_from_list(
    certs: List[rfc9480.CMPCertificate], cert_a: rfc9480.CMPCertificate
) -> rfc9480.CMPCertificate:
    """Get the related certificate from a list of certificates.

    :param certs: The list of certificates to search.
    :param cert_a: The certificate for which to find the related certificate.
    :return: The related certificate if found, otherwise `None`.
    :raises ValueError: If no related certificate is found.
    """
    hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)
    signature = _get_related_cert_sig(cert_a)
    if signature is None:
        raise ValueError("The Certificate did not contain the RelatedCertificate extension.")

    for cert in certs:
        cert_hash = cmputils.calculate_cert_hash(cert=cert, hash_alg=hash_alg)
        if cert_hash == signature:
            return cert
    raise ValueError("No related certificate found.")


def _negative_testing():
    # validations:
    # MUST only include a certificate in the extension that is listed and validated in
    # the relatedCertRequest attribute of the CSR submitted by the requesting entity.
    pass


######################
# Server Side function
######################

# other server side functions are currently not included.


def validate_ku_and_eku_related_cert(cert_a: rfc9480.CMPCertificate, related_cert: rfc9480.CMPCertificate) -> None:
    """Validate the key usage (KU) and extended key usage (EKU) of a related certificate.

    Ensure that the cert_a has at least the same KU and EKU bits set.

    :param cert_a: The certificate being issued (Cert B), which defines the required KU and EKU.
                   It should be a parsed x509 certificate object.
    :param related_cert: The related certificate (Cert A) being validated.
                         It should also be a parsed x509 certificate object.

    :raises ValueError: If EKU and KU bits are not set or missing.
    """
    # MUST ensure that the related certificate at least contains the KU bits and EKU
    # OIDs being asserted in the certificate being issued

    eku_cert_a = get_field_from_certificate(cert_a, extension="eku")
    eku_cert_b = get_field_from_certificate(cert_a, extension="eku")

    if eku_cert_a is not None:
        for eku_oid in eku_cert_b:
            if eku_oid not in related_cert:
                raise ValueError()

    ku_cert_a = get_field_from_certificate(cert_a, extension="key_usage")
    ku_cert_b = get_field_from_certificate(related_cert, extension="key_usage")

    if ku_cert_a is not None:
        set_a = set(get_set_bitstring_names(ku_cert_a))
        set_b = set(get_set_bitstring_names(ku_cert_b))

        if ku_cert_b is None or set_a - set_b:
            raise ValueError()


def extract_related_cert_request_attribute(csr: rfc6402.CertificationRequest) -> RequesterCertificate:
    """Extract the relatedCertRequest attribute from a given CSR.

    Retrieves the `relatedCertRequest` attribute from the CSR and decodes it to return the contained
    `RequesterCertificate`.

    :param csr: The `CSR` from which the attribute will be extracted.
    :return: The decoded `RequesterCertificate` object.
    :raises ValueError: If the `relatedCertRequest` attribute is not found in the CSR.
    """
    attributes = csr["certificationRequestInfo"]["attributes"]

    for attr in attributes:
        if attr["attrType"] == id_aa_relatedCertRequest:
            attr_values = attr["attrValues"]
            if len(attr_values) != 1:
                raise ValueError("Unexpected number of values in relatedCertRequest attribute.")
            requester_cert_der = attr_values[0]
            requester_cert, _ = decoder.decode(requester_cert_der, asn1Spec=RequesterCertificate())
            return requester_cert

    raise ValueError("The relatedCertRequest attribute was not found in the CSR.")


def process_mime_message(mime_data: bytes):
    """Parses a MIME message and extracts application/pkcs7-mime content.

    :param mime_data: Raw MIME message as bytes.
    :return: Decoded CMS content (as bytes).
    """
    message = message_from_bytes(mime_data)

    # Look for the application/pkcs7-mime part
    for part in message.walk():
        if part.get_content_type() == "application/pkcs7-mime":
            payload = part.get_payload(decode=True)  # Decode base64
            return payload

    raise ValueError("No application/pkcs7-mime part found in the message.")


def load_certificate_from_uri(uri: str, load_chain: bool) -> List[rfc9480.CMPCertificate]:
    """Get the related certificate using the provided URI.

    :param uri: The URI of the secondary certificate.
    :param load_chain: Whether to load a chain or a single certificate.
    :return: The parsed certificate.
    :raise ValueError: If the fetching fails.
    """
    try:
        logging.info(f"Fetching secondary certificate from {uri}")
        response = requests.get(uri)
        response.raise_for_status()

    except requests.RequestException as e:
        raise ValueError(f"Failed to fetch secondary certificate: {e}")

    if not load_chain:
        cert, rest = decoder.decode(response.content, rfc9480.CMPCertificate())
        if rest:
            raise ValueError("The decoding of the fetching certificate had a remainder.")

        return [cert]

    else:
        certs = response.content.split(b"-----END CERTIFICATE-----\n")
        certs = [cert for cert in certs if cert.strip()]
        cert = [parse_certificate(utils.decode_pem_string(cert)) for cert in certs]
        return cert


def validate_multi_auth_binding_csr(
    csr: rfc6402.CertificationRequest,
    load_chain: bool = False,
    max_freshness_seconds: int = 500,
    trustanchors: str = "./data/trustanchors",
    allow_os_store: bool = False,
    crl_check: bool = False,
) -> rfc9480.CMPCertificate:
    """Process a CSR containing the `relatedCertRequest` attribute.

    Expected the CSR`s Proof-of-Possession (PoP) to be verified.

    :param csr: The x509.CertificateSigningRequest to process.
    :param max_freshness_seconds: How fresh the `BinaryTime` must be Defaults to `500`.
    :param load_chain: Whether to load a chain or a single certificate.
    :param trustanchors: The directory containing the trust anchors. Defaults to `./data/trustanchors`.
    :param crl_check: Whether to check the CRL. Defaults to `False`.
    :param allow_os_store: Whether to allow the OS trust store. Defaults to `False`.
    :return: The related certificate.
    :raises ValueError: If the `BinaryTime` is not fresh or the certificate chain is invalid.
    :raises InvalidSignature: If the PoP of the related certificate is invalid.
    :raises ValueError: If the last certificate in the chain is not a trust anchor.
    :raises ValueError: If the certificate chain is not valid.
    """
    attributes = extract_related_cert_request_attribute(csr)

    request_time = int(attributes["requestTime"])
    current_time = int(time.time())
    if abs(current_time - request_time) > max_freshness_seconds:
        raise ValueError("BinaryTime is not sufficiently fresh.")

    location_info = attributes["locationInfo"]
    signature = attributes["signature"].asOctets()

    cert_chain = load_certificate_from_uri(location_info, load_chain=load_chain)
    cert_a = cert_chain[0]

    # validate binding
    public_key = load_public_key_from_cert(cert_a)
    hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    sig_name = may_return_oid_to_name(cert_a["tbsCertificate"]["signature"]["algorithm"])
    logging.info(f"Signature algorithm: {sig_name}")

    if hash_alg is None:
        raise ValueError(f"The hash algorithm could not be determined. Signature algorithm was: {sig_name}")

    validate_issuer_and_serial_number_field(attributes["certID"], cert_a)
    # extra the bound value to verify the signature
    data = encoder.encode(attributes["requestTime"]) + encoder.encode(attributes["certID"])

    verify_signature(data=data, hash_alg=hash_alg, public_key=public_key, signature=signature)

    certificates_are_trustanchors(cert_chain[-1], trustanchors=trustanchors, allow_os_store=allow_os_store)
    verify_cert_chain_openssl(cert_chain=cert_chain, crl_check=crl_check)
    return cert_a


# Technically should be changed to CertTemplate and/or CSR.
# MUST include chain check.
def server_side_validate_cert_binding_for_multi_auth(ee_cert, related_cert) -> None:
    """Validate the certificate binding for multiple authentications on the server side.

    :param ee_cert: The certificate being issued (Cert B), which defines the required KU and EKU.
    :param related_cert: The related certificate (Cert A) being validated.
    """
    # Only on ee-certificates
    extn = get_extension(ee_cert["extensions"], rfc5280.id_ce_basicConstraints)

    if extn is not None:
        if extn["cA"]:
            raise ValueError("The `Cert A` is a CA certificate.")

    # MUST ensure that the related certificate at least contains the KU bits and EKU
    # OIDs being asserted in the certificate being issued
    validate_ku_and_eku_related_cert(ee_cert, related_cert)

    # SHOULD determine that all certificates are valid at the time of issuance.
    # The usable overlap of validity periods is a Subscriber concern.

    now = datetime.now()

    val_cert_a = related_cert["tbsCertificate"]["validity"]
    cert_b = ee_cert["tbsCertificate"]["validity"]

    rel_cert_not_valid_before = pyasn1_time_obj_to_py_datetime(val_cert_a["notBefore"])
    rel_cert_not_valid_after = pyasn1_time_obj_to_py_datetime(val_cert_a["notAfter"])

    cert_b_not_valid_before = pyasn1_time_obj_to_py_datetime(cert_b["notBefore"])
    cert_b_not_valid_after = pyasn1_time_obj_to_py_datetime(cert_b["notAfter"])

    if not (rel_cert_not_valid_after <= now <= rel_cert_not_valid_before):
        raise ValueError("Cert A is not valid at the time of issuance.")
    if not (cert_b_not_valid_before <= now <= cert_b_not_valid_after):
        raise ValueError("Cert B is not valid at the time of issuance.")
    if rel_cert_not_valid_after < rel_cert_not_valid_before:
        logging.info("Cert A and Cert B do not have an overlapping validity period.")


def _convert_to_crypto_lib_cert(cert: rfc9480.CMPCertificate) -> x509.Certificate:
    """Ensure the function calling this method, can work with certificates from the 'cryptography' library."""
    return x509.load_der_x509_certificate(encoder.encode(cert))


def generate_certs_only_message(cert_path: str, cert_dir: str) -> bytes:
    """Generate a CMS 'certs-only' message containing Cert A and its intermediate certificates.

    :param cert_path: Path to the end-entity certificate (Cert A).
    :param cert_dir: The directory where the chain is stored.
    :return: DER-encoded CMS 'certs-only' message as bytes.
    """
    ee_cert = parse_certificate(utils.load_and_decode_pem_file(cert_path))
    cert_chain = build_cert_chain_from_dir(ee_cert, cert_chain_dir=cert_dir)

    cms_message = pkcs7.PKCS7SignatureBuilder().set_data(b"")
    for cert in cert_chain:
        cms_message = cms_message.add_certificate(convert_to_crypto_lib_cert(cert))

    cms_der = cms_message.sign(serialization.Encoding.DER, [])
    return cms_der


def prepare_related_certificate_extension(
    cert_a, hash_alg: Optional[str] = None, critical: bool = False
) -> rfc5280.Extension:
    """Prepare the RelatedCertificate extension for a x509 certificate.

    :param cert_a: The certificate for which to prepare the extension.
    :param hash_alg: The hash algorithm to use for the certificate. Defaults to `None`.
    :param critical: Whether the extension should be marked as critical. Defaults to `False`.
    :return: The prepared extension.
    """
    # Notes:
    # For certificate chains, this extension MUST only be included in the end-entity certificate.

    # TODO tell the specifier to fix for sig algorithm without hash!
    # ed25519 and ML-DSA.

    # for negative testing or ed-keys and so on.
    hash_alg = hash_alg or get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    cert_hash = cmputils.calculate_cert_hash(cert=cert_a, hash_alg=hash_alg)
    extension = rfc5280.Extension()
    extension["extnID"] = id_relatedCert
    # This extension SHOULD NOT be marked critical.
    # As of section 4.1
    extension["critical"] = critical
    extension["extnValue"] = RelatedCertificate(cert_hash)

    return extension
