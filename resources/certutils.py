"""Some wrapper-tools for validating an X509 cert by invoking other software, e.g., OpenSSL, pkilint."""

import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pkilint import loader, report
from pkilint.pkix import certificate, extension, name
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480

# TODO for these to integrate smoothly into RF, they have to raise exceptions in case of failure, rather than
# return False


def parse_certificate(data):
    """Parse a DER-encoded X509 certificate into a pyasn1 object.

    :param data: bytes, DER-encoded X509 certificate.
    :returns: pyasn1 object, the parsed certificate.
    """
    cert, _rest = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())
    return cert


def validate_certificate_openssl(data):
    """Validate a certificate by attempting to load it with the cryptography library, which invokes OpenSSL underneath.

    :param data: bytes, DER-encoded X509 certificate.
    :returns bool: True if loading was without errors, otherwise False
    """
    try:
        _certificate = x509.load_der_x509_certificate(data, default_backend())
    except Exception as e:
        message = f"Certificate validation with openssl failed: {e}"
        logging.error(message)
        raise ValueError(message)


def validate_certificate_pkilint(data):
    """Validate a certificate using the pkilint tool.

    :param data: bytes, DER-encoded X509 certificate.
    :returns None: Will raise an exception if issues were found
    """
    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container([]),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container([]),
            certificate.create_extensions_validator_container([]),
        ],
    )

    cert = loader.load_certificate(data, "dynamic-cert")
    results = doc_validator.validate(cert.root)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        raise ValueError(issues)


if __name__ == "__main__":
    raw_cert = open(r"cert.cer", "rb").read()
    result = validate_certificate_pkilint(raw_cert)
    print(result)

    result = validate_certificate_openssl(raw_cert)
    print(result)
