"""Some wrapper-tools for validating an X509 cert by invoking other software, e.g., OpenSSL, pkilint. """
import logging

from pkilint import loader
from pkilint import report
from pkilint.pkix import certificate, name, extension
from pkilint.validation import ValidationFindingSeverity

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def validate_certificate_openssl(data):
    """Validate a certificate by attempting to load it with the cryptography library, which invokes OpenSSL underneath.

    :param data: bytes, DER-encoded X509 certificate.
    :returns bool: True if loading was without errors, otherwise False"""
    try:
        _certificate = x509.load_der_x509_certificate(data, default_backend())
    except Exception as e:
        logging.error("Certificate validation with openssl failed: %s", e)
        return False

    return True


def validate_certificate_pkilint(data):
    """Validate a certificate using the pkilint tool.

    :param data: bytes, DER-encoded X509 certificate.
    :returns bool: True if all is well, otherwise False (errors will be printed in the log)"""
    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container(
                []
            ),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container(
                []
            ),
            certificate.create_extensions_validator_container(
                []
            ),
        ]
    )

    cert = loader.load_certificate(data, "dynamic-cert")
    results = doc_validator.validate(cert.root)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        logging.error('Certificate validation with pkilint failed: %s', issues)
        return False

    return True


if __name__ == "__main__":
    raw_cert = open(r"cert.cer", 'rb').read()
    result = validate_certificate_pkilint(raw_cert)
    print(result)

    result = validate_certificate_openssl(raw_cert)
    print(result)
