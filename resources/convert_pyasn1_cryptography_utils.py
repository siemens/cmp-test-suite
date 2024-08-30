"""
This library provides utility functions for converting cryptographic data structures between
pyasn1 and cryptography library formats.

The naming convention is:
convert_<objectname>_crypto_to_pyasn1 to -> pyasn1 object
convert_<objectname>_pyasn1_to_crypto -> cryptography object

For better readability always start with: pyasn1_to_crypto -> cryptography object

# TODO needs to be added if kept.
Example:

"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc5280, rfc6402
from robot.api.deco import not_keyword


@not_keyword
def convert_cert_pyasn1_to_crypto(cert: rfc5280.Certificate) -> x509.Certificate:
    """
    Converts a pyasn1 `rfc5280.Certificate` object to a cryptography `x509.Certificate` object.

    :param cert: The pyasn1 certificate to be converted.
    :return: The converted certificate as a `cryptography` `x509.Certificate` object.
    """
    return x509.load_der_x509_certificate(encoder.encode(cert))


@not_keyword
def convert_cert_crypto_to_pyasn1(cert: x509.Certificate) -> rfc5280.Certificate:
    """
    Converts a cryptography `x509.Certificate` object to a pyasn1 `rfc5280.Certificate` object.

    :param cert: The cryptography `x509.Certificate` to be converted.
    :return: The converted certificate as a pyasn1 `rfc5280.Certificate` object.
    """
    cert = cert.public_bytes(serialization.Encoding.DER)
    return decoder.decode(cert, ans1spec=rfc5280.Certificate)

@not_keyword
def convert_csr_pyasn1_to_crypto(csr: rfc6402.CertificationRequest) -> x509.CertificateSigningRequest:
    """
    Converts a pyasn1 `rfc6402.CertificationRequest` object to a cryptography `x509.CertificateSigningRequest` object.

    :param csr: The pyasn1 certification request to be converted.
    :return: The converted certification request as a `cryptography` `x509.CertificateSigningRequest` object.
    """
    return x509.load_der_x509_csr(encoder.encode(csr))


@not_keyword
def convert_csr_crypto_to_pyasn1(csr: x509.CertificateSigningRequest) -> rfc6402.CertificationRequest:
    """
    Converts a cryptography `x509.CertificateSigningRequest` object to a pyasn1 `rfc6402.CertificationRequest` object.

    :param csr: The cryptography `x509.CertificateSigningRequest` to be converted.
    :return: The converted certification request as a pyasn1 `rfc6402.CertificationRequest` object.
    """
    csr = csr.public_bytes(serialization.Encoding.DER)
    return decoder.decode(csr, ans1spec=rfc6402.CertificationRequest)









