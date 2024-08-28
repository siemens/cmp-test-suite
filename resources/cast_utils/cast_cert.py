import logging
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc2986, rfc9480
import utils


from typingutils import CSR_TYPE, CERT_TYPE


# TODO install pyyaml and load config
debug_asn1_decode_remainder = True

#TODO include Pem

def cast_csr_to_asn1csr(data: CSR_TYPE) -> rfc2986.CertificationRequest:
    """
    Converts a given Certificate Signing Request (CSR) into an ASN.1 encoded `rfc2986.CertificationRequest` object.

    Arguments:
    - data: The CSR data to be converted. Can be one of the following:
      - `bytes`: DER-encoded CSR data.
      - `x509.CertificateSigningRequest`: An `x509` CSR object.
      - `rfc2986.CertificationRequest`: An ASN.1 encoded `CertificationRequest` object.

    Returns:
    - The CSR as an `rfc2986.CertificationRequest` object.

    Raises:
    - ValueError: If the input data type is not supported.
    """

    if isinstance(data, rfc2986.CertificationRequest):
        # If the input data is already an ASN.1 CertificationRequest object, return it as is.
        return data

    elif isinstance(data, bytes):
        # If the input data is in DER-encoded bytes format, decode it into a CertificationRequest object.
        csr, remainder = decoder.decode(data, asn1Spec=rfc2986.CertificationRequest())

        # Optionally log any remaining undecoded data if debugging is enabled.
        if debug_asn1_decode_remainder:
            logging.debug(f"remainder: {remainder}")

        # Return the decoded ASN.1 CertificationRequest object.
        return csr

    elif isinstance(data, x509.CertificateSigningRequest):
        # If the input data is a cryptography x509.CertificateSigningRequest,
        # convert it to DER-encoded bytes and recursively call the function to get an ASN.1 CertificationRequest.
        return cast_csr_to_asn1csr(data.public_bytes(serialization.Encoding.DER))
    else:
        # Raise an error if the input type is unsupported.
        raise ValueError(f'Unsupported type: {type(data)}')


def cast_asn1csr_to_csr(data: CSR_TYPE) -> x509.CertificateSigningRequest:
    """
    Convert data to a `x509.CertificateSigningRequest` object.

    Arguments:
    - data: The input data to be converted into a `x509.CertificateSigningRequest` object.
            Can be one of the following types:
            - `bytes`: DER-encoded CSR data.
            - `x509.CertificateSigningRequest`: An `x509` CSR object.
            - `rfc2986.CertificationRequest`: An ASN.1 encoded `CertificationRequest` object.

    Returns:
    - The input data as a `x509.CertificateSigningRequest` object.

    Raises:
    - ValueError: If the input data is of an unsupported type.
    """

    # Check if the input data is an ASN.1 CertificationRequest object
    if isinstance(data, rfc2986.CertificationRequest):
        # Encode the ASN.1 object into DER format
        data = encoder.encode(data)
        # Recursively call the function with the DER-encoded data
        return cast_asn1csr_to_csr(data)

    # Check if the input data is already in DER-encoded bytes
    elif isinstance(data, bytes):
        # Load and parse the DER-encoded CSR into an x509.CertificateSigningRequest object
        return x509.load_der_x509_csr(data=data)

    # Check if the input data is already a x509.CertificateSigningRequest object
    elif isinstance(data, x509.CertificateSigningRequest):
        # Return the input data as it is already the desired type
        return data
    # Raise an error if the input data type is unsupported
    else:
        raise ValueError(f'Unsupported type: {type(data)}')


# TODO change to actual RFC
def cast_cert_to_asn1cert(data: CERT_TYPE) -> rfc9480.Certificate:
    """
    Converts a given Certificate into an ASN.1 encoded `rfc9480.Certificate` object.

    Arguments:
    - data: The Certificate data to be converted. Can be one of the following:
      - `bytes`: DER-encoded Certificate data.
      - `x509.Certificate`: An `x509` CSR object.
      - `rfc9480.Certificate`: An ASN.1 encoded `Certificate` object.

    Returns:
    - The CSR as an `rfc9480.Certificate` object.

    Raises:
    - ValueError: If the input data type is not supported.
    """

    if isinstance(data, rfc9480.Certificate):
        # If the input data is already an ASN.1 CertificationRequest object, return it as is.
        return data

    elif isinstance(data, bytes):
        # If the input data is in DER-encoded bytes format, decode it into a CertificationRequest object.
        csr, remainder = decoder.decode(data, asn1Spec=rfc9480.Certificate)

        # Optionally log any remaining undecoded data if debugging is enabled.
        if debug_asn1_decode_remainder:
            logging.debug(f"remainder: {remainder}")

        # Return the decoded ASN.1 CertificationRequest object.
        return csr

    elif isinstance(data, x509.Certificate):
        # If the input data is a cryptography x509.CertificateSigningRequest,
        # convert it to DER-encoded bytes and recursively call the function to get an ASN.1 CertificationRequest.
        return cast_cert_to_asn1cert(data.public_bytes(serialization.Encoding.DER))
    else:
        # Raise an error if the input type is unsupported.
        raise ValueError(f'Unsupported type: {type(data)}')


def cast_asn1cert_to_cert(data: CERT_TYPE) -> x509.Certificate:
    """
    Convert data to a `x509.Certificate` object.

    Arguments:
    - data: The input data to be converted into a `x509.Certificate` object.
            Can be one of the following types:
            - `bytes`: DER-encoded Certificate data.
            - `x509.Certificate`: An `x509` Certificate object.
            - `rfc2986.Certificate`: An ASN.1 encoded `Certificate` object.

    Returns:
    - The input data as a `x509.Certificate` object.

    Raises:
    - ValueError: If the input data is of an unsupported type.
    """

    # Check if the input data is an ASN.1 CertificationRequest object
    if isinstance(data, rfc9480.Certificate):
        # Encode the ASN.1 object into DER format
        data = encoder.encode(data)
        # Recursively call the function with the DER-encoded data
        return cast_asn1cert_to_cert(data)

    # Check if the input data is already in DER-encoded bytes
    elif isinstance(data, bytes):
        # Load and parse the DER-encoded CSR into an x509.Certificate object
        return x509.load_der_x509_certificate(data=data)

    # Check if the input data is already a x509.CertificateSigningRequest object
    elif isinstance(data, x509.Certificate):
        # Return the input data as it is already the desired type
        return data
    # Raise an error if the input data type is unsupported
    else:
        raise ValueError(f'Unsupported type: {type(data)}')