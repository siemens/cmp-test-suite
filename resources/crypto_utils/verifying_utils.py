from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from castutils import cast_asn1cert_to_cert, cast_asn1csr_to_csr
from typingutils import PublicKey, CertType, CsrType


# TODO update ECC.

def verify_signature(cert: Union[x509.Certificate, x509.CertificateSigningRequest], public_key: PublicKey = None):
    """
    Verifies the digital signature of a given certificate or certificate signing request (CSR).

    :param cert:
        The certificate or certificate signing request to verify.
        Must be an instance of either `x509.Certificate` or `x509.CertificateSigningRequest`.
    :param public_key:
        The public key used to verify the signature of the certificate.
        This parameter is optional and only applicable when verifying an `x509.Certificate`.
        Default is None. (self-signed)
    :return:
        Returns `True` if the signature is valid; otherwise, returns `False`.
    :raises ValueError:
        If the input `cert` is not an instance of `x509.Certificate` or `x509.CertificateSigningRequest`.
        In such cases, use `verify_cert_signature` or `verify_csr_signature` directly.
    """
    if isinstance(cert, x509.Certificate):
        return verify_cert_signature(cert=cert, public_key=public_key)

    elif isinstance(cert, x509.CertificateSigningRequest):
        return verify_csr_signature(cert)

    else:
        raise ValueError('Certificate must be either x509.Certificate or x509.CertificateSigningRequest Otherwise use verify_cert_signature or verify_csr_signature'
                         'includes casting!')


def verify_cert_signature(cert: CertType, public_key: PublicKey = None):
    """
    Verifies the digital signature of an X.509 certificate using the provided or extracted public key.


    :param cert:
        The certificate to verify, represented in a type that can be cast to an X.509 certificate object.
        It should be in a DER-encoded form compatible with the `x509.Certificate` type.
    :param public_key:
        The public key used for verifying the certificate's signature.
        This parameter is optional. If not provided, the public key is extracted from the certificate.

    :raises ValueError:
        If the certificate type is not valid or casting fails.
    :raises InvalidSignature:
        If the certificate's signature is not valid when verified against the provided or extracted public key.
    """
    # Converts the input in a x509.Certificate object.
    cert: x509.Certificate = cast_asn1cert_to_cert(cert)

    if public_key is None:
        # Extract the public key from the CSR, which will be used to verify the signature.
        public_key = cert.public_key()


    # Verify the signature of the CSR.
    public_key.verify(
        cert.signature,  # The signature to verify.
        cert.tbs_certificate_bytes,  # The data that was signed.
        padding.PKCS1v15(),  # The padding scheme used for the signature.
        cert.signature_hash_algorithm,  # The hash algorithm used for the signature.
    )


def verify_csr_signature(csr: CsrType, public_key: PublicKey = None):
    """
    Verifies the digital signature of an X.509 CSR using the provided or extracted public key.


    :param csr:
        The Certificate Signing Request to verify, represented in a type that can be cast to an X.509 CSR object.
        It should be in a DER-encoded form compatible with the `x509.Certificate` type.
    :param public_key:
        The public key used for verifying the certificate's signature.
        This parameter is optional. If not provided, the public key is extracted from the certificate.

    :raises ValueError:
        If the csr type is not valid or casting fails.
    :raises InvalidSignature:
        If the csr's signature is not valid when verified against the provided or extracted public key.
    """
    # Converts the input in a x509.CertificateSigningRequest object.
    cert = cast_asn1csr_to_csr(csr)

    if public_key is None:
        # Extract the public key from the CSR, which will be used to verify the signature.
        public_key = cert.public_key()


    # Verify the signature of the CSR.
    public_key.verify(
        cert.signature,  # The signature to verify.
        cert.tbs_certrequest_bytes,  # The data that was signed.
        padding.PKCS1v15(),  # The padding scheme used for the signature.
        cert.signature_hash_algorithm,  # The hash algorithm used for the signature.
    )

