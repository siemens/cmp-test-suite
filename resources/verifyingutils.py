from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from robot.api.deco import not_keyword

from typingutils import PublicKey

# TODO: Was changed in next Merge!


# only internally used, so strict Parsing
@not_keyword
def verify_cert_signature(cert: x509.Certificate, public_key: PublicKey = None):
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

# only internally used, so strict Parsing
def verify_csr_signature(csr: x509.CertificateSigningRequest, public_key: PublicKey = None):
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

    if public_key is None:
        # Extract the public key from the CSR, which will be used to verify the signature.
        public_key = csr.public_key()


    # Verify the signature of the CSR.
    public_key.verify(
        csr.signature,  # The signature to verify.
        csr.tbs_certrequest_bytes,  # The data that was signed.
        padding.PKCS1v15(),  # The padding scheme used for the signature.
        csr.signature_hash_algorithm,  # The hash algorithm used for the signature.
    )

