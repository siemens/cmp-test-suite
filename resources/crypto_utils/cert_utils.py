import base64
from typing import Tuple

from cryptography import x509
from robot.api.deco import not_keyword

from cryptoutils import generate_csr, sign_csr
from crypto_utils.key_utils import generate_key

from typingutils import PRIVATE_KEY

def pem_to_der(pem_csr: str | bytes) -> bytes:
    """
    Convert a PEM-encoded Certificate Signing Request (CSR) to DER format.

    :param pem_csr: The PEM-encoded CSR as a string.
    :return: The DER-encoded CSR as bytes.
    """

    if isinstance(pem_csr, bytes):
        pem_csr = pem_csr.decode("utf-8")

    # Split the PEM string into lines
    lines = pem_csr.strip().splitlines()

    # Filter out the header and footer lines
    pem_body = ''.join(line for line in lines if not line.startswith('-----'))

    # Decode the base64 encoded content to DER format
    der_data = base64.b64decode(pem_body)

    return der_data



@not_keyword
def generate_fresh_csr(common_name: str, key: PRIVATE_KEY = None) -> Tuple[x509.CertificateSigningRequest, PRIVATE_KEY]:
    """
    This Function generates a fresh csr with a provided common name
    :param common_name: in the format CN=Hans,emailAdresse=@.com and so on.
    :return: Returns
    """

    key = key or generate_key(algorithm="rsa", length=2048)
    csr = generate_csr(common_name)
    csr_signed = sign_csr(csr=csr, key=key)
    csr_signed = x509.load_pem_x509_csr(csr_signed)
    return csr_signed, key
