from typing import Optional
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc2986, rfc2459, rfc5280, rfc9480
from pyasn1.type import char
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Union
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.type import univ
import random

from cast_utils.cast_cert import cast_csr_to_asn1
from typingutils import csr_cert_types

def modify_csr_cn(csr_data: csr_cert_types, new_cn: Optional[str] = "Hans Mustermann") -> bytes:
    """Modifies the Common Name (CN) in a CSR. Expects a CN to be present in the certificate; otherwise, raises a ValueError.

    Args:
        csr_data: The DER-encoded CSR as a byte string.
        new_cn: The new Common Name (CN) to be set. Defaults to "Hans Mustermann".

    Returns:
        The DER-encoded CSR with the modified CN.

    Raises:
        ValueError: If no Common Name (CN) is found in the CSR.
    """
    # Decode the CSR from its DER-encoded form into a CertificationRequest object.
    csr = cast_csr_to_asn1(csr_data)

    # Access the subject field from the CSR, which contains the RDNSequence.
    subject = csr["certificationRequestInfo"]["subject"]

    # Flag to check if a CN was found and modified.
    found_cn = False

    # Iterate through the Relative Distinguished Names (RDN) sequence to find the CN.
    for rdn in subject["rdnSequence"]:  # rdnSequence is a Sequence OF RDN.
        # Each RDN can contain multiple AttributeTypeAndValue pairs.
        attribute: rfc2986.AttributeTypeAndValue
        for attribute in rdn:
            # Check if the current attribute is a Common Name (CN).
            if attribute["type"] == rfc2459.id_at_commonName:
                # Modify the CN by setting a new PrintableString value.
                found_cn = True
                attribute['value'] = char.PrintableString(new_cn)

    # If no CN was found, raise an error to indicate that the modification failed.
    if not found_cn:
        raise ValueError("No Common Name (CN) found in the provided CSR.")

    # Re-encode the modified CertificationRequest object back into DER format.
    modified_csr_der = encoder.encode(csr)

    # Return the DER-encoded CSR with the modified CN.
    return modified_csr_der


def verify_csr_signature(csr_der: bytes) -> bool:
    """Verifies the signature of a Certificate Signing Request (CSR).

    Args:
        csr_der: The DER-encoded CSR as a byte string.

    Returns:
        True if the CSR signature is valid, False otherwise.
    """
    # Load the CSR from its DER-encoded form into an x509 CertificateSigningRequest object.
    cert = x509.load_der_x509_csr(csr_der)

    # Extract the public key from the CSR, which will be used to verify the signature.
    public_key = cert.public_key()

    try:
        # Verify the signature of the CSR.
        public_key.verify(
            cert.signature,  # The signature to verify.
            cert.tbs_certrequest_bytes,  # The data that was signed.
            padding.PKCS1v15(),  # The padding scheme used for the signature.
            cert.signature_hash_algorithm,  # The hash algorithm used for the signature.
        )
        # If the verification is successful, return True.
        return True

    except Exception as e:
        # If verification fails, print an error message and return False.
        print(f"Signature verification failed: {e}")
        return False

