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

def modify_csr_cn(csr_der: bytes, new_cn: Optional[str] = "Hans Mustermann") -> bytes:
    """Modifies the Common Name (CN) in a CSR. expects to have a CN inside the Certificate
    Otherwise Raises an ValueError

    Args:
        csr_der: The DER-encoded CSR as a byte string.
        new_cn: The new Common Name (CN) to be set. Defaults to "Hans Mustermann".

    Returns:
        The DER-encoded CSR with the modified CN.

    Raises:
        ValueError: If no Common Name (CN) is found in the CSR.
    """
    # Decode the CSR from its DER-encoded form into a CertificationRequest object.
    csr, _ = decoder.decode(csr_der, asn1Spec=rfc2986.CertificationRequest())

    # Access the subject field from the CSR, which contains the RDNSequence.
    subject = csr["certificationRequestInfo"]["subject"]

    # Flag to check if a CN was found and modified.
    found_cn = False

    # Iterate through the Relative Distinguished Names (RDN) sequence to find the CN.
    for rdn in subject["rdnSequence"]:  # rdnSequence is a Sequence OF RDN.
        for (
            attribute
        ) in rdn:  # Each RDN can contain multiple AttributeTypeAndValue pairs.
            # Check if the current attribute is a Common Name (CN).
            if attribute["type"] == rfc2459.id_at_commonName:
                # Modify the CN by setting a new PrintableString value.
                found_cn = True
                attribute.setComponentByPosition(1, char.PrintableString(new_cn))

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





def change_byte_at_offset(data: bytes, index: int, value: bytes) -> bytes:
    """
    Change a byte at a specific offset in a bytes object.

    This keyword modifies a byte at a specified position in a given bytes object.
    It replaces the original byte at the provided index with the new byte given
    in the `value` parameter.

    Arguments:
    - data: The original bytes object to be modified.
    - index: The position in the bytes object where the byte should be changed.
    - value: A single byte that will replace the original byte at the given index.

    Returns:
    - A new bytes object with the byte at the specified index replaced.
    """

    # Ensure the value is exactly one byte
    if len(value) != 1:
        raise ValueError("The value must be a single byte.")

    # Convert the bytes object to a mutable bytearray
    mutable_data = bytearray(data)

    # Change the byte at the specified index
    mutable_data[index] = value[0]

    # Convert the bytearray back to bytes and return the modified bytes object
    return bytes(mutable_data)




def randomly_change_byte(data: bytes) -> bytes:
    """
    Randomly change a byte in a given byte object.

    :param data: The original byte object.
    :return: A new byte object with one byte randomly changed.
    """
    if not data:
        raise ValueError("The byte object must not be empty.")

    # Convert the byte object to a mutable bytearray
    byte_array = bytearray(data)

    # Select a random index to change
    index_to_change = random.randint(0, len(byte_array) - 1)

    # Select a new random byte value (0-255) that is different from the current one
    original_byte = byte_array[index_to_change]
    new_byte = original_byte
    while new_byte == original_byte:
        new_byte = random.randint(128, 255)

    # Change the byte at the selected index
    byte_array[index_to_change] = new_byte

    # Convert the bytearray back to a bytes object
    return bytes(byte_array)


# Example usage:
# original_data = b"Example byte string"
# modified_data = randomly_change_byte(original_data)
