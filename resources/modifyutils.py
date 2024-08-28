from typing import Optional
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc2986, rfc2459
from pyasn1.type import char

from cast_utils.cast_cert import cast_csr_to_asn1csr
from typingutils import CSR_TYPE

def modify_csr_cn(csr_data: CSR_TYPE, new_cn: Optional[str] = "Hans Mustermann") -> bytes:
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
    csr = cast_csr_to_asn1csr(csr_data)

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


