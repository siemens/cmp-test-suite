import unittest

import cryptography.exceptions
from cryptography import x509

import cmputils
import verifyingutils
from cmputils import encode_to_der
from convert_pyasn1_cryptography_utils import convert_cert_pyasn1_to_crypto, convert_csr_crypto_to_pyasn1
from cryptoutils import generate_signed_csr
from utils import decode_pem_string


class TestUtils(unittest.TestCase):
    def test_verification_fails(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        """

        csr, key = generate_signed_csr(common_name="CN=Hans", key="rsa", pem=False)


        # to check that the signature before was correct.
        csr_signed = x509.load_pem_x509_csr(csr)
        #verify if the certificate is correct
        verifyingutils.verify_csr_signature(csr_signed, key.public_key())
        verifyingutils.verify_csr_signature(csr_signed, None)

        csr = convert_csr_crypto_to_pyasn1(csr_signed)
        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        # returns DER Encoded data
        modified_csr = cmputils.modify_csr_cn(csr, new_cn="Hans MusterMann")

        modified_csr = x509.load_der_x509_csr(modified_csr)
        # Verify the signature of the modified CSR
        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            verifyingutils.verify_csr_signature(modified_csr, key.public_key())

