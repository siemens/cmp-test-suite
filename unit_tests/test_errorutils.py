import unittest

import cryptography.exceptions

import cmputils
import verifyingutils
from cryptoutils import generate_signed_csr


class TestUtils(unittest.TestCase):
    def test_verification_fails(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        """

        csr, key = generate_signed_csr(common_name="CN=Hans", key="rsa", pem=False)

        #verify if the certificate is correct
        verifying_utils.verify_csr_signature(csr, key.public_key())
        verifying_utils.verify_csr_signature(csr, None)

        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        modified_csr = cmputils.modify_csr_cn(csr, new_cn="Hans MusterMann")

        # Verify the signature of the modified CSR
        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            verifying_utils.verify_csr_signature(modified_csr, key.public_key())

