import unittest

import cryptography.exceptions

import cmputils
import crypto_utils.verifying_utils
from crypto_utils.cert_utils import generate_fresh_csr


class TestUtils(unittest.TestCase):
    def test_verification_fails(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        :return: None
        """

        csr, key = generate_fresh_csr(common_name="CN=Hans", key=None)

        #verify if the certificate is correct
        crypto_utils.verifying_utils.verify_csr_signature(csr, key.public_key())
        crypto_utils.verifying_utils.verify_csr_signature(csr, None)

        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        modified_csr = cmputils.modify_csr_cn(csr, new_cn="Hans MusterMann")

        # Verify the signature of the modified CSR
        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            crypto_utils.verifying_utils.verify_csr_signature(modified_csr, key.public_key())

