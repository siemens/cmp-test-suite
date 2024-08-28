import unittest

import cryptography.exceptions

import pycrypto_utils.verifying_utils
from resources import modifyutils
from resources.cryptoutils import generate_csr, sign_csr, generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from resources.utils import load_and_decode_pem_file

class TestUtils(unittest.TestCase):
    def test_verification_fails(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        :return: None
        """

        csr = generate_csr("Hans Mustermann")


        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        modified_csr = modifyutils.modify_csr_cn(der_data, new_cn="Hans MusterMann")

        # Verify the signature of the modified CSR
        self.assertRaises(pycrypto_utils.verifying_utils.verify_csr_signature(modified_csr), cryptography.exceptions.InvalidSignature)
