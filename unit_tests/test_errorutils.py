import unittest

import cryptography.exceptions
from pyasn1_alt_modules.rfc2459 import common_name

import pycrypto_utils.verifying_utils
from pycrypto_utils.cert_utils import generate_fresh_csr
from pycrypto_utils.load_key_utils import load_rsa_key
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

        csr, key = generate_fresh_csr(common_name="CN=Hans", key=None)

        #verify if the certificate is correct
        pycrypto_utils.verifying_utils.verify_csr_signature(csr, key.public_key())
        pycrypto_utils.verifying_utils.verify_csr_signature(csr, None)

        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        modified_csr = modifyutils.modify_csr_cn(csr, new_cn="Hans MusterMann")

        # Verify the signature of the modified CSR
        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            pycrypto_utils.verifying_utils.verify_csr_signature(modified_csr, key.public_key())

