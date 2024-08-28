import unittest
from resources import errorutils
from resources.cryptoutils import generate_csr, sign_csr, generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
from cryptography import x509


class TestUtils(unittest.TestCase):
    def test_verification_fails(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        :return: None
        """
        # Generate a new RSA key pair with a 2048-bit length
        private_key = generate_rsa_keypair(length=2048)

        # Generate a CSR with a specified common name (CN)
        csr = generate_csr(
            common_name="C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann"
        )

        # Sign the generated CSR with the private key
        csr_signed = sign_csr(csr, private_key)

        # Convert the signed CSR from PEM to DER format (binary format)
        der_data = x509.load_pem_x509_csr(csr_signed).public_bytes(
            serialization.Encoding.DER
        )

        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        modified_csr = errorutils.modify_csr_cn(der_data, new_cn="Hans MusterMann")

        # Verify the signature of the modified CSR
        is_valid = errorutils.verify_csr_signature(modified_csr)

        # Assert that the signature verification fails (returns False)
        self.assertEqual(False, is_valid)
