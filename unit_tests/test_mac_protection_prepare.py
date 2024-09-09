import unittest
from cryptography.hazmat.primitives import serialization
from resources.certutils import parse_certificate
from resources.cmputils import _prepare_extra_certs, build_p10cr_from_csr, parse_csr
from resources.cryptoutils import generate_signed_csr, generate_cert_from_private_key
from resources.mac_protection import _apply_cert_pkimessage_protection
from resources.utils import decode_pem_string

from keyutils import generate_key


class TestPrepareCertPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)

        cls.certificate_crypto = generate_cert_from_private_key(private_key=private_key, common_name="CN=Hans")
        cls.pki_message = pki_message
        cls.private_key = private_key

    def test_without_certificate_and_empty_extraCerts(self):
        """Test if a Certificate can be created with a `cryptography` PrivateKey
        and then if the Certificate can be added to a `pyasn1 rfc9480.PKIMessage`.
        """
        _apply_cert_pkimessage_protection(self.pki_message, self.private_key, certificate=None)

        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)

    def test_with_certificate_and_empty_extraCerts(self):
        """Test if a provided Certificate can be added to a `pyasn1 rfc9480.PKIMessage`,which is used for the Protection."""
        _apply_cert_pkimessage_protection(self.pki_message, self.private_key, self.certificate_crypto)
        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)

    def test_with_certificate_and_same_extraCerts(self):
        """Checks if a certificate is already present in the "extraCerts" field.
        Ensures that if the certificate is already included, it is not added again.
        """
        self.assertTrue(len(self.pki_message["extraCerts"]) == 0)
        raw = self.certificate_crypto.public_bytes(serialization.Encoding.DER)
        certificate = parse_certificate(raw)
        self.pki_message["extraCerts"] = _prepare_extra_certs([certificate])

        _apply_cert_pkimessage_protection(self.pki_message, self.private_key, certificate=self.certificate_crypto)

        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(
            len(self.pki_message["extraCerts"]) == 1,
            f"Length of PKIMessage ExtraCerts is : {len(self.pki_message['extraCerts'])}",
        )

    def test_extraCerts_and_wrong_private_key(self):
        """Check if a new certificate is generated, if a different Private Key is provided."""
        raw = self.certificate_crypto.public_bytes(serialization.Encoding.DER)
        certificate = parse_certificate(raw)
        self.pki_message["extraCerts"] = _prepare_extra_certs([certificate])

        # Generate a new key so that the public key of the
        # certificate does not match the private key.
        private_key = generate_key()

        _apply_cert_pkimessage_protection(self.pki_message, private_key, certificate=None)

        # because it did not find a matching Certificate.
        self.assertTrue(len(self.pki_message["extraCerts"]) == 2)


if __name__ == "__main__":
    unittest.main()
