import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import certutils
from cmputils import encode_to_der
from resources.certutils import parse_certificate
from resources.cmputils import prepare_extra_certs, build_p10cr_from_csr, parse_csr
from resources.cryptoutils import generate_signed_csr, generate_certificate
from resources.protectionutils import add_cert_to_pkimessage_used_by_protection
from resources.utils import decode_pem_string

from keyutils import generate_key


class TestPrepareCertPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)

        # a `cryptography.x509.Certificate` object
        cls.certificate_crypto_lib = generate_certificate(private_key=private_key, common_name="CN=Hans")
        cls.pki_message = pki_message
        cls.private_key = private_key

    def test_without_certificate_and_empty_extraCerts(self):
        """Test if a Certificate can be created with a `cryptography` PrivateKey
        and then if the Certificate can be added to a `pyasn1 rfc9480.PKIMessage`.
        """
        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, certificate=None)

        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)


    def test_with_certificate_and_empty_extraCerts(self):
        """Test if a provided Certificate can be added to a `pyasn1 rfc9480.PKIMessage`,which is used for the Protection."""
        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, self.certificate_crypto_lib)
        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(len(self.pki_message["extraCerts"]) == 1)

        raw = self.certificate_crypto_lib.public_bytes(serialization.Encoding.DER)
        certificate = certutils.parse_certificate(raw)

        self.assertEqual(self.pki_message["extraCerts"][0], certificate)


    def test_with_certificate_and_same_extraCerts(self):
        """check if the same certificate is present in the structure more than once."""
        self.assertTrue(len(self.pki_message["extraCerts"]) == 0)
        raw = self.certificate_crypto_lib.public_bytes(serialization.Encoding.DER)
        certificate = parse_certificate(raw)
        self.pki_message["extraCerts"] = prepare_extra_certs([certificate])

        add_cert_to_pkimessage_used_by_protection(self.pki_message, self.private_key, certificate=self.certificate_crypto_lib)

        self.assertTrue(self.pki_message["extraCerts"].hasValue())
        self.assertTrue(
            len(self.pki_message["extraCerts"]) == 1,
            f"Length of PKIMessage ExtraCerts is : {len(self.pki_message['extraCerts'])}",
        )

        der_cert = encode_to_der((self.pki_message['extraCerts'][0]))
        first_cert = x509.load_der_x509_certificate(der_cert)

        self.assertEqual(self.certificate_crypto_lib, first_cert)


    def test_extraCerts_and_wrong_private_key(self):
        """Check if a new certificate is generated, if a different Private Key is provided."""
        raw = self.certificate_crypto_lib.public_bytes(serialization.Encoding.DER)
        certificate = parse_certificate(raw)
        self.pki_message["extraCerts"] = prepare_extra_certs([certificate])

        # Generate a new key so that the public key of the
        # certificate does not match the private key.
        private_key = generate_key()


        # because it did not find a matching Certificate.
        with (self.assertRaises(ValueError)):
            add_cert_to_pkimessage_used_by_protection(self.pki_message, private_key, certificate=None)


if __name__ == "__main__":
    unittest.main()
