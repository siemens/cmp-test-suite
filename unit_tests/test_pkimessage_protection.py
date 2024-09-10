import unittest

from protectionutils import protect_pki_message, verify_pki_protection
from resources.cmputils import prepare_extra_certs, build_p10cr_from_csr, parse_csr
from resources.cryptoutils import generate_signed_csr, generate_certificate
from resources.utils import decode_pem_string

from keyutils import generate_key, load_private_key_from_file, save_key

PASSWORD = bytes.fromhex("AA" * 32)

class TestPKIMessageProtection(unittest.TestCase):

    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)

        cls.pki_message = pki_message
        cls.private_key = private_key


    def test_hmac_protection(self):
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            protection="hmac",
                                            password=PASSWORD)

        verify_pki_protection(pki_message=protected_msg, password=PASSWORD)


    def test_gmac_protection(self):
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            protection="aes-gmac",
                                            password=PASSWORD)

        verify_pki_protection(pki_message=protected_msg, password=PASSWORD)



    def test_password_based_mac_protection(self):
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            protection="password_based_mac",
                                            password=PASSWORD)

        verify_pki_protection(pki_message=protected_msg, password=PASSWORD)


    def test_pbmac1_protection(self):
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            protection="pbmac1",
                                            password=PASSWORD)

        verify_pki_protection(pki_message=protected_msg, password=PASSWORD)


    def test_sig_rsa(self):
        private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        certificate = generate_certificate(private_key=private_key, common_name="CN=Hans", hash_alg="sha256")
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            certificate=certificate,
                                            private_key=private_key,
                                            protection="signature",
                                            password=None)

        verify_pki_protection(pki_message=protected_msg, private_key=private_key)

    def test_sig_ed25519(self):

        private_key =  load_private_key_from_file("data/keys/private-key-ed25519.raw", "ed25519")

        certificate = generate_certificate(private_key=private_key,
                                           common_name="CN=Hans",
                                           hash_alg=None)

        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            certificate=certificate,
                                            private_key=private_key,
                                            protection="signature",
                                            password=None)


        verify_pki_protection(pki_message=protected_msg, private_key=private_key)


    def test_sig_ecdsa(self):
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        certificate = generate_certificate(private_key=private_key,
                                           common_name="CN=Hans",
                                           hash_alg="sha256")
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            certificate=certificate,
                                            private_key=private_key,
                                            protection="signature",
                                            password=None)

        # verifies with self-signed certificate, generate inside apply_pki_ if not provided.
        verify_pki_protection(pki_message=protected_msg, private_key=None)

    def test_sig_ecdsa_without_cert(self):
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            certificate=None,
                                            private_key=private_key,
                                            protection="signature",
                                            password=None)

        # verifies with self-signed certificate, generate inside apply_pki_ if not provided.
        verify_pki_protection(pki_message=protected_msg, private_key=None)


    def test_dh_based_sig(self):
        client_private_key = load_private_key_from_file("data/keys/client_dh_key.pem")


        protected_msg = protect_pki_message(pki_message=self.pki_message,
                                            certificate=None,
                                            private_key=client_private_key,
                                            protection="dh",
                                            password="dhbasedmac",
                                            )

        #verify_pki_protection(pki_message=protected_msg, private_key=client_private_key.public_key(), password="dhbasedmac")

