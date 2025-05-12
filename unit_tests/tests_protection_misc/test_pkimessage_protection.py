# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import generate_certificate
from resources.exceptions import BadMacProtection
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage, verify_pkimessage_protection

from unit_tests.utils_for_test import build_pkimessage, de_and_encode_pkimessage

PASSWORD = bytes.fromhex("AA" * 32)
INVALID_PASSWORD = bytes.fromhex("AA" * 31 + "AB")


class TestPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.pki_message = build_pkimessage()


    def test_hmac_protection(self):
        """
        GIVEN a PKIMessage and a password for HMAC protection.
        WHEN the PKIMessage is protected using HMAC.
        THEN the HMAC verification should succeed without any exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="hmac", password=PASSWORD)
        verify_pkimessage_protection(pki_message=protected_msg, password=PASSWORD)

    def test_hmac_protection_and_verify_different_password(self):
        """
        GIVEN a PKIMessage and a password for HMAC protection.
        WHEN the PKIMessage is protected using HMAC.
        and the verification is called with a different password,
        THEN the HMAC verification should raise a ValueError exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="hmac", password=PASSWORD)
        with self.assertRaises(BadMacProtection):
            verify_pkimessage_protection(pki_message=protected_msg, password=INVALID_PASSWORD)

    def test_kmac_protection(self):
        """
        GIVEN a PKIMessage and a password for KMAC protection.
        WHEN the PKIMessage is protected using KMAC.
        THEN the KMAC verification should succeed without any exceptions.
        """
        try:
            from Crypto.Hash import KMAC128, KMAC256
        except ImportError:
            return

        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="kmac", password=PASSWORD)
        verify_pkimessage_protection(pki_message=protected_msg, password=PASSWORD)

    def test_kmac_protection_and_verify_different_password(self):
        """
        GIVEN a PKIMessage and a password for KMAC protection.
        WHEN the PKIMessage is protected using KMAC.
        and the verification is called with a different password,
        THEN the KMAC verification should raise a ValueError exceptions.
        """
        try:
            from Crypto.Hash import KMAC128, KMAC256
        except ImportError:
            return

        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="kmac", password=PASSWORD)
        with self.assertRaises(BadMacProtection):
            verify_pkimessage_protection(pki_message=protected_msg, password=INVALID_PASSWORD)

    def test_gmac_protection(self):
        """
        GIVEN a PKIMessage and a password for AES-GMAC protection.
        WHEN the PKIMessage is protected using AES-GMAC.
        THEN the GMAC verification should succeed without any exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="aes-gmac", password=PASSWORD)
        verify_pkimessage_protection(pki_message=protected_msg, password=PASSWORD)

    def test_gmac_protection_and_verify_different_password(self):
        """
        GIVEN a PKIMessage and a password for AES-GMAC protection.
        WHEN the PKIMessage is protected using AES-GMAC.
        and the verification is called with a different password,
        THEN the GMAC verification should raise a ValueError exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="aes-gmac", password=PASSWORD)
        with self.assertRaises(BadMacProtection):
            verify_pkimessage_protection(pki_message=protected_msg, password=INVALID_PASSWORD)

    def test_password_based_mac_protection(self):
        """
        GIVEN a PKIMessage and a password for Password-Based MAC protection.
        WHEN the PKIMessage is protected using Password-Based MAC.
        THEN the Password-Based MAC verification should succeed without any exceptions.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="password_based_mac", password=PASSWORD
        )
        verify_pkimessage_protection(pki_message=protected_msg, password=PASSWORD)

    def test_password_based_mac_protection_and_verify_different_password(self):
        """
        GIVEN a PKIMessage and a password for Password-Based MAC protection.
        WHEN the PKIMessage is protected using Password-Based MAC
        and the verification is called with a different password,
        THEN the Password-Based MAC verification should raise a ValueError exceptions.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="password_based_mac", password=PASSWORD
        )
        with self.assertRaises(BadMacProtection):
            verify_pkimessage_protection(pki_message=protected_msg, password=INVALID_PASSWORD)

    def test_pbmac1_protection(self):
        """
        GIVEN a PKIMessage and a password for PBMAC1 protection.
        WHEN the PKIMessage is protected using PBMAC1.
        THEN the PBMAC1 verification should succeed without any exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="pbmac1", password=PASSWORD)
        verify_pkimessage_protection(pki_message=protected_msg, password=PASSWORD)

    def test_pbmac1_based_mac_protection_and_verify_different_password(self):
        """
        GIVEN a PKIMessage and a password for PBMAC1 protection.
        WHEN the PKIMessage is protected using PBMAC1
        and the verification is called with a different password,
        THEN the PBMAC1 verification should raise a ValueError exceptions.
        """
        protected_msg = protect_pkimessage(pki_message=self.pki_message, protection="pbmac1", password=PASSWORD)
        with self.assertRaises(BadMacProtection):
            verify_pkimessage_protection(pki_message=protected_msg, password=INVALID_PASSWORD)

    def test_sig_rsa(self):
        """
        GIVEN a PKIMessage, an RSA private key, and a corresponding certificate.
        WHEN the PKIMessage is protected using an RSA signature.
        THEN the RSA signature verification should succeed without any exceptions.
        """
        private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        certificate = generate_certificate(private_key=private_key, common_name="CN=Hans", hash_alg="sha256")
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=certificate,
            private_key=private_key,
            protection="signature",
            password=None,
        )
        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, private_key=private_key)

    def test_sig_ed25519(self):
        """
        GIVEN a PKIMessage, an Ed25519 private key, and a corresponding certificate.
        WHEN the PKIMessage is protected using an Ed25519 signature.
        THEN the Ed25519 signature verification should succeed without any exceptions.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")

        certificate = generate_certificate(private_key=private_key, common_name="CN=Hans", hash_alg=None)

        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=certificate,
            private_key=private_key,
            protection="signature",
            password=None,
        )

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, private_key=private_key)

    def test_sig_ecdsa(self):
        """
        GIVEN a PKIMessage, an ECDSA private key, and a corresponding certificate.
        WHEN the PKIMessage is protected using an ECDSA signature.
        THEN the ECDSA signature verification should succeed without any exceptions.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        certificate = generate_certificate(private_key=private_key, common_name="CN=Hans", hash_alg="sha256")
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=certificate,
            private_key=private_key,
            protection="signature",
            password=None,
        )

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, private_key=None)

    def test_sig_ecdsa_without_cert(self):
        """
        GIVEN a PKIMessage and an ECDSA private key without a certificate.
        WHEN the PKIMessage is protected using an ECDSA signature.
        THEN the ECDSA signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
        )

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, private_key=None)

    def test_sig_ecdsa_with_shake128_without_cert(self):
        """
        GIVEN a PKIMessage and an ECDSA private key without a certificate.
        WHEN the PKIMessage is protected using an ECDSA signature with shake128 algorithm.
        THEN the ECDSA signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
            hash_alg="shake256",
        )

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg)

    def test_sig_ecdsa_with_shake256_without_cert(self):
        """
        GIVEN a PKIMessage and an ECDSA private key without a certificate.
        WHEN the PKIMessage is protected using an ECDSA signature with shake256 algorithm.
        THEN the ECDSA signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="signature",
            password=None,
            hash_alg="shake256",
        )

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg)

    def test_sig_rsassa_pss_without_cert(self):
        """
        GIVEN a PKIMessage and an RSA private key without a certificate.
        WHEN the PKIMessage is protected using an RSASSA-PSS signature with sha256 algorithm.
        THEN the RSASSA-PSS signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="rsassa-pss",
            password=None,
            hash_alg="sha256",
        )
        # simulate over wire. because expects the `parameters` field to be un-decoded.
        protected_msg = de_and_encode_pkimessage(pki_message=protected_msg)

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, public_key=private_key.public_key())

    def test_sig_rsassa_pss_shake128_without_cert(self):
        """
        GIVEN a PKIMessage and an RSA private key without a certificate.
        WHEN the PKIMessage is protected using an RSASSA-PSS signature with shake128 algorithm.
        THEN the RSASSA-PSS signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="rsassa-pss",
            password=None,
            hash_alg="shake128",
        )
        # simulate over wire. because expects the `parameters` field to be un-decoded.
        protected_msg = de_and_encode_pkimessage(pki_message=protected_msg)

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, public_key=private_key.public_key())

    def test_sig_rsassa_pss_shake256_without_cert(self):
        """
        GIVEN a PKIMessage and an RSA private key without a certificate.
        WHEN the PKIMessage is protected using an RSASSA-PSS signature with shake256 algorithm.
        THEN the RSASSA-PSS signature verification should succeed with a self-signed certificate.
        """
        private_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message,
            cert=None,
            private_key=private_key,
            protection="rsassa-pss",
            password=None,
            hash_alg="shake256",
        )
        # simulate over wire. because expects the `parameters` field to be un-decoded.
        protected_msg = de_and_encode_pkimessage(pki_message=protected_msg)

        # verifies with self-signed certificate, generated inside if not provided.
        verify_pkimessage_protection(pki_message=protected_msg, public_key=private_key.public_key())
