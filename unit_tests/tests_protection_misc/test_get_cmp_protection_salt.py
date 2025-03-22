# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.keyutils import load_private_key_from_file
from resources.protectionutils import get_cmp_protection_salt, protect_pkimessage

from unit_tests.utils_for_test import build_pkimessage, de_and_encode_pkimessage


class TestPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        private_key = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        cls.pki_message = build_pkimessage(body_type="cr", private_key=private_key)
        cls.private_key = private_key
        cls.PASSWORD = bytes.fromhex("AA" * 32)
        cls.SALT = bytes.fromhex("AA" * 16)

    def test_get_salt_password_based_mac(self):
        """
        GIVEN a Protected PKIMessage and a password, salt for Password-Based MAC protection.
        WHEN `get_cmp_protection_salt` is called,
        THEN salt value should be able to be extracted and equal to the provided salt.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="password_based_mac", password=self.PASSWORD, salt=self.SALT
        )
        salt = get_cmp_protection_salt(protected_msg["header"]["protectionAlg"])
        self.assertEqual(salt, self.SALT)

    def test_get_salt_password_based_mac_decoded_message(self):
        """
        GIVEN a Protected PKIMessage and a password, salt for Password-Based MAC protection.
        WHEN `get_cmp_protection_salt` is called on an en-decoded `PKIMessage`
        THEN salt value should be able to be extracted and equal to the provided salt.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="password_based_mac", password=self.PASSWORD, salt=self.SALT
        )
        protected_msg = de_and_encode_pkimessage(protected_msg)
        salt = get_cmp_protection_salt(protected_msg["header"]["protectionAlg"])
        self.assertEqual(salt, self.SALT)

    def test_get_pbmac1(self):
        """
        GIVEN a Protected PKIMessage and a password, salt for Password-Based MAC protection.
        WHEN `get_cmp_protection_salt` is called,
        THEN salt value should be able to be extracted and equal to the provided salt.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="pbmac1", password=self.PASSWORD, salt=self.SALT
        )
        salt = get_cmp_protection_salt(protected_msg["header"]["protectionAlg"])
        self.assertEqual(salt, self.SALT)

    def test_get_pbmac1_decoded_message(self):
        """
        GIVEN a Protected PKIMessage and a password, salt for Password-Based MAC protection.
        WHEN `get_cmp_protection_salt` is called on an en-decoded `PKIMessage`
        THEN salt value should be able to be extracted and equal to the provided salt.
        """
        protected_msg = protect_pkimessage(
            pki_message=self.pki_message, protection="pbmac1", password=self.PASSWORD, salt=self.SALT
        )
        protected_msg = de_and_encode_pkimessage(protected_msg)
        salt = get_cmp_protection_salt(protected_msg["header"]["protectionAlg"])
        self.assertEqual(salt, self.SALT)
