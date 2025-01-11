# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import check_protection_alg_field
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import patch_protectionalg, protect_pkimessage

from unit_tests.utils_for_test import build_pkimessage


class TestCheckProtectionAlgField(unittest.TestCase):
    @classmethod
    def setUp(cls):
        """Set up a valid PKI message for both signature-based and MAC-based protection."""
        cls.private_key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")

        cls.sig_pki_message = build_pkimessage()
        cls.mac_pki_message = build_pkimessage()
        cls.unprotected_pki_message = build_pkimessage()

        cls.sig_protected_message = protect_pkimessage(
            pki_message=cls.sig_pki_message, private_key=cls.private_key, protection="signature"
        )
        cls.mac_protected_message = protect_pkimessage(
            pki_message=cls.mac_pki_message, password="test_password", protection="pbmac1"
        )

    def test_valid_signature_based_protection(self):
        """
        GIVEN a PKI message with signature-based protection
        WHEN check_protectionAlg_field is called with expected_type='sig'
        THEN the check should pass without raising any exceptions.
        """
        check_protection_alg_field(pki_message=self.sig_protected_message, expected_type="sig", must_be_protected=False)

    def test_valid_signature_based_protection_must_be_present(self):
        """
        GIVEN a PKI message with signature-based protection
        WHEN check_protectionAlg_field is called with expected_type='sig'
        THEN the check should pass without raising any exceptions.
        """
        check_protection_alg_field(pki_message=self.sig_protected_message, expected_type="sig", must_be_protected=True)

    def test_mac_based_protection(self):
        """
        GIVEN a PKI message with MAC-based protection
        WHEN check_protectionAlg_field is called with expected_type='mac'
        THEN the check should pass without raising any exceptions.
        """
        check_protection_alg_field(pki_message=self.mac_protected_message, expected_type="mac", must_be_protected=True)

        check_protection_alg_field(pki_message=self.mac_protected_message, expected_type="mac")

    def test_protectionAlg_not_matching_expected_type(self):
        """
        GIVEN a PKI message with signature-based protection
        WHEN check_protectionAlg_field is called with expected_type='mac'
        THEN it should raise a ValueError due to mismatched protection type.
        """
        with self.assertRaises(ValueError):
            check_protection_alg_field(
                pki_message=self.sig_protected_message, expected_type="mac", must_be_protected=True
            )

        with self.assertRaises(ValueError):
            check_protection_alg_field(
                pki_message=self.mac_protected_message, expected_type="sig", must_be_protected=True
            )

    def test_protectionAlg_not_present(self):
        """
        GIVEN a PKI message with no protectionAlg field present
        WHEN check_protectionAlg_field is called with must_be_present=False
        THEN the check should pass without raising any exceptions.
        """
        check_protection_alg_field(pki_message=self.unprotected_pki_message, must_be_protected=False)

    def test_protectionAlg_not_present_but_expected(self):
        """
        GIVEN a PKI message with no protectionAlg field present
        WHEN check_protectionAlg_field is called with must_be_present=True
        THEN the check should raise an exceptions.
        """
        with self.assertRaises(ValueError):
            check_protection_alg_field(pki_message=self.unprotected_pki_message, expected_type="sig")

        with self.assertRaises(ValueError):
            check_protection_alg_field(pki_message=self.unprotected_pki_message, expected_type="mac")

    def test_inconsistent_protectionAlg_and_subjectPublicKeyInfo(self):
        """
        GIVEN a PKI message with inconsistent protectionAlg and subjectPublicKeyInfo
        WHEN check_protectionAlg_field is called
        THEN it should raise a ValueError due to inconsistency.
        """
        protected_message = protect_pkimessage(
            pki_message=self.unprotected_pki_message, private_key=self.private_key, protection="signature"
        )

        protected_message = patch_protectionalg(
            protected_message, protection="signature", private_key=generate_key("ecdsa")
        )

        with self.assertRaises(ValueError):
            check_protection_alg_field(pki_message=protected_message)


if __name__ == "__main__":
    unittest.main()
