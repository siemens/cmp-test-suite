# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.protectionutils import modify_pkimessage_protection, protect_pkimessage

from unit_tests.utils_for_test import build_pkimessage


class TestPatchPKIMessageProtection(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.pki_message = build_pkimessage()
        cls.protected_pki_message = protect_pkimessage(build_pkimessage(), protection="hmac", password=b"TEST PASSWORD")

    def test_patch_pkimessage_protection_wrong_value(self):
        """
        GIVEN a protected `PKIMessage`
        WHEN patch_pkimessage_protection is called with `wrong_type="modify_value"`
        THEN the patched message's protection value should differ from the original protection signature.
        """
        sig_before = self.protected_pki_message["protection"].asOctets()
        patched_message = modify_pkimessage_protection(self.protected_pki_message)
        self.assertNotEqual(patched_message["protection"].asOctets(), sig_before)

if __name__ == "__main__":
    unittest.main()
