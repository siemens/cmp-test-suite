# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.cmputils import build_cmp_error_message, verify_statusstring


class TestVerifyStatusText(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_message = build_cmp_error_message(texts="This is a sample status text")


    def test_any_text_success(self):
        """
        GIVEN a `PKIMessage` containing specific text
        WHEN verify_statusstring is called with any_text containing "sample" or "random"
        THEN the verification should pass, as "sample" is found in the status text.
        """
        verify_statusstring(self.pki_message, any_text="sample,random", must_be_present=True)

    def test_any_text_failure(self):
        """
        GIVEN a `PKIMessage` with a specific text
        WHEN verify_statusstring is called with any_text set to "not" or "here"
        THEN the verification should fail, raising a ValueError, as neither word is in the status text.
        """
        with self.assertRaises(ValueError):
            verify_statusstring(self.pki_message, any_text="not,here", must_be_present=True)

    def test_all_text_success(self):
        """
        GIVEN a `PKIMessage` containing multiple words
        WHEN verify_statusstring is called with all_text containing "sample" and "status"
        THEN the verification should pass, as both words are present in the status text.
        """
        verify_statusstring(self.pki_message, all_text="sample,status", must_be_present=True)

    def test_all_text_failure(self):
        """
        GIVEN a `PKIMessage` with a specific text
        WHEN verify_statusstring is called with all_text set to "sample" and "missing"
        THEN the verification should fail, raising a ValueError, as "missing" is not in the status text.
        """
        with self.assertRaises(ValueError):
            verify_statusstring(self.pki_message, all_text="sample,missing", must_be_present=True)

    def test_both_conditions_success(self):
        """
        GIVEN a `PKIMessage` containing multiple words
        WHEN verify_statusstring is called with both any_text containing "sample" or "random" and
        all_text with "status" and "text"
        THEN the verification should pass, as all specified conditions are met in the status text.
        """
        verify_statusstring(self.pki_message, any_text="sample,random", all_text="status,text", must_be_present=True)

    def test_both_conditions_failure_any(self):
        """
        GIVEN a `PKIMessage` containing specific words
        WHEN verify_statusstring is called with any_text containing "random" or "missing" and all_text containing
        "status" and "text"
        THEN the verification should fail, raising a ValueError, as neither "random" nor "missing" is in
        the status text.
        """
        with self.assertRaises(ValueError):
            verify_statusstring(
                self.pki_message, any_text="random,missing", all_text="status,text", must_be_present=True
            )


if __name__ == "__main__":
    unittest.main()
