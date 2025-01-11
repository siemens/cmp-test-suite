# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.certutils import validate_key_usage
from resources.suiteenums import KeyUsageStrictness


class TestValidateKeyUsage(unittest.TestCase):
    def setUp(self):
        # Prepare certificates with specific key usages for testing
        cert_valid, _ = build_certificate(ski=True, key_usage="digitalSignature")
        self.cert_valid = cert_valid

        # Certificate with different key usage
        self.cert_different_usage, _ = build_certificate(ski=True, key_usage="keyAgreement")

    def test_validate_correct_usage(self):
        """
        GIVEN a certificate with the "digitalSignature" key usage
        WHEN validate_key_usage is called with strictness=STRICT and key_usages="digitalSignature"
        THEN the validation should pass without any errors
        """
        try:
            validate_key_usage(
                cert=self.cert_valid, strictness=KeyUsageStrictness.STRICT.value, key_usages="digitalSignature"
            )
        except ValueError as e:
            self.fail(f"validate_key_usage raised ValueError unexpectedly: {e}")

    def test_validate_incorrect_usage(self):
        """
        GIVEN a certificate with an incorrect key usage ("keyAgreement")
        WHEN validate_key_usage is called with strictness=LAX and key_usages="digitalSignature"
        THEN a ValueError should be raised indicating the key usage is invalid
        """
        with self.assertRaises(ValueError):
            validate_key_usage(
                cert=self.cert_different_usage, strictness=KeyUsageStrictness.LAX.value, key_usages="digitalSignature"
            )

    def test_validate_no_key_usage_extension(self):
        """
        GIVEN a certificate without a KeyUsage extension
        WHEN validate_key_usage is called with strictness=STRICT and key_usages="digitalSignature"
        THEN a ValueError should be raised indicating the KeyUsage extension is missing
        """
        # Build a certificate without KeyUsage extension
        cert_no_usage, _ = build_certificate(ski=True, key_usage=None)
        with self.assertRaises(ValueError):
            validate_key_usage(
                cert=cert_no_usage, strictness=KeyUsageStrictness.STRICT.value, key_usages="digitalSignature"
            )

    def test_validate_with_strictness_none(self):
        """
        GIVEN a certificate with an incorrect key usage ("keyAgreement")
        WHEN validate_key_usage is called with strictness=NONE and key_usages="digitalSignature"
        THEN the validation should pass without any errors
        """
        validate_key_usage(
            cert=self.cert_different_usage, strictness=KeyUsageStrictness.NONE.value, key_usages="digitalSignature"
        )


if __name__ == "__main__":
    unittest.main()
