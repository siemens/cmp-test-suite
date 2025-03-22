# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate, prepare_extensions
from resources.certutils import parse_certificate, validate_cmp_extended_key_usage
from resources.suiteenums import KeyUsageStrictness
from resources.utils import load_and_decode_pem_file

from unit_tests.utils_for_test import prepare_cert_for_extensions


class TestValidateCMPExtendedKeyUsage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cert_no_usage = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

    def test_validate_correct_ext_key_usage(self):
        """
        GIVEN a certificate with the "cmcRA" extended key usage
        WHEN `validate_key_usage` is called with strictness=STRICT and key_usages="cmcRA"
        THEN the validation should pass without any errors
        """
        cert = prepare_cert_for_extensions(prepare_extensions(eku="cmcRA"))
        try:
            validate_cmp_extended_key_usage(
                cert=cert, strictness=KeyUsageStrictness.STRICT.value, ext_key_usages="cmcRA"
            )
        except ValueError as e:
            self.fail(f"validate_key_usage raised ValueError unexpectedly: {e}")

    def test_validate_incorrect_eku(self):
        """
        GIVEN a certificate with a different extended key usage attribute ("cmcCA")
        WHEN `validate_key_usage` is called with strictness "LAX"
        THEN a ValueError should be raised indicating the key usage is invalid
        """
        cert_different = prepare_cert_for_extensions(prepare_extensions(eku="cmcCA"))
        with self.assertRaises(ValueError):
            validate_cmp_extended_key_usage(cert=cert_different, strictness="LAX", ext_key_usages="cmcRA")

    def test_validate_no_ext_key_usage_extension(self):
        """
        GIVEN a certificate without the `ExtendedKeyUsage` extension
        WHEN `validate_key_usage` is called with strictness "STRICT"
        THEN a ValueError should be raised indicating the KeyUsage extension is missing
        """
        cert_no_usage, _ = build_certificate()
        with self.assertRaises(ValueError):
            validate_cmp_extended_key_usage(cert=cert_no_usage, strictness="STRICT", ext_key_usages="cmcRA")

    def test_validate_ext_key_usage_extension_more_set(self):
        """
        GIVEN a certificate with the `ExtendedKeyUsage` extension
        WHEN `validate_key_usage` is called with "STRICT" and "LAX"
        THEN the validation should pass without any errors.
        """
        cert_more_set = prepare_cert_for_extensions(prepare_extensions(eku="cmcRA,cmcCA"))
        validate_cmp_extended_key_usage(cert=cert_more_set, strictness="STRICT", ext_key_usages="cmcRA")
        validate_cmp_extended_key_usage(cert=cert_more_set, strictness="LAX", ext_key_usages="cmcRA")

    def test_validate_with_strictness_none(self):
        """
        GIVEN a certificate without a `ExtendedKeyUsage` extension
        WHEN `validate_key_usage` is called with strictness "NONE"
        THEN the validation should pass without any errors
        """
        validate_cmp_extended_key_usage(cert=self.cert_no_usage, strictness="NONE", ext_key_usages="caKGA")


if __name__ == "__main__":
    unittest.main()
