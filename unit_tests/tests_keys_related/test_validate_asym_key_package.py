# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from resources.ca_kga_logic import validate_asymmetric_key_package
from resources.envdatautils import prepare_asymmetric_key_package

from unit_tests.utils_for_test import private_key_to_pkcs8


class TestValidateAsymmetricKeyPackage(unittest.TestCase):

    def test_check_keys_match_inside_one_asym_key_ed_key(self):
        """
        GIVEN a OneAsymmetricKey structure, which contains a ED25519 private key and a public key.
        WHEN validate_asymmetric_key_package is called,
        THEN the function should return the private key.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        asym_one_key = prepare_asymmetric_key_package([key])
        private_key = validate_asymmetric_key_package(asym_key_package=asym_one_key)
        self.assertEqual(key.private_bytes_raw(), private_key.private_bytes_raw())

    def test_check_keys_match_inside_one_asym_key_ec_key(self):
        """
        GIVEN a OneAsymmetricKey structure, which contains a EC private key and a public key.
        WHEN validate_asymmetric_key_package is called,
        THEN the function should return the private key.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        asym_one_key = prepare_asymmetric_key_package([key])
        private_key = validate_asymmetric_key_package(asym_key_package=asym_one_key)
        extracted_key = private_key_to_pkcs8(private_key)
        orig_key = private_key_to_pkcs8(key)
        self.assertEqual(orig_key, extracted_key)

if __name__ == '__main__':
    unittest.main()
