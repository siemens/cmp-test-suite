# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import XMSSMTPrivateKey, XMSSPrivateKey
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import get_all_xmss_xmssmt_keys


class TestXMSSAndXMSSMTKeyLoadingFile(unittest.TestCase):
    def test_xmss_key_loading_file(self):
        """
        GIVEN all XMSS keys.
        WHEN loading each key from file,
        THEN the key is loaded successfully and matches the expected algorithm name.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test loading each key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if alg_name.startswith("xmssmt-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                self.assertEqual(private_key.name, alg_name, f"Key name mismatch for {alg_name}")

    def test_xmss_key_derivation(self):
        """
        GIVEN all XMSS keys.
        WHEN loading each key from file with only the private key bytes,
        THEN the derived public key matches the original public key.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test loading each XMSS key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if not alg_name.startswith("xmss-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                self.assertEqual(private_key.name, alg_name, f"Key name mismatch for {alg_name}")
                private_key_bytes = private_key.private_bytes_raw()
                loaded_private_key = XMSSPrivateKey(private_key.name, private_key_bytes)
                self.assertEqual(private_key.public_key(), loaded_private_key.public_key())

    def test_xmssmt_key_loading_file(self):
        """
        GIVEN all XMSSMT keys.
        WHEN loading each key from file,
        THEN the key is loaded successfully and matches the expected algorithm name.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test loading each XMSSMT key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if not alg_name.startswith("xmssmt-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                self.assertEqual(private_key.name, alg_name, f"Key name mismatch for {alg_name}")

    def test_xmssmt_key_derivation(self):
        """
        GIVEN all XMSSMT keys.
        WHEN loading each key from file with only the private key bytes,
        THEN the derived public key matches the original public key.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test loading each XMSSMT key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if not alg_name.startswith("xmssmt-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                self.assertEqual(private_key.name, alg_name, f"Key name mismatch for {alg_name}")
                private_key_bytes = private_key.private_bytes_raw()
                loaded_private_key = XMSSMTPrivateKey(private_key.name, private_key_bytes)
                self.assertEqual(
                    private_key.public_key(),
                    loaded_private_key.public_key(),
                    f"name: {loaded_private_key.name} {private_key.name},\n"
                    f"private_key: {private_key.public_key().public_bytes_raw().hex()},\n"
                    f"loaded_private_key: {loaded_private_key.public_key().public_bytes_raw().hex()}",
                )

    def test_xmss_attribute_access(self):
        """
        GIVEN an XMSS key.
        WHEN accessing attributes,
        THEN the attributes are accessible and match expected values.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test accessing attributes of each XMSS key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if not alg_name.startswith("xmss-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                private_key: XMSSPrivateKey
                _ = private_key.private_bytes_raw()
                _ = private_key.public_key().public_bytes_raw()
                _ = private_key.name
                _ = private_key.public_key().name
                length_private = private_key.key_size
                length_public = private_key.public_key().key_size
                self.assertNotEqual(length_private, length_public)
                self.assertGreater(length_private, 0, "Private key length should be greater than 0")
                self.assertGreater(length_public, 0, "Public key length should be greater than 0")
                self.assertEqual(
                    private_key.max_sig_size,
                    private_key.public_key().max_sig_size,
                    "Max signature size should be equal for private and public keys",
                )
                used_keys = private_key.used_keys
                self.assertIsInstance(used_keys, list, "Used keys should be a list")
                _ = private_key.sigs_remaining

    def test_xmssmt_attribute_access(self):
        """
        GIVEN an XMSSMT key.
        WHEN accessing attributes,
        THEN the attributes are accessible and match expected values.
        """
        # Load all XMSS and XMSSMT keys
        keys = get_all_xmss_xmssmt_keys()

        # Test accessing attributes of each XMSSMT key
        for alg_name, key_path in keys.items():
            alg_name = alg_name.lower()
            if not alg_name.startswith("xmssmt-"):
                continue

            with self.subTest(alg_name=alg_name):
                private_key = load_private_key_from_file(key_path)
                private_key: XMSSMTPrivateKey
                _ = private_key.private_bytes_raw()
                _ = private_key.public_key().public_bytes_raw()
                _ = private_key.name
                _ = private_key.public_key().name
                length_private = private_key.key_size
                length_public = private_key.public_key().key_size
                self.assertNotEqual(length_private, length_public)
                self.assertGreater(length_private, 0, "Private key length should be greater than 0")
                self.assertGreater(length_public, 0, "Public key length should be greater than 0")
                self.assertEqual(
                    private_key.max_sig_size,
                    private_key.public_key().max_sig_size,
                    "Max signature size should be equal for private and public keys",
                )
                used_keys = private_key.used_keys
                self.assertIsInstance(used_keys, list, "Used keys should be a list")
                _ = private_key.sigs_remaining


if __name__ == "__main__":
    unittest.main()
