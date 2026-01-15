# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import HSSPrivateKey, HSSPublicKey
from pq_logic.keys.pq_stateful_sig_factory import PQStatefulSigFactory
from resources.keyutils import generate_key, load_private_key_from_file
from resources.typingutils import PrivateKey


class TestHSSKeys(unittest.TestCase):
    SHA256_ALG = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"
    SHAKE_ALG = "hss_lms_shake_m24_h5_lmots_shake_n24_w4"
    # TODO fix if the implementation supports it.
    DIFF_HASH_ALG = "hss_lms_shake_m24_h10_lmots_shake_n24_w1"

    def _ensure_hss_private_key(self, key: PrivateKey) -> HSSPrivateKey:
        """Helper to assert and cast a PrivateKey to HSSPrivateKey."""
        self.assertIsInstance(key, HSSPrivateKey)
        return key

    def test_generate_sha256_hss_key_properties(self):
        """
        GIVEN HSS key generation with SHA-256 based algorithm
        WHEN generating a new key,
        THEN the public key properties should match expectations.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        pub = key.public_key()
        self.assertIsInstance(pub, HSSPublicKey)
        self.assertEqual(pub.hash_alg, "sha256")
        self.assertEqual(key.max_sig_size, pub.max_sig_size)

    def test_generate_shake_hss_key_properties(self):
        """
        GIVEN HSS key generation with SHAKE based algorithm
        WHEN generating a new key,
        THEN the public key properties should match expectations.
        """
        key = HSSPrivateKey(self.SHAKE_ALG, levels=2)
        pub = key.public_key()
        self.assertEqual(pub.hash_alg, "shake256")

    def test_factory_supports_hss(self):
        """
        GIVEN the PQStatefulSigFactory
        WHEN querying supported algorithms and generating keys,
        THEN HSS algorithms should be listed and key generation should work as expected.
        """
        algorithms = PQStatefulSigFactory.get_algorithms_by_family()["hss"]
        self.assertIn(self.SHA256_ALG, algorithms)
        generated = PQStatefulSigFactory.generate_pq_stateful_key(self.SHA256_ALG, length=2)
        self._ensure_hss_private_key(generated)

    def test_can_verify_with_ops_requires_sha2(self):
        """
        GIVEN HSS keys with different hash algorithms.
        WHEN checking if they can verify with optimized operations
        THEN only SHA-256 based keys should return True.
        """
        sha2_key: HSSPrivateKey = self._ensure_hss_private_key(generate_key(self.SHA256_ALG))
        self.assertTrue(sha2_key.public_key()._can_verify_with_ops())
        shake_key: HSSPrivateKey = self._ensure_hss_private_key(generate_key(self.SHAKE_ALG))
        self.assertFalse(shake_key.public_key()._can_verify_with_ops())

    def test_load_hss_key_from_file(self):
        """
        GIVEN an HSS key file.
        WHEN the key is loaded from the file,
        THEN the key should be an instance of HSSPrivateKey.
        """
        key = load_private_key_from_file("data/keys/hss_keys/hss_lms_sha256_m24_h10_lmots_sha256_n24_w1_l9.pem")
        _ = self._ensure_hss_private_key(key)
