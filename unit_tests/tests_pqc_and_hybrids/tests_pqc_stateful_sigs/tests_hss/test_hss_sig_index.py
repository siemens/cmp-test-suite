# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import HSSPrivateKey, compute_hss_signature_index
from resources.keyutils import generate_key
from resources.typingutils import PrivateKey


class TestHSSIndexSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithm = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"
        cls.message = b"Test message for HSS index signature"
        cls.new_message = b"New message for HSS index signature"

    def _ensure_hss_private_key(self, key: PrivateKey) -> HSSPrivateKey:
        """Helper to assert and cast a PrivateKey to HSSPrivateKey."""
        self.assertIsInstance(key, HSSPrivateKey)
        return key

    def test_hss_index_signature(self):
        """
        GIVEN a StatefulSignature instance for HSS.
        WHEN generating a keypair and signing multiple messages,
        THEN the signatures should be indexed correctly.
        """
        key = self._ensure_hss_private_key(generate_key(self.algorithm))
        public_key = key.public_key()

        # Sign the initial message
        signature1 = key.sign(self.message)
        public_key.verify(data=self.message, signature=signature1)

        # Sign a new message
        signature2 = key.sign(self.new_message)
        public_key.verify(data=self.new_message, signature=signature2)

        indexed_signatures = public_key.get_leaf_index(signature1)
        self.assertEqual(indexed_signatures, 0, "First signature should have index 0")
        indexed_signatures = public_key.get_leaf_index(signature2)
        self.assertEqual(indexed_signatures, 1, "Second signature should have index 1")

    def test_hss_index_signature_after_deserialization(self):
        """
        GIVEN a StatefulSignature instance for HSS.
        WHEN generating a keypair, signing a message, and then deserializing the key,
        THEN the used keys should be exported and the new signature should be indexed correctly.
        """
        key1 = self._ensure_hss_private_key(generate_key(self.algorithm))
        _ = key1.sign(self.message)
        exported_keys = key1.used_keys
        self.assertEqual(len(exported_keys), 1, "Expected 1 exported key after signing")

        # Deserialize from the first exported key
        key2 = HSSPrivateKey.from_private_bytes(key1.private_bytes_raw())
        public_key = key1.public_key()
        self.assertEqual(len(key2.used_keys), 0, "Used keys list should be empty after deserialization")

        # Sign a new message with the restored key
        new_signature = key2.sign(self.new_message)
        key2.public_key().verify(data=self.new_message, signature=new_signature)
        indexed_signatures = public_key.get_leaf_index(new_signature)
        self.assertEqual(indexed_signatures, 1, "New signature should have index 1 after deserialization")

    def test_hss_multi_level_get_index(self):
        """
        GIVEN an HSS key with 2 levels and a height of 5 and valid signatures.
        WHEN signing the message,
        THEN the signature index should be valid.
        """
        key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w1", levels=2)
        m = b"OQS Signature verification"
        for x in range(key.max_sig_size):
            sig = key.sign(m)
            self.assertEqual(x % 32, key.get_leaf_index(sig), f"The signature index should be the same as the leaf index. At i.{x}")
            self.assertEqual(key.sigs_remaining, key.max_sig_size - (x + 1), f"Signatures remaining should decrease accordingly at i.{x}.")
            self.assertEqual(compute_hss_signature_index(sig, key), x, f"The computed HSS signature index should match the signing index at i.{x}.")

    def test_hss_test_hss_multi_level_get_index_h10(self):
        """
        GIVEN an HSS key with 2 levels and a height of 10 and valid signatures.
        WHEN signing the message,
        THEN the signature index should be valid.
        """
        key = HSSPrivateKey("hss_lms_sha256_m24_h10_lmots_sha256_n24_w1", levels=2)
        m = b"OQS Signature verification"
        for x in range(2050):
            sig = key.sign(m)
            self.assertEqual(x % 1024, key.get_leaf_index(sig), f"The signature index should be the same as the leaf index. At i.{x}")
            self.assertEqual(key.sigs_remaining, key.max_sig_size - (x + 1), f"Signatures remaining should decrease accordingly at i.{x}.")
            self.assertEqual(compute_hss_signature_index(sig, key), x, f"The computed HSS signature index should match the signing index at i.{x}.")

if __name__ == "__main__":
    unittest.main()
