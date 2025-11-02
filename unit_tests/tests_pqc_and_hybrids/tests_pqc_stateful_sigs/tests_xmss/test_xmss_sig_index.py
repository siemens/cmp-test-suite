# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from oqs import StatefulSignature

from pq_logic.keys.stateful_sig_keys import XMSSPublicKey, XMSSPrivateKey
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import get_all_xmss_xmssmt_keys


class TestXMSSIndexSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithm = "XMSS-SHA2_10_256"
        cls.message = b"Test message for XMSS index signature"
        cls.new_message = b"New message for XMSS index signature"

    def test_index_signature(self):
        """
        GIVEN an XMSS stateful signature instance,
        WHEN signing a message and then signing a new message,
        THEN the signatures should be indexed correctly.
        """
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            self.assertIsNotNone(public_key, "Public key generation failed")

            # Sign the initial message
            signature1 = sig.sign(self.message)
            self.assertTrue(sig.verify(self.message, signature1, public_key), "Signature verification failed")

            # Sign a new message
            signature2 = sig.sign(self.new_message)
            self.assertTrue(
                sig.verify(self.new_message, signature2, public_key), "New message signature verification failed"
            )

            public_key = XMSSPublicKey.from_public_bytes(public_key)
            indexed_signatures = public_key.get_leaf_index(signature1)
            self.assertEqual(indexed_signatures, 0, "First signature should have index 0")
            indexed_signatures = public_key.get_leaf_index(signature2)
            self.assertEqual(indexed_signatures, 1, "Second signature should have index 1")

    def test_index_signature_after_deserialization(self):
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            _ = sig.sign(self.message)

            # Export the used keys
            exported_keys = sig.export_used_keys()
            self.assertEqual(len(exported_keys), 1, "Expected 1 exported key after signing")

        # Deserialize from the first exported key
        sig2 = StatefulSignature(self.algorithm, secret_key=exported_keys[0])
        self.assertEqual(len(sig2.export_used_keys()), 0, "Used keys list should be empty after deserialization")

        # Sign a new message with the restored key
        new_signature = sig2.sign(self.new_message)
        self.assertTrue(
            sig2.verify(self.new_message, new_signature, public_key), "Signature after deserialization failed"
        )
        public_key = XMSSPublicKey.from_public_bytes(public_key)
        indexed_signatures = public_key.get_leaf_index(new_signature)
        self.assertEqual(indexed_signatures, 1, "New signature should have index 1 after deserialization")

    def test_index_signature_comp(self):
        """
        GIVEN an XMSS stateful signature instance,
        WHEN signing a message and then signing a new message,
        THEN the signatures should be indexed correctly.
        """
        private_key = XMSSPrivateKey(self.algorithm.lower())
        for x in range(private_key.max_sig_size):
            signature = private_key.sign(self.message)
            index = private_key.get_leaf_index(signature)
            self.assertEqual(index, x, f"Signature index {x} does not match expected index {index}")

    def test_index_signature_comp_shake(self):
        """
        GIVEN an XMSS stateful signature instance,
        WHEN signing a message and then signing a new message,
        THEN the signatures should be indexed correctly.
        """
        private_key = XMSSPrivateKey("xmss-shake_10_256")
        for x in range(private_key.max_sig_size):
            signature = private_key.sign(self.message)
            index = private_key.get_leaf_index(signature)
            self.assertEqual(index, x, f"Signature index {x} does not match expected index {index}")

    def test_index_zero_and_one_signature_all(self):
        """
        GIVEN an XMSSMT stateful signature instance,
        WHEN signing a message and then signing a new message,
        THEN the signatures should be indexed correctly.
        """
        for key_name, key_path in get_all_xmss_xmssmt_keys().items():
            if key_name.startswith("xmssmt-"):
                continue

            private_key = load_private_key_from_file(key_path)
            self.assertIsInstance(private_key, XMSSPrivateKey, f"Key {key_name} is not an XMSSPrivateKey instance")

            signature1 = private_key.sign(self.message)
            indexed_signatures = private_key.public_key().get_leaf_index(signature1)
            self.assertEqual(indexed_signatures, 0, f"First signature for {key_name} should have index 0")
            signature2 = private_key.sign(self.new_message)
            indexed_signatures = private_key.public_key().get_leaf_index(signature2)
            self.assertEqual(indexed_signatures, 1, f"Second signature for {key_name} should have index 1")


if __name__ == "__main__":
    unittest.main()
