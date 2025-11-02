# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from oqs import StatefulSignature

from pq_logic.keys.stateful_sig_keys import XMSSMTPublicKey


class TestXMSSMTIndexSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithm = "XMSSMT-SHAKE_20/2_256"
        cls.message = b"Test message for XMSSMT index signature"
        cls.new_message = b"New message for XMSSMT index signature"

    def test_index_signature(self):
        """
        GIVEN a StatefulSignature instance for XMSSMT.
        WHEN generating a keypair and signing multiple messages,
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

            public_key = XMSSMTPublicKey.from_public_bytes(public_key)
            indexed_signatures = public_key.get_leaf_index(signature1)
            self.assertEqual(indexed_signatures, 0, "First signature should have index 0")
            indexed_signatures = public_key.get_leaf_index(signature2)
            self.assertEqual(indexed_signatures, 1, "Second signature should have index 1")

    def test_index_signature_after_deserialization(self):
        """
        GIVEN a StatefulSignature instance for XMSSMT.
        WHEN generating a keypair, signing a message, and then deserializing the key,
        THEN the used keys should be exported and the new signature should be indexed correctly.
        """
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
        public_key = XMSSMTPublicKey.from_public_bytes(public_key)
        indexed_signatures = public_key.get_leaf_index(new_signature)
        self.assertEqual(indexed_signatures, 1, "New signature should have index 1 after deserialization")


if __name__ == "__main__":
    unittest.main()
