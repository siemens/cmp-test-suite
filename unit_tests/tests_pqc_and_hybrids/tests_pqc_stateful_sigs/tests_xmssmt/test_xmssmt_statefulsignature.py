# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from oqs import StatefulSignature


class TestXMSSMTStatefulSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithm = "XMSSMT-SHAKE_20/2_256"
        cls.message = os.urandom(32)
        cls.message2 = b"Hello, XMSS^MT!"
        cls.new_message = b"Hello again, XMSS^MT!"

    def test_saved_used_keys(self):
        """
        GIVEN a StatefulSignature instance for XMSSMT.
        WHEN generating a keypair and signing two different messages,
        THEN the used keys should be saved correctly.
        """
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()
            self.assertIsNotNone(public_key, "Public key generation failed")

            signature1 = sig.sign(self.message)
            self.assertTrue(sig.verify(self.message, signature1, public_key), "First signature verification failed")

            signature2 = sig.sign(self.message2)
            self.assertTrue(sig.verify(self.message2, signature2, public_key), "Second signature verification failed")

            exported_keys = sig.export_used_keys()
            self.assertEqual(
                len(exported_keys), 2, f"Exported keys should contain 2 entries. Got: {len(exported_keys)}"
            )

    def test_key_generation_signing_serialization(self):
        """
        GIVEN a StatefulSignature instance for XMSSMT.
        WHEN generating a keypair, signing two messages, and exporting keys,
        THEN the keys should be serialized correctly and the signatures should verify.
        """
        # Generate key and sign two messages
        with StatefulSignature(self.algorithm) as sig:
            public_key = sig.generate_keypair()

            sig1 = sig.sign(self.message)
            self.assertTrue(sig.verify(self.message, sig1, public_key), "First signature verification failed")

            sig2 = sig.sign(self.message2)
            self.assertTrue(sig.verify(self.message2, sig2, public_key), "Second signature verification failed")

            self.assertFalse(sig.verify(self.message2, sig1, public_key), "Old signature should not verify new message")

            exported_keys = sig.export_used_keys()
            self.assertEqual(len(exported_keys), 2, f"Exported keys should contain 2 keys. Got: {len(exported_keys)}")

        # Restore from exported key
        sig2 = StatefulSignature(self.algorithm, secret_key=exported_keys[0])
        self.assertEqual(len(sig2.export_used_keys()), 0, "Used keys list should be empty after deserialization")

        new_sig = sig2.sign(self.new_message)
        self.assertTrue(sig2.verify(self.new_message, new_sig, public_key), "Signature after deserialization failed")

        exported_after = sig2.export_used_keys()
        self.assertGreaterEqual(len(exported_after), 1, "Expected at least 1 exported key after signing")
        self.assertNotEqual(exported_after[0], exported_keys[0], "Deserialized key should be updated after signing")


if __name__ == "__main__":
    unittest.main()
