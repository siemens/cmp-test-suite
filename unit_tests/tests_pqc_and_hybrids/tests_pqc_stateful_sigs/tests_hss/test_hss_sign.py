# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from cryptography.exceptions import InvalidSignature

from pq_logic.keys.stateful_sig_keys import HSSPrivateKey


class TestHSSSigning(unittest.TestCase):
    SHA256_ALG = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"
    SHAKE_ALG = "hss_lms_shake_m24_h5_lmots_shake_n24_w4"
    DIFF_HASH_ALG = "hss_lms_shake_m24_h10_lmots_shake_n24_w1"

    def test_sign_and_verify_sha256(self):
        """
        GIVEN an HSS key with SHA-256 hash algorithms.
        WHEN signing and verifying a message,
        THEN should the signature be valid.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        msg = b"CMP HSS unit test"
        sig = key.sign(msg)
        key.public_key().verify(msg, sig)
        self.assertEqual(key.public_key().get_leaf_index(sig), int.from_bytes(key.used_keys[-1], "big"))

    def test_sign_and_verify_shake(self):
        """
        GIVEN an HSS key with SHAKE hash algorithms.
        WHEN signing and verifying a message,
        THEN should the signature be valid.
        """
        key = HSSPrivateKey(self.SHAKE_ALG, levels=2)
        msg = b"HSS SHAKE message"
        sig = key.sign(msg)
        key.public_key().verify(msg, sig)

    def test_sign_and_verify_mixed_hash(self):
        """
        GIVEN an HSS key with mixed hash algorithms.
        WHEN signing and verifying a message,
        THEN should the signature be valid.
        """
        key = HSSPrivateKey(self.DIFF_HASH_ALG, levels=2)
        msg = b"HSS SHAKE message"
        sig = key.sign(msg)
        key.public_key().verify(msg, sig)

    def test_used_keys_returns_copy_and_isolated(self):
        """
        GIVEN an HSS key.
        WHEN accessing used_keys and modifying the returned list,
        THEN should the internal state of the key remain unchanged.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        sig = key.sign(b"tracking test")
        original_used = key.used_keys
        self.assertGreater(len(original_used), 0)
        original_used.append(b"tamper")
        self.assertNotEqual(key.used_keys[-1], b"tamper")
        key.public_key().verify(b"tracking test", sig)

    def test_correctly_sign_and_verify_with_length_9(self):
        """
        GIVEN an HSS key with 9 levels.
        WHEN signing and verifying a message,
        THEN should the signature be valid.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=9)
        msg = b"Test message for HSS key with 9 levels"
        sig = key.sign(msg)
        key.public_key().verify(data=msg, signature=sig)

    def test_invalid_sign_and_verify_with_length_9(self):
        """
        GIVEN an HSS key with 9 levels.
        WHEN signing a message and verifying with a different message,
        THEN should the verification fail.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=9)
        msg = b"Test message for HSS key with 9 levels"
        sig = key.sign(msg)
        with self.assertRaises(InvalidSignature) as cm:
            key.public_key().verify(b"Different message", sig)
        self.assertIn("HSS signature verification failed", str(cm.exception))


    def test_verify_fails_on_modified_signature(self):
        """
        GIVEN an HSS key and a valid signature.
        WHEN the signature is modified.
        THEN should the verification fail.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        msg = b"Integrity check"
        sig = bytearray(key.sign(msg))
        # Corrupt one byte safely inside payload
        if len(sig) > 10:
            sig[10] ^= 0xFF
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(msg, bytes(sig))


    def test_sign_and_verify_oqs_multi_level(self):
        """
        GIVEN an HSS key and valid signatures.
        WHEN signing and verifying the message,
        THEN should the signature be valid.
        """
        key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w1", levels=2)
        m = b"OQS Signature verification"
        for x in range(key.max_sig_size):
            sig = key.sign(m)
            key.public_key().verify(m, sig)


if __name__ == "__main__":
    unittest.main()