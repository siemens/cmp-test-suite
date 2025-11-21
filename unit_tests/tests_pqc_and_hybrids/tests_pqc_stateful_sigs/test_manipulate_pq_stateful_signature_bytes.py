# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import math
import unittest

from cryptography.exceptions import InvalidSignature

from pq_logic.keys.stateful_sig_keys import HSSPrivateKey, XMSSMTPrivateKey, XMSSPrivateKey
from resources.keyutils import load_private_key_from_file
from resources.utils import manipulate_pq_stateful_signature_bytes
from unit_tests.utils_for_test import get_all_xmss_xmssmt_keys


class TestManipulatePQStatefulSignature(unittest.TestCase):
    """Tests for manipulating stateful PQ signature bytes and indices."""

    def test_modify_xmss_signature_index(self):
        """
        GIVEN an XMSS key.
        WHEN the key's signature is manipulated,
        THEN should the manipulated signature be invalid.
        """
        key = XMSSPrivateKey("xmss-sha2_10_256")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False)
        self.assertEqual(int.from_bytes(sig[:4], "little"), key.max_sig_size)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)

    def test_modify_xmss_signature_index_zero(self):
        """
        GIVEN an XMSS key and a valid signature.
        WHEN the signature's index is set to zero,
        THEN should the signature remain valid (index 0 is the first valid signature).
        """
        key = XMSSPrivateKey("xmss-sha2_10_256")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False, index=0)
        self.assertEqual(int.from_bytes(sig[:4], "little"), 0)
        key.public_key().verify(m, sig)

    def test_modify_xmss_signature_index_to_one(self):
        """
        GIVEN an XMSS key.
        WHEN the key's signature index is set to one,
        THEN should the manipulated signature be invalid.
        """
        key = XMSSPrivateKey("xmss-sha2_10_256")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False, index=1)
        self.assertEqual(int.from_bytes(sig[:4], "little"), 1)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)

    def test_modify_xmss_signature_data(self):
        """
        GIVEN an XMSS key.
        WHEN the key's signature data is manipulated,
        THEN should the manipulated signature be invalid.
        """
        key = XMSSPrivateKey("xmss-sha2_10_256")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=True)
        self.assertEqual(sig_orig[:4], sig[:4])
        self.assertNotEqual(sig_orig[4:], sig[4:])
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)

    def test_modify_xmss_signature(self):
        """
        GIVEN all known XMSS keys.
        WHEN each key's signature index is set to max_sig_size and signature data is corrupted,
        THEN should the manipulated signatures be invalid.
        """
        m = b"Secret message for signing"
        for alg_name, fpath in get_all_xmss_xmssmt_keys().items():
            if alg_name.startswith("xmssmt-"):
                continue
            with self.subTest(key=alg_name):
                loaded_key = load_private_key_from_file(fpath)
                self.assertIsInstance(loaded_key, XMSSPrivateKey)
                sig_orig = loaded_key.sign(m)
                sig = manipulate_pq_stateful_signature_bytes(sig_orig, loaded_key, manipulate_sig=False)
                self.assertEqual(int.from_bytes(sig[:4], "little"), loaded_key.max_sig_size)
                with self.assertRaises(InvalidSignature):
                    loaded_key.public_key().verify(m, sig)

                sig2 = manipulate_pq_stateful_signature_bytes(sig_orig, loaded_key, manipulate_sig=True)
                self.assertEqual(sig_orig[:4], sig2[:4])
                self.assertNotEqual(sig_orig[4:], sig2[4:])
                with self.assertRaises(InvalidSignature):
                    loaded_key.public_key().verify(m, sig2)

    def test_exhaust_xmssmt_key(self):
        """
        GIVEN an XMSSMT key and a valid signature.
        WHEN the signature's index is manipulated to the maximum value (exhausted state),
        THEN should the manipulated signature index be equal to max_sig_size.
        """
        key = XMSSMTPrivateKey("xmssmt-sha2_20/2_256")
        self.assertIsInstance(key, XMSSMTPrivateKey)
        index_length = math.ceil(key.tree_height / 8)
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False, index=None)
        self.assertEqual(int.from_bytes(sig[:index_length], "little"), key.max_sig_size)

    def test_modify_xmssmt_signatures(self):
        """
        GIVEN all known XMSSMT keys.
        WHEN each key's signature index is set to max_sig_size and signature data is corrupted,
        THEN should the manipulated signatures be invalid.
        """
        m = b"Secret message for signing"
        for alg_name, fpath in get_all_xmss_xmssmt_keys().items():
            if not alg_name.startswith("xmssmt-"):
                continue
            with self.subTest(key=alg_name):
                loaded_key = load_private_key_from_file(fpath)
                self.assertIsInstance(loaded_key, XMSSMTPrivateKey)
                sig_orig = loaded_key.sign(m)
                sig = manipulate_pq_stateful_signature_bytes(sig_orig, loaded_key, manipulate_sig=False)
                index_length = math.ceil(loaded_key.tree_height / 8)
                self.assertEqual(int.from_bytes(sig[:index_length], "little"), loaded_key.max_sig_size)
                with self.assertRaises(InvalidSignature):
                    loaded_key.public_key().verify(m, sig)

                sig2 = manipulate_pq_stateful_signature_bytes(sig_orig, loaded_key, manipulate_sig=True)
                self.assertEqual(sig_orig[:index_length], sig2[:index_length])
                self.assertNotEqual(sig_orig[index_length:], sig2[index_length:])
                with self.assertRaises(InvalidSignature):
                    loaded_key.public_key().verify(m, sig2)

    def test_modify_hss_signature_index(self):
        """
        GIVEN an HSS key with 3 levels and a valid signature.
        WHEN the signature's leaf index is manipulated to an invalid value,
        THEN should the manipulated signature be invalid.
        """
        key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=3)
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        self.assertEqual(key.levels, 3)
        # level n -1
        self.assertEqual(
            int.from_bytes(sig_orig[:4], "big"), 2, "Initial signature index should match the second level"
        )
        self.assertEqual(int.from_bytes(sig_orig[4:8], "big"), 0, "Initial leaf index should be zero")
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)

    def test_modify_hss_signature_index_zero(self):
        """
        GIVEN an HSS key with 2 levels and a valid signature.
        WHEN the signature's index is set to zero,
        THEN should the signature remain valid (index 0 is the first valid signature).
        """
        key = HSSPrivateKey("hss", levels=2)
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False, index=0)
        self.assertEqual(len(sig_orig), len(sig), "The signature length should be the same as the initial signature")
        self.assertEqual(sig_orig.hex(), sig.hex(), "The manipulated signature should be the same.")
        key.public_key().verify(m, sig)

    def test_modify_hss_signature_index_to_one(self):
        """
        GIVEN an HSS key.
        WHEN the key's signature index is set to one,
        THEN should the manipulated signature be invalid.
        """
        key = HSSPrivateKey("hss")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=False, index=1)
        self.assertEqual(int.from_bytes(sig[:4], "big"), 0, "Must be level -1.")
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)

    def test_modify_hss_signature_data(self):
        """
        GIVEN an HSS key.
        WHEN the key's signature data is manipulated,
        THEN should the manipulated signature be invalid.
        """
        key = HSSPrivateKey("hss")
        m = b"Secret message for signing"
        sig_orig = key.sign(m)
        sig = manipulate_pq_stateful_signature_bytes(sig_orig, key, manipulate_sig=True)
        self.assertEqual(sig_orig[:4], sig[:4])
        self.assertNotEqual(sig_orig[4:], sig[4:])
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(m, sig)


if __name__ == "__main__":
    unittest.main()
