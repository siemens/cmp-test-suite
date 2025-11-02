# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import XMSSMTPrivateKey, XMSSPrivateKey
from resources.keyutils import modify_pq_stateful_sig_private_key, load_private_key_from_file
from unit_tests.utils_for_test import get_all_xmss_xmssmt_keys


class TestExhaustStflKeys(unittest.TestCase):
    def test_exhaust_xmss_key(self):
        """
        GIVEN an XMSS key.
        WHEN the key is exhausted,
        THEN should the key have no more signatures left.
        """
        key = XMSSPrivateKey("xmss-sha2_10_256")
        exhausted_key = modify_pq_stateful_sig_private_key(key)
        self.assertIsInstance(exhausted_key, XMSSPrivateKey)
        self.assertEqual(0, exhausted_key.sigs_remaining)

    def test_exhaust_xmss_keys(self):
        """
        GIVEN all known XMSS keys.
        WHEN each key is exhausted,
        THEN should each key have no more signatures left.
        """
        for alg_name, fpath in get_all_xmss_xmssmt_keys().items():
            if alg_name.startswith("xmssmt-"):
                continue
            with self.subTest(key=alg_name):
                loaded_key = load_private_key_from_file(fpath)
                self.assertIsInstance(loaded_key, XMSSPrivateKey)
                exhausted_key = modify_pq_stateful_sig_private_key(loaded_key)
                self.assertIsInstance(exhausted_key, XMSSPrivateKey)
                self.assertEqual(0, exhausted_key.sigs_remaining)

    def test_exhaust_xmssmt_key(self):
        """
        GIVEN an XMSSMT key.
        WHEN the key is exhausted,
        THEN should the key have no more signatures left.
        """
        key = XMSSMTPrivateKey("xmssmt-sha2_20/2_256")
        exhausted_key = modify_pq_stateful_sig_private_key(key)
        self.assertIsInstance(exhausted_key, XMSSMTPrivateKey)
        self.assertEqual(0, exhausted_key.sigs_remaining)

    def test_exhaust_xmssmt_keys(self):
        """
        GIVEN all known XMSSMT keys.
        WHEN each key is exhausted,
        THEN should each key have no more signatures left.
        """
        for alg_name, fpath in get_all_xmss_xmssmt_keys().items():
            if not alg_name.startswith("xmssmt-"):
                continue
            with self.subTest(key=alg_name):
                loaded_key = load_private_key_from_file(fpath)
                self.assertIsInstance(loaded_key, XMSSMTPrivateKey)
                exhausted_key = modify_pq_stateful_sig_private_key(loaded_key)
                self.assertIsInstance(exhausted_key, XMSSMTPrivateKey)
                self.assertEqual(0, exhausted_key.sigs_remaining)

if __name__ == "__main__":
    unittest.main()
