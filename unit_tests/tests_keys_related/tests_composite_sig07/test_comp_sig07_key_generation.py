# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey
from resources.keyutils import generate_key


class TestCompSig07KeyGeneration(unittest.TestCase):

    def test_comp_sig07_key_generation(self):
        """
        GIVEN a composite signature key in version 7.
        WHEN generating the key.
        THEN the key is generated successfully.
        """
        key2 = generate_key("composite-sig-07")
        self.assertIsInstance(key2, CompositeSig07PrivateKey)

    def test_comp_sig07_key_generation_by_name_rsa4096(self):
        """
        GIVEN a composite signature key in version 7.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig-07-ml-dsa-87-rsa4096", by_name=True)
        self.assertEqual(key.name, "composite-sig-07-ml-dsa-87-rsa4096")
        self.assertIsInstance(key, CompositeSig07PrivateKey)
        self.assertEqual(key.trad_key.key_size, 4096)

    def test_comp_sig07_key_generation_by_name(self):
        """
        GIVEN a composite signature key in version 7.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig-07")
        key2 = generate_key(key.name, by_name=True)
        self.assertEqual(key.name, key2.name)
        self.assertIsInstance(key2, CompositeSig07PrivateKey)
