# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig13 import CompositeSig13PrivateKey
from resources.keyutils import generate_key


class TestCompSig13KeyGeneration(unittest.TestCase):

    def _ensure_and_gen_composite_sig13_key(self, name: str) -> CompositeSig13PrivateKey:
        """Generate a composite signature key of version 13 with the given name."""
        key = generate_key(name, by_name=True)
        self.assertIsInstance(key, CompositeSig13PrivateKey)
        return key


    def test_comp_sig13_key_generation(self):
        """
        GIVEN a composite signature key in version 13.
        WHEN generating the key.
        THEN the key is generated successfully.
        """
        key2 = generate_key("composite-sig-13")
        self.assertIsInstance(key2, CompositeSig13PrivateKey)

    def test_comp_sig13_key_generation_by_name_rsa4096(self):
        """
        GIVEN a composite signature key in version 13.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = self._ensure_and_gen_composite_sig13_key("composite-sig-13-ml-dsa-87-rsa4096")
        self.assertEqual(key.name, "composite-sig-13-ml-dsa-87-rsa4096")
        self.assertEqual(key.trad_key.key_size, 4096)

    def test_comp_sig13_key_generation_by_name(self):
        """
        GIVEN a composite signature key in version 13.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig-13")
        key2 = generate_key(key.name, by_name=True)
        self.assertEqual(key.name, key2.name)
        self.assertIsInstance(key2, CompositeSig13PrivateKey)
