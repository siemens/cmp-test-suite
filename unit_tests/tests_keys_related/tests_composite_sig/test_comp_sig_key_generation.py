# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig import CompositeSigPrivateKey
from resources.keyutils import generate_key


class TestCompSigKeyGeneration(unittest.TestCase):

    def _ensure_and_gen_composite_sig_key(self, name: str) -> CompositeSigPrivateKey:
        """Generate a composite signature key of the current version with the given name."""
        key = generate_key(name, by_name=True)
        self.assertIsInstance(key, CompositeSigPrivateKey)
        return key


    def test_comp_sig13_key_generation(self):
        """
        GIVEN a composite signature key in the current version.
        WHEN generating the key.
        THEN the key is generated successfully.
        """
        key2 = generate_key("composite-sig")
        self.assertIsInstance(key2, CompositeSigPrivateKey)

    def test_comp_sig13_key_generation_by_name_rsa4096(self):
        """
        GIVEN a composite signature key in the current version.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = self._ensure_and_gen_composite_sig_key("composite-sig-ml-dsa-87-rsa4096")
        self.assertEqual(key.name, "composite-sig-ml-dsa-87-rsa4096")
        self.assertEqual(key.trad_key.key_size, 4096)

    def test_comp_sig13_key_generation_by_name(self):
        """
        GIVEN a composite signature key in the current version.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig")
        key2 = generate_key(key.name, by_name=True)
        self.assertEqual(key.name, key2.name)
        self.assertIsInstance(key2, CompositeSigPrivateKey)
