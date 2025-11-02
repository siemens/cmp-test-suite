# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from pq_logic.keys.kem_keys import FrodoKEMPrivateKey
from resources.keyutils import generate_key
from resources.utils import manipulate_first_byte


class TestFrodoKEM(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.frodokem_names = ["frodokem-640-aes", "frodokem-976-aes", "frodokem-1344-aes",
                              "frodokem-640-shake", "frodokem-976-shake", "frodokem-1344-shake"]

    def test_frodokem_pos(self):
        """
        GIVEN two FrodoKEM key keys.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1: FrodoKEMPrivateKey = generate_key("frodokem-640-aes")

        ss_1, ct = key1.public_key().encaps()
        ss_2 = key1.decaps(ct)

        self.assertEqual(ss_1, ss_2)

    def test_frodokem_neg(self):
        """
        GIVEN two FrodoKEM key keys.
        WHEN encaps and decaps are called and the ciphertext is manipulated,
        THEN should the shared secret not be equal.
        """
        key: FrodoKEMPrivateKey = generate_key("frodokem-640-aes")

        ss_1, ct = key.public_key().encaps()
        ct_modified = manipulate_first_byte(ct)

        ss_2 = key.decaps(ct_modified)

        self.assertNotEqual(ss_1, ss_2)

    def test_frodokem_derivate_public_key(self):
        """
        GIVEN a FrodoKEM private key.
        WHEN the public key is derived from the private key.
        THEN the derived public key should match the original public key.
        """
        for name in self.frodokem_names:
            with self.subTest(f"Testing FrodoKEM key generation for {name}"):
                key: FrodoKEMPrivateKey = generate_key(name)
                derived_public_key = key._derivate_public_key()
                self.assertEqual(key.public_key().public_bytes_raw(), derived_public_key)

    def test_frodokem_from_seed(self):
        """
        GIVEN a FrodoKEM seed.
        WHEN the key is generated from a seed.
        THEN the key should be valid and match the expected properties.
        """
        for name in self.frodokem_names:
            seed_size = FrodoKEMPrivateKey._seed_size(name)
            seed = os.urandom(seed_size)
            with self.subTest(f"Testing FrodoKEM key generation from seed for {name}"):
                key = FrodoKEMPrivateKey.from_seed(name, seed)
                self.assertIsInstance(key, FrodoKEMPrivateKey)
                self.assertEqual(key._derivate_public_key(), key.public_key().public_bytes_raw())
                self.assertEqual(key.name, name)
                self.assertEqual(key._seed, seed)
                self.assertEqual(key.public_key().name, name)
