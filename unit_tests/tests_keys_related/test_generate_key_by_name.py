# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pq_logic.combined_factory import CombinedKeyFactory
from resources.exceptions import InvalidKeyCombination


class TestGenerateKeyByName(unittest.TestCase):
    def test_generate_key_by_name_trad(self):
        """
        GIVEN the key name="rsa".
        WHEN the key is generated,
        THEN the key is an instance of RSAPrivateKey
        """
        algorithm = "rsa"
        key = CombinedKeyFactory.generate_key_from_name(algorithm)
        self.assertIsInstance(key, RSAPrivateKey)

    def test_generate_key_by_name_chempat(self):
        """
        GIVEN the key name="chempat-ml-kem-768-ecdh-secp256r1".
        WHEN the key is generated,
        THEN the key is correctly generated.
        """
        algorithm = "chempat-ml-kem-768-ecdh-secp256r1"
        key = CombinedKeyFactory.generate_key_from_name(algorithm)
        self.assertEqual(key.name, algorithm)

    def test_generate_key_by_name_composite_kem(self):
        """
        GIVEN the key name="composite-kem-ml-kem-768-ecdh-secp384r1".
        WHEN the key is generated,
        THEN the key is correctly generated.
        """
        algorithm = "composite-kem-ml-kem-768-ecdh-secp384r1"
        key = CombinedKeyFactory.generate_key_from_name(algorithm)
        self.assertEqual(key.name, algorithm)

    def test_generate_key_by_name_invalid_algorithm(self):
        """
        GIVEN the key name="composite-kem-ml-kem-1024-ecdh-secp256r1".
        WHEN the key is generated,
        THEN the InvalidKeyCombination exception is raised,
        because this combination is not allowed.
        """
        algorithm = "composite-kem-ml-kem-1024-ecdh-secp256r1"
        with self.assertRaises(InvalidKeyCombination):
            CombinedKeyFactory.generate_key_from_name(algorithm)


if __name__ == "__main__":
    unittest.main()
