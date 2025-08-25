# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.chempat_key import ChempatMLKEMPrivateKey, ChempatSntrup761PrivateKey, \
    ChempatMcEliecePrivateKey
from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.trad_kem_keys import RSADecapKey, DHKEMPrivateKey
from resources.keyutils import generate_key
from cryptography.hazmat.primitives.asymmetric import x25519

class TestHybridKeyFactory(unittest.TestCase):


    def test_hybrid_key_factory_chempat_sntrup761(self):
        """
        GIVEN a hybrid key factory and the chempat algorithm.
        WHEN a hybrid key is generated with the pq_name sntrup761.
        THEN the pq_key should be sntrup761 and the trad_key should be x25519
        """
        key = generate_key(algorithm="chempat", pq_name="sntrup761") # type: ignore
        key: ChempatSntrup761PrivateKey

        self.assertEqual(key.pq_key.name, "sntrup761")
        self.assertIsInstance(key.trad_key._private_key, x25519.X25519PrivateKey)

    def test_hybrid_key_factory_chempat_ml_kem_768(self):
        """
        GIVEN a hybrid key factory and the chempat algorithm.
        WHEN a hybrid key is generated with the pq_name ml-kem-768.
        THEN the pq_key should be ml-kem-768 and the trad_key should be x25519.
        """
        key = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", # type: ignore
                                                   pq_name="ml-kem-768")

        key: ChempatMLKEMPrivateKey

        self.assertEqual(key.pq_key.name, "ml-kem-768")
        self.assertIsInstance(key.trad_key._private_key, x25519.X25519PrivateKey)

    def test_hybrid_key_factory_chempat_mceliece(self):
        """
        GIVEN a hybrid key factory and the chempat algorithm.
        WHEN a hybrid key is generated with the pq_name mceliece-6688128.
        THEN the pq_key should be mceliece-6688128 and the trad_key should be x25519.
        """
        key = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", # type: ignore
                                                   pq_name="mceliece-6688128")

        key: ChempatMcEliecePrivateKey

        self.assertEqual(key.pq_key.name, "mceliece-6688128")
        self.assertIsInstance(key.trad_key._private_key, x25519.X25519PrivateKey)

    def test_hybrid_key_factory_comp_kem_mlkem(self):
        """
        GIVEN a hybrid key factory and the composite-kem algorithm.
        WHEN a hybrid key is generated with the pq_name ml-kem-768.
        THEN the pq_key should be ML-KEM and the trad_key should be rsa.
        """
        key = HybridKeyFactory.generate_hybrid_key(algorithm="composite-kem", # type: ignore
                                                   pq_name="ml-kem-768",
                                                )

        self.assertEqual(key.pq_key.name, "ml-kem-768")
        self.assertIsInstance(key.trad_key, DHKEMPrivateKey)

    def test_hybrid_key_factory_comp_kem_rsa(self):
        """
        GIVEN a hybrid key factory and the composite-kem algorithm.
        WHEN a hybrid key is generated with the trad_name rsa.
        THEN the pq_key should be ML-KEM and the trad_key should be rsa.
        """
        key = HybridKeyFactory.generate_hybrid_key(algorithm="composite-kem",
                                                   trad_name="rsa",
                                                )

        self.assertEqual(key.pq_key.name, "ml-kem-1024")
        self.assertIsInstance(key.trad_key, RSADecapKey)


    def test_hybrid_key_factory_comp_kem_frodokem(self):
        """
        GIVEN a hybrid key factory and the composite-kem algorithm.
        WHEN a hybrid key is generated with the pq_name frodokem-976-aes.
        THEN the pq_key should be frodokem-976-aes, and the trad_key should be x25519.
        """
        key = HybridKeyFactory.generate_hybrid_key(algorithm="composite-kem",
                                                   pq_name="frodokem-976-aes",
                                                )

        self.assertEqual(key.pq_key.name, "frodokem-976-aes")
        self.assertIsInstance(key.trad_key, DHKEMPrivateKey)
