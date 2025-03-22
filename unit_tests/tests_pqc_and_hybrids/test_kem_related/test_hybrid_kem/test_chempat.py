# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


import unittest

from pq_logic.chempatkem import ChempatMLKEMPrivateKey
from pq_logic.hybrid_key_factory import HybridKeyFactory


class TestChempatKEM(unittest.TestCase):

    def test_chempat_ml_kem_768_x25519(self):
        """
        GIVEN two ChempatMLKEM768PrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1 = ChempatMLKEMPrivateKey.generate(trad_name="x25519")
        key2 = ChempatMLKEMPrivateKey.generate(trad_name="x25519")

        ss_1, ct = key1.encaps(key2.public_key())
        ss_2 = key2.decaps(ct)
        self.assertEqual(ss_1, ss_2)


    def test_chempat_mceliece_6688128_x25519(self):
        """
        GIVEN two ChempatMLKEM768PrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="mceliece-6688128")
        key2 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="mceliece-6688128")
        ss_1, ct = key1.encaps(key2.public_key())
        ss_2 = key2.decaps(ct)
        self.assertEqual(ss_1, ss_2)

    def test_chempat_mlkem_768_x25519(self):
        """
        GIVEN two ChempatMLKEM768PrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="ml-kem-768", trad_name="x25519")
        key2 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="ml-kem-768", trad_name="x25519")
        ss_1, ct = key1.encaps(key2.public_key())
        ss_2 = key2.decaps(ct)
        self.assertEqual(ss_1, ss_2)


    def test_chempat_frodokem_976_aes_x25519(self):
        """
        GIVEN two ChempatMLKEM768PrivateKey instances.
        WHEN encaps and decaps are called.
        THEN the shared secret should be equal.
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="frodokem-976-aes", trad_name="x25519")
        key2 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="frodokem-976-aes", trad_name="x25519")

        ss_1, ct = key1.encaps(key2.public_key())
        ss_2 = key2.decaps(ct)
        self.assertEqual(ss_1, ss_2)