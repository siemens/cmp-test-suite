# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


import unittest

from pq_logic.keys.chempat_key import ChempatMLKEMPrivateKey, ChempatMcEliecePrivateKey, ChempatFrodoKEMPrivateKey
from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from resources.keyutils import generate_key


class TestChempatKEM(unittest.TestCase):

    def test_chempat_ml_kem_768_x25519(self):
        """
        GIVEN a Chempat ML-KEM-768 and X25519 key and a X25519 key.
        WHEN the Chempat public key is encapsulated with the X25519 key,
        THEN is the same shared secret generated when the Chempat key is decapsulated.
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat",  # type: ignore
                                                    pq_name="ml-kem-768", trad_name="x25519")

        key1: ChempatMLKEMPrivateKey
        key2 = generate_key("x25519")
        ss_1, ct = key1.public_key().encaps(key2)
        ss_2 = key1.decaps(ct)
        self.assertEqual(ss_1, ss_2)

    def test_chempat_mceliece_6688128_x448(self):
        """
        GIVEN a Chempat McEliece-6688128 and X25519 key and a X25519 key.
        WHEN the Chempat key is encapsulated with the X25519 key,
        THEN is the same shared secret generated when the Chempat key is decapsulated.
        :return:
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", pq_name="mceliece-6688128") # type: ignore
        key1: ChempatMcEliecePrivateKey
        key2 = generate_key("X25519")
        ss_1, ct = key1.public_key().encaps(key2)
        ss_2 = key1.decaps(ct)
        self.assertEqual(ss_1, ss_2)

    def test_chempat_frodokem_976_aes_x25519(self):
        """
        GIVEN a Chempat FrodoKEM-976-AES and X25519 key and a X25519 key.
        WHEN the Chempat key is encapsulated with the X25519 key,
        THEN is the same shared secret generated when the Chempat key is decapsulated.
        """
        key1 = HybridKeyFactory.generate_hybrid_key(algorithm="chempat", # type: ignore
                                                    pq_name="frodokem-976-aes", trad_name="x25519")
        key1: ChempatFrodoKEMPrivateKey
        key2 = generate_key("x25519")
        ss_1, ct = key1.public_key().encaps(key2)
        ss_2 = key1.decaps(ct)
        self.assertEqual(ss_1, ss_2)