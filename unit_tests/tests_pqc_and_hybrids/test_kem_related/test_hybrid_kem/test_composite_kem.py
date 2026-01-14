# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import x25519

from pq_logic.keys.composite_kem import CompositeKEMPrivateKey, CompositeDHKEMRFC9180PrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from resources.keyutils import generate_key


class TestCompositeKEM(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ml_kem_key = generate_key("ml-kem-768")
        cls.rsa_key = generate_key("rsa", length=2048)
        cls.ecc_key = generate_key("ecc", curve="secp256r1")
        cls.x448_key = generate_key("x448")

    def test_valid_mlkem_ecdh_secp256r1(self):
        """
        GIVEN a CompositeKEMPrivateKey
        WHEN the encaps and decaps functions are called,
        THEN the shared secret is the same.
        """
        key = CompositeKEMPrivateKey(self.ml_kem_key, self.ecc_key)  # type: ignore
        
        ss, ct = key.public_key().encaps()
        ss2 = key.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_valid_mlkem_x448(self):
        """
        GIVEN a CompositeKEMPrivateKey
        WHEN the encaps and decaps functions are called,
        THEN the shared secret is the same.
        """
        ml_kem_key = generate_key("ml-kem-1024")
        key = CompositeKEMPrivateKey(ml_kem_key, self.x448_key)
        ss, ct = key.public_key().encaps()
        ss2 = key.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_valid_mlkem_rsa(self):
        """
        GIVEN a CompositeKEMPrivateKey
        WHEN the encaps and decaps functions are called,
        THEN the shared secret is the same.
        """
        key = CompositeKEMPrivateKey(self.ml_kem_key, self.rsa_key) # type: ignore
        ss, ct = key.public_key().encaps()
        ss2 = key.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_encaps_and_decaps_frodokem_x25519(self):
        """
        GIVEN two FrodoKEM 976 AES-based composite keys.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        trad_key = generate_key("x25519")
        pq_key = PQKeyFactory.generate_pq_key("frodokem-976-aes")
        comp_key = CompositeKEMPrivateKey(pq_key, trad_key)
        shared_secret, ct_vals = comp_key.public_key().encaps()
        decaps_ss = comp_key.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for FrodoKEM X25519-based keys.")


    def test_encaps_and_decaps_mlkem768_dhkemrfc9180_x25519(self):
        """
        GIVEN a ML-KEM 768-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        trad_key1 = x25519.X25519PrivateKey.generate()
        pq_key1 = PQKeyFactory.generate_pq_key("ml-kem-768")
        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)
        ss, ct = key1.public_key().encaps()

        ss2 = key1.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_encaps_and_decaps_frodokem_976_aes_dhkemrfc9180_x25519(self):
        """
        GIVEN a FrodoKEM 976 AES-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        trad_key1 = x25519.X25519PrivateKey.generate()
        pq_key1 = PQKeyFactory.generate_pq_key("frodokem-976-aes")
        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)

        ss, ct = key1.public_key().encaps()
        ss2 = key1.decaps(ct)
        self.assertEqual(ss, ss2)