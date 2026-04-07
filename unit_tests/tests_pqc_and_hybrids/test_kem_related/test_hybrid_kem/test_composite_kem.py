# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem import CompositeKEMPrivateKey
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


