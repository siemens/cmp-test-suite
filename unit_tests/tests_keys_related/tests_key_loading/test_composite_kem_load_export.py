# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization

from pq_logic.combined_factory import CombinedKeyFactory
from resources.keyutils import generate_key


class TestCompositeKemPublicKeyLoading(unittest.TestCase):


    def test_comp_kem_load_x25519(self):
        """
        GIVEN a CompositeKEMPublicKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = generate_key("composite-kem", trad_name="x25519", pq_name="ml-kem-768")
        spki = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded_key = CombinedKeyFactory.load_public_key_from_spki(
            spki=spki,
        )
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key, key.public_key())

    def test_comp_kem_load_ecc(self):
        """
        GIVEN a CompositeKEMPublicKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = generate_key("composite-kem", trad_name="ecdh",
                           pq_name="ml-kem-768", curve="secp256r1")
        spki = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded_key = CombinedKeyFactory.load_public_key_from_spki(
            spki=spki,
        )
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key, key.public_key())

    def test_comp_kem_load_rsa(self):
        """
        GIVEN a CompositeKEMPublicKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = generate_key("composite-kem", trad_name="rsa",
                          )
        spki = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded_key = CombinedKeyFactory.load_public_key_from_spki(
            spki=spki,
        )
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key, key.public_key())