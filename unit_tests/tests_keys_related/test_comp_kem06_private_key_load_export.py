# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.composite_kem06 import CompositeKEM06PrivateKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from resources.keyutils import generate_key


class TestCompositeKem06PrivateLoad(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ml_kem_key = generate_key("ml-kem-768") # type: MLKEMPrivateKey
        cls.rsa_key = generate_key("rsa", length=2048)
        cls.ecc_key = generate_key("ecc", curve="secp256r1")
        cls.x25519_key = x25519.X25519PrivateKey.generate()

    def test_comp_kem06_load_x25519(self):
        """
        GIVEN a CompositeKEM06privateKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = CompositeKEM06PrivateKey(self.ml_kem_key, self.x25519_key)
        one_asym_key = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
        )
        loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key.public_key().pq_key, key.public_key().pq_key)
        self.assertEqual(loaded_key.public_key().trad_key._public_key, key.public_key().trad_key._public_key)
        self.assertEqual(loaded_key.public_key(), key.public_key())

    def test_comp_kem06_load_ecc(self):
        """
        GIVEN a CompositeKEM06PublicKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = CompositeKEM06PrivateKey(self.ml_kem_key, self.ecc_key)
        one_asym_key = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
        )
        loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key.public_key(), key.public_key())

    def test_comp_kem06_load_rsa(self):
        """
        GIVEN a CompositeKEM06PublicKey.
        WHEN loading the public key from a SPKI.
        THEN the key is loaded correctly.
        """
        key = CompositeKEM06PrivateKey(self.ml_kem_key, self.rsa_key)
        one_asym_key = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
        )
        loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)
        self.assertEqual(loaded_key.get_oid(), key.get_oid())
        self.assertEqual(loaded_key.name, key.name)
        self.assertEqual(loaded_key.public_key(), key.public_key())