# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.trad_kem_keys import RSADecapKey
from resources.keyutils import load_private_key_from_file, save_key


class TestRSADecapKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.decap_key = RSADecapKey()

    def test_rsa_decap_key_initialization(self):
        """
        GIVEN an RSA Decap and Encap key.
        WHEN the key is initialized.
        THEN the key should be successfully initialized and return the correct values.
        """
        _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = RSADecapKey(_key)
        self.assertIsNotNone(key)
        self.assertEqual(key.name, "rsa-kem")
        self.assertEqual(key.public_key().name, "rsa-kem")
        self.assertEqual(key.get_trad_name, "rsa2048")
        self.assertEqual(key.public_key().get_trad_name, "rsa2048")
        self.assertGreaterEqual(key.key_size, 256)
        self.assertEqual(key.public_key().key_size, 256)

    def test_rsa_decap_key_enc_dec_cycle(self):
        """
        GIVEN an RSA Decap key.
        WHEN the key is used to encapsulate and decapsulate a shared secret.
        THEN the shared secret should be successfully
        """
        encap_key = self.decap_key.public_key()

        shared_secret, ciphertext = encap_key.encaps(use_oaep=True)
        self.assertTrue(len(shared_secret) == 32)
        self.assertTrue(len(ciphertext) > 0)

        recovered_secret = self.decap_key.decaps(ciphertext, use_oaep=True)
        self.assertEqual(shared_secret, recovered_secret, "Recovered secret should match the original shared secret.")

    def test_rsa_decap_key_according_to_rfc9690(self):
        """
        GIVEN an RSA Decap key.
        WHEN the key is used to encapsulate and decapsulate a shared secret.
        THEN the shared secret should be successfully
        """

        encap_key = self.decap_key.public_key()
        shared_secret, ciphertext = encap_key.encaps(use_oaep=False, ss_length=32, hash_alg="sha256")
        self.assertTrue(len(shared_secret) == 32)
        self.assertTrue(len(ciphertext) > 0)

    def test_rsa_kem_pubkey_serialization(self):
        """
        GIVEN an RSA Encap key.
        WHEN the key is serialized and deserialized.
        THEN the deserialized key should be equal to the original key.
        """
        der_data = self.decap_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        spki, rest = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(rest, b"")

        pub_key = CombinedKeyFactory.load_public_key_from_spki(spki)
        self.assertEqual(self.decap_key.public_key(), pub_key)

    def test_rsa_kem_decap_serialization(self):
        """
        GIVEN an RSA Decap key.
        WHEN the key is serialized and deserialized.
        THEN the deserialized key should be equal to the original key.
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file_path = tmp_file.name
            save_key(self.decap_key, tmp_file_path)

        key = load_private_key_from_file(tmp_file_path)
        self.assertEqual(self.decap_key.public_key(), key.public_key())

if __name__ == "__main__":
    unittest.main()