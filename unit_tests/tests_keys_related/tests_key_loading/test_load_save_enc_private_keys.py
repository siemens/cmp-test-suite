# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.key_pyasn1_utils import load_enc_key
from pq_logic.keys.serialize_utils import prepare_enc_key_pem
from pq_logic.keys.pq_key_factory import PQKeyFactory


class TestEncryptedKeys(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.password =  "secure_password"

    def test_trad_key_encryption_decryption(self):
        """
        GIVEN a traditional key.
        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [
            ("X25519", x25519.X25519PrivateKey.generate()),
            ("X448", x448.X448PrivateKey.generate()),
            ("ED25519", ed25519.Ed25519PrivateKey.generate()),
            ("ED448", ed448.Ed448PrivateKey.generate()),
            ("RSA", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("EC", ec.generate_private_key(ec.SECP256R1()))
        ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)

    def test_pq_key_enc_decryption(self):
        """
        GIVEN a pq key.
        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [("ML-KEM", PQKeyFactory.generate_pq_key("ml-kem-768")),
                     ("ML-DSA", PQKeyFactory.generate_pq_key("ml-dsa-65")),
                     ("SLH-DSA", PQKeyFactory.generate_pq_key("slh-dsa")),
                     ]

        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(decrypted_key)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())


    def test_composite_sig_enc_decryption(self):
        """
        GIVEN a composite signature key.
        WHEN the key is encrypted and decrypted,
        THEN the decrypted key should be equal to the original key.
        """
        key_cases = [("COMPOSITE-SIG",
                      CombinedKeyFactory.generate_key(algorithm="composite-sig",
                                                      trad_name="rsa", length=2048)),
                      ("COMPOSITE-SIG",
                       CombinedKeyFactory.generate_key(algorithm="composite-sig",
                                                       trad_name="ed25519")),
                       ("COMPOSITE-SIG",
                        CombinedKeyFactory.generate_key(algorithm="composite-sig",
                                                        trad_name="ed448")),
                     ]


        for key_name, private_key in key_cases:
            with self.subTest(key_name=key_name):
                one_asym_key = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )

                pem_data = prepare_enc_key_pem(self.password, one_asym_key, key_name.encode("utf-8"))
                decrypted_key = load_enc_key(password=self.password, data=pem_data)
                self.assertEqual(decrypted_key, one_asym_key)
                loaded_key = CombinedKeyFactory.load_private_key_from_one_asym_key(decrypted_key)
                self.assertEqual(loaded_key.public_key(), private_key.public_key())





if __name__ == "__main__":
    unittest.main()
