# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey


class TestMLDSAKeyGen(unittest.TestCase):

    def test_derive_public_key(self):
        """
        GIVEN an ML-KEM private key.
        WHEN the public key is derived.
        THEN the public key should be derived successfully.
        """
        private_key = MLDSAPrivateKey(alg_name="ml-dsa-44")
        private_bytes = private_key.private_bytes_raw()
        private_key2 = MLDSAPrivateKey.from_private_bytes(data=private_bytes, name="ml-dsa-44")
        pub_raw = private_key2.public_key().public_bytes_raw()
        self.assertEqual(private_key.public_key().public_bytes_raw(), pub_raw)

    def test_load_from_seed(self):
        """
        GIVEN a seed and an ML-DSA private key.
        WHEN a key is generated from the seed.
        THEN the key should be generated successfully.
        """
        seed = b"A" * 32
        private_key = MLDSAPrivateKey(alg_name="ml-dsa-44", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        key2 = MLDSAPrivateKey.from_seed(
            seed=private_key._export_private_key(),
            alg_name="ml-dsa-44",
        )
        self.assertEqual(key2._export_private_key().hex(), seed.hex())
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())

        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())

    def test_load_from_private_bytes(self):
        """
        GIVEN a seed and an ML-DSA private key.
        WHEN a key is generated from the seed.
        THEN the key should be generated successfully.
        """

        seed = b"A" * 32
        private_key = MLDSAPrivateKey(alg_name="ml-dsa-44", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        key2 = MLDSAPrivateKey.from_private_bytes(
            data=private_key._export_private_key(),
            name="ml-dsa-44",
        )

        self.assertEqual(key2._export_private_key().hex(), seed.hex())
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())

        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())

    def test_load_from_seed_asym_one_mldsa(self):
        """
        GIVEN a seed and an ML-DSA `OneAsymmetricKey` structure.
        WHEN a key is generated from the seed and loaded from the `OneAsymmetricKey` structure.
        THEN the key should be generated successfully.
        """
        seed = b"A" * 32
        private_key = MLDSAPrivateKey(alg_name="ml-dsa-44", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        one_asym_key, rest = decoder.decode(private_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")

        priv_key2 = MLDSAPrivateKey.from_private_bytes(
            data=one_asym_key["privateKey"].asOctets(),
            name="ml-dsa-44",
        )

        self.assertEqual(priv_key2._export_private_key(), seed)

        out = one_asym_key["publicKey"].asOctets()
        self.assertEqual(out, private_key.public_key().public_bytes_raw())
        pub_key = MLDSAPublicKey.from_public_bytes(data=out, name="ml-dsa-44")
        self.assertEqual(pub_key.public_bytes_raw(), private_key.public_key().public_bytes_raw())

        key2 = CombinedKeyFactory.load_key_from_one_asym_key(private_bytes)
        
        self.assertEqual(key2._export_private_key().hex(), seed.hex())


