# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.sig_keys import SLHDSAPrivateKey, SLHDSAPublicKey


class TestSLHDSAKeyGen(unittest.TestCase):

    def test_derive_public_key(self):
        """
        GIVEN an SLH-DSA private key.
        WHEN the public key is derived.
        THEN the public key should be derived successfully.
        """
        private_key = SLHDSAPrivateKey(alg_name="slh-dsa-sha2-128s")
        private_bytes = private_key.private_bytes_raw()
        private_key2 = SLHDSAPrivateKey.from_private_bytes(data=private_bytes, name="slh-dsa-sha2-128s")
        pub_raw = private_key2.public_key().public_bytes_raw()
        self.assertEqual(private_key.public_key().public_bytes_raw(), pub_raw)

    def test_load_from_seed(self):
        """
        GIVEN a seed.
        WHEN load_from_seed is called,
        THEN a key is generated.
        """
        n = 16
        seed_size = 48
        pub_size = 32
        priv_size = 64
        key = SLHDSAPrivateKey(alg_name="slh-dsa-sha2-128s")
        seed = key._export_private_key()
        self.assertEqual(len(seed), 48)
        loaded_key = SLHDSAPrivateKey.from_seed(alg_name="slh-dsa-sha2-128s", seed=seed)

        self.assertEqual(loaded_key.private_bytes_raw(), key.private_bytes_raw())
        self.assertEqual(loaded_key._export_private_key(), key._export_private_key())

        self.assertEqual(len(key.private_bytes_raw()), 64)
        self.assertEqual(len(loaded_key.private_bytes_raw()), 64)

        self.assertEqual(loaded_key.public_key(), key.public_key())
        self.assertEqual(len(loaded_key.public_key().public_bytes_raw()), 32)

    def test_load_from_seed2(self):
        """
        GIVEN a seed and a key.
        WHEN a key is generated from the seed.
        THEN the key should be generated successfully.
        """
        seed = b"A" * 48
        private_key = SLHDSAPrivateKey(alg_name="slh-dsa-sha2-128s", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        key2 = SLHDSAPrivateKey.from_seed(
            seed=private_key._export_private_key(),
            alg_name="slh-dsa-sha2-128s",
        )
        self.assertEqual(key2._export_private_key().hex(), seed.hex())
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())

        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())

    def test_load_from_private_bytes(self):
        """
        GIVEN a seed and a key.
        WHEN a key is generated from the seed.
        THEN the key should be generated successfully.
        """

        seed = b"A" * 48
        private_key = SLHDSAPrivateKey(alg_name="slh-dsa-sha2-128s", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        key2 = SLHDSAPrivateKey.from_private_bytes(
            data=private_key._export_private_key(),
            name="slh-dsa-sha2-128s",
        )

        self.assertEqual(key2._export_private_key().hex(), seed.hex())
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())

        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())

    def test_load_from_seed_asym_one(self):
        """
        GIVEN a seed and a `OneAsymmetricKey` structure.
        WHEN a key is generated from the seed and loaded from the `OneAsymmetricKey` structure.
        THEN the key should be generated successfully.
        """
        seed = b"A" * 48
        private_key = SLHDSAPrivateKey(alg_name="slh-dsa-sha2-128s", seed=seed)
        self.assertEqual(private_key._export_private_key().hex(), seed.hex())

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        one_asym_key, rest = decoder.decode(private_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")

        priv_key2 = SLHDSAPrivateKey.from_private_bytes(
            data=one_asym_key["privateKey"].asOctets(),
            name="slh-dsa-sha2-128s",
        )

        self.assertEqual(priv_key2._export_private_key(), seed)

        out = one_asym_key["publicKey"].asOctets()
        self.assertEqual(out, private_key.public_key().public_bytes_raw())
        pub_key = SLHDSAPublicKey.from_public_bytes(data=out, name="slh-dsa-sha2-128s")
        self.assertEqual(pub_key.public_bytes_raw(), private_key.public_key().public_bytes_raw())

        key2 = CombinedKeyFactory.load_private_key_from_one_asym_key(private_bytes)
        self.assertEqual(key2._export_private_key().hex(), seed.hex())


