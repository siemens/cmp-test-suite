# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.kem_keys import FrodoKEMPrivateKey, FrodoKEMPublicKey

class TestFrodoKEMKeyGen(unittest.TestCase):


    def test_load_from_seed_asym_one_frodokem(self):
        """
        GIVEN a seed and a `OneAsymmetricKey` structure.
        WHEN a key is generated from the seed and loaded from the `OneAsymmetricKey` structure.
        THEN the key should be generated successfully.
        """
        private_key = FrodoKEMPrivateKey(alg_name="frodokem-640-aes")

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        one_asym_key, rest = decoder.decode(private_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")

        _ = FrodoKEMPrivateKey.from_private_bytes(
            data=one_asym_key["privateKey"].asOctets(),
            name="frodokem-640-aes",
        )

        out = one_asym_key["publicKey"].asOctets()
        self.assertEqual(out, private_key.public_key().public_bytes_raw())
        pub_key = FrodoKEMPublicKey.from_public_bytes(data=out, name="frodokem-640-aes")
        self.assertEqual(pub_key.public_bytes_raw(), private_key.public_key().public_bytes_raw())

        key2 = CombinedKeyFactory.load_private_key_from_one_asym_key(private_bytes)
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())
        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())
