# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.sig_keys import FalconPrivateKey, FalconPublicKey

class TestFalconKeyGen(unittest.TestCase):

    def test_load_from_seed_asym_one_falcon(self):
        """
        GIVEN a seed and a `OneAsymmetricKey` structure.
        WHEN a key is generated from the seed and loaded from the `OneAsymmetricKey` structure.
        THEN the key should be generated successfully.
        """
        private_key = FalconPrivateKey(alg_name="falcon-512")

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        one_asym_key, rest = decoder.decode(private_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")

        priv_key2 = FalconPrivateKey.from_private_bytes(
            data=one_asym_key["privateKey"].asOctets(),
            name="falcon-512",
        )
        self.assertEqual(priv_key2.private_bytes_raw(), private_key.private_bytes_raw())

        out = one_asym_key["publicKey"].asOctets()
        self.assertEqual(out, private_key.public_key().public_bytes_raw())
        pub_key = FalconPublicKey.from_public_bytes(data=out, name="falcon-512")
        self.assertEqual(pub_key.public_bytes_raw(), private_key.public_key().public_bytes_raw())

        key2 = CombinedKeyFactory.load_key_from_one_asym_key(private_bytes)
        self.assertEqual(key2.private_bytes_raw(), private_key.private_bytes_raw())
        self.assertEqual(key2.public_key().public_bytes_raw(), private_key.public_key().public_bytes_raw())