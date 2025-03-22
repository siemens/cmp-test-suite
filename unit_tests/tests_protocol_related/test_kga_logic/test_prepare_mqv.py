# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der.decoder import decode
from pyasn1_alt_modules import rfc5753
from resources.envdatautils import prepare_mqv_user_keying_material


class TestPrepareMQVUserKeyingMaterial(unittest.TestCase):
    def test_prepare_mqv_user_keying_material(self):
        """
        GIVEN an elliptic curve private key.
        WHEN `prepare_mqv_user_keying_material` is called without additional ukm.
        THEN the resulting MQV user keying material should contain the correct ephemeral public key
        and have no value for `addedukm`.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        mqv_ukm = prepare_mqv_user_keying_material(private_key)

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )

        originator_public_key, _ = decode(public_key_bytes, rfc5753.OriginatorPublicKey())
        self.assertEqual(mqv_ukm["ephemeralPublicKey"], originator_public_key)

        decoded_public_key = serialization.load_der_public_key(public_key_bytes)
        self.assertEqual(decoded_public_key.public_numbers(), private_key.public_key().public_numbers())

        self.assertFalse(mqv_ukm["addedukm"].isValue)

    def test_prepare_mqv_user_keying_material_with_ukm(self):
        """
        GIVEN an elliptic curve private key and an additional user keying material (ukm).
        WHEN `prepare_mqv_user_keying_material` is called with additional UKM.
        THEN the resulting MQV user keying material should contain the correct ephemeral public key
        and the provided `addedukm` value.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        added_ukm = b"test_user_keying_material"
        mqv_ukm = prepare_mqv_user_keying_material(private_key, added_ukm=added_ukm)

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )

        originator_public_key, _ = decode(public_key_bytes, rfc5753.OriginatorPublicKey())
        self.assertEqual(mqv_ukm["ephemeralPublicKey"], originator_public_key)

        decoded_public_key = serialization.load_der_public_key(public_key_bytes)
        self.assertEqual(decoded_public_key.public_numbers(), private_key.public_key().public_numbers())

        self.assertEqual(mqv_ukm["addedukm"], added_ukm)


if __name__ == "__main__":
    unittest.main()
