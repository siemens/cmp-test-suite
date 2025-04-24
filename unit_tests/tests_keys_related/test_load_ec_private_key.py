# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc5915, rfc5958

from pq_logic.keys.trad_key_factory import parse_trad_key_from_one_asym_key
from pq_logic.keys.serialize_utils import prepare_ec_private_key
from resources.envdatautils import prepare_one_asymmetric_key
from resources.keyutils import generate_key


class TestLoadECPrivateKey(unittest.TestCase):

    def test_load_ec_private_key(self):
        """
        GIVEN an EC private key.
        WHEN the key is loaded from a DER encoded format.
        THEN the loaded key should match the original key.
        """
        private_key = generate_key("ecc")

        asn1_ec_private_key = prepare_ec_private_key(private_key)

        asn1_loaded_key = serialization.load_der_private_key(
            encoder.encode(asn1_ec_private_key),
            password=None
        )
        self.assertEqual(asn1_loaded_key.public_key(), private_key.public_key())
        self.assertEqual(asn1_loaded_key.private_numbers(), private_key.private_numbers())


        encoded_key = private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key_info, _ = decoder.decode(encoded_key, asn1Spec=rfc5958.OneAsymmetricKey())
        inner_der = private_key_info['privateKey'].asOctets()
        ec_private_key, _ = decoder.decode(inner_der, asn1Spec=rfc5915.ECPrivateKey())
        ec_private_key = parse_trad_key_from_one_asym_key(one_asym_key=private_key_info, must_be_version_2=False)

        self.assertEqual(ec_private_key.public_key(), private_key.public_key())
        self.assertEqual(ec_private_key.private_numbers(), private_key.private_numbers())

    def test_ecc_prepare_and_load(self):
        """
        GIVEN an EC private key.
        WHEN the key is prepared and then loaded.
        THEN the loaded key should match the original key.
        """
        private_key = generate_key("ecc")
        one_asym_key = prepare_one_asymmetric_key(
            private_key,
            version="v2"
        )
        loaded_key = parse_trad_key_from_one_asym_key(one_asym_key)
        self.assertEqual(loaded_key.public_key(), private_key.public_key())
        self.assertEqual(loaded_key.private_numbers(), private_key.private_numbers())
