# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc3447, rfc5915, rfc5958
from resources import keyutils
from resources.asn1utils import encode_to_der
from resources.envdatautils import prepare_one_asymmetric_key

from unit_tests.utils_for_test import crypto_lib_private_key_to_der, der_to_crypto_lib_private_key


class TestOneAsymKey(unittest.TestCase):
    def test_is_rsa_private_key_the_same(self):
        """
        GIVEN an RSA private key.
        WHEN the key is converted to ASN.1 format and then decoded back.
        THEN the public key generated from the decoded private key should match the original public key.
        """
        original_key = keyutils.generate_key("rsa")

        rsa_asn1_der = crypto_lib_private_key_to_der(original_key)

        decoded_asn1, rest = decoder.decode(rsa_asn1_der, asn1Spec=rfc3447.RSAPrivateKey())
        self.assertEqual(rest, b"")

        reloaded_private_key = der_to_crypto_lib_private_key(encode_to_der(decoded_asn1))

        original_public_key_pem = original_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        reloaded_public_key_pem = reloaded_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(original_public_key_pem, reloaded_public_key_pem)

    def test_is_ec_private_key_the_same(self):
        """
        GIVEN an EC (Elliptic Curve) private key.
        WHEN the key is converted to ASN.1 format and then decoded back.
        THEN the public key generated from the decoded private key should match the original public key.
        """
        original_key: ec.EllipticCurvePrivateKey = keyutils.generate_key("ec")

        ec_asn1_der = crypto_lib_private_key_to_der(original_key)

        decoded_asn1, rest = decoder.decode(ec_asn1_der, asn1Spec=rfc5915.ECPrivateKey())
        self.assertEqual(rest, b"")
        reloaded_private_key = der_to_crypto_lib_private_key(encode_to_der(decoded_asn1))

        original_public_key_pem = original_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        reloaded_public_key_pem = reloaded_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(original_public_key_pem, reloaded_public_key_pem)

    def test_prepare_one_asym_key_with_rsa(self):
        """
        GIVEN an RSA private key.
        WHEN the key is prepared as a OneAsymmetricKey structure.
        THEN both the publicKey and privateKey fields in the resulting ASN.1 structure should have values.
        """
        original_key = keyutils.generate_key("rsa")
        one_asym_key = prepare_one_asymmetric_key(private_key=original_key)
        der_data = encoder.encode(one_asym_key)
        decoded_asn1, rest = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")
        self.assertTrue(decoded_asn1["publicKey"].isValue)
        self.assertTrue(decoded_asn1["privateKey"].isValue)

    def test_prepare_one_asym_key_with_ec(self):
        """
        GIVEN an EC private key.
        WHEN the key is prepared as a OneAsymmetricKey structure.
        THEN both the publicKey and privateKey fields in the resulting ASN.1 structure should have values.
        """
        original_key = keyutils.generate_key("rsa")
        one_asym_key = prepare_one_asymmetric_key(private_key=original_key)
        der_data = encoder.encode(one_asym_key)
        decoded_asn1, rest = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())
        self.assertEqual(rest, b"")
        self.assertTrue(decoded_asn1["publicKey"].isValue)
        self.assertTrue(decoded_asn1["privateKey"].isValue)


if __name__ == "__main__":
    unittest.main()
