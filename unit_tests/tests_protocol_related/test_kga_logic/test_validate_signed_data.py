# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import encoder
from resources import utils
from resources.ca_kga_logic import validate_signed_data_structure
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_asymmetric_key_package, prepare_signed_data
from resources.keyutils import generate_key, load_private_key_from_file
from resources.oid_mapping import sha_alg_name_to_oid


class TestCheckSignedData(unittest.TestCase):
    def setUp(self):
        self.trustanchors = "data/unittest"
        self.trusted_root = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem")
        )
        self.root_key = load_private_key_from_file(
            "data/keys/private-key-ed25519.pem", key_type="ed25519"
        )

        # Load KGA certificate and key
        self.kga_certificate = parse_certificate(
            utils.load_and_decode_pem_file("data/unittest/kga_cert_kari_ecdsa.pem")
        )
        self.kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

        self.dig_alg_id = sha_alg_name_to_oid("sha256")
        self.new_key_rsa = generate_key("rsa")
        e_content_data = encoder.encode(prepare_asymmetric_key_package(private_keys=[self.new_key_rsa]))
        self.signed_data = prepare_signed_data(
            signing_key=self.kga_key, cert=self.kga_certificate,
            e_content=e_content_data, sig_hash_name="sha512",
            cert_chain=[self.kga_certificate, self.trusted_root]
        )

    def test_valid_signed_data_with_rsa_key(self):
        """
        GIVEN a valid SignedData structure using an RSA key.
        WHEN validate_signed_data_structure is called.
        THEN it should return the correct RSAPrivateKey, and the public key should match the provided RSA key.
        """
        e_content_data = encoder.encode(prepare_asymmetric_key_package(
            private_keys=[self.new_key_rsa]))

        self.signed_data = prepare_signed_data(
            cert_chain=[self.kga_certificate, self.trusted_root],
            signing_key=self.kga_key,
            cert=self.kga_certificate,
            e_content=e_content_data, sig_hash_name="sha512"
        )


        private_key = validate_signed_data_structure(self.signed_data, trustanchors=self.trustanchors)
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.public_key(), self.new_key_rsa.public_key())

    def test_valid_signed_data_with_ec_key(self):
        """
        GIVEN a valid SignedData structure using an EC key
        WHEN validate_signed_data_structure is called.
        THEN it should return the correct RSAPrivateKey, and the public key should match the newly generated RSA key.
        """
        new_key = generate_key("rsa")

        e_content_data = encoder.encode(prepare_asymmetric_key_package(private_keys=[new_key]))
        self.signed_data = prepare_signed_data(
            cert_chain=[self.kga_certificate, self.trusted_root],
            signing_key=self.kga_key, cert=self.kga_certificate,
            e_content=e_content_data, sig_hash_name="sha512"
        )

        private_key = validate_signed_data_structure(self.signed_data, trustanchors=self.trustanchors)
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.public_key(), new_key.public_key())

    def test_valid_signed_data_with_invalid_sig(self):
        """
        GIVEN a SignedData structure with an intentionally invalid signature.
        WHEN validate_signed_data_structure is called.
        THEN it should raise an InvalidSignature exception, indicating the signature is incorrect.
        """
        e_content_data = encoder.encode(prepare_asymmetric_key_package(private_keys=[self.new_key_rsa]))
        self.signed_data = prepare_signed_data(
            cert_chain=[self.kga_certificate, self.trusted_root],
            signing_key=self.kga_key,
            cert=self.kga_certificate,
            e_content=e_content_data,
            sig_hash_name="sha512",
            negative_signature=True,
        )

        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            validate_signed_data_structure(self.signed_data, trustanchors=self.trustanchors)

    def test_valid_signed_data_with_different_digest_and_sig(self):
        """
        GIVEN a SignedData structure where the digest and signature algorithms are mismatched
        WHEN validate_signed_data_structure is called.
        THEN it should raise a ValueError indicating the mismatch between digest and signature algorithms.
        """
        e_content_data = encoder.encode(prepare_asymmetric_key_package(private_keys=[self.new_key_rsa]))
        self.signed_data = prepare_signed_data(
            cert_chain=[self.kga_certificate, self.trusted_root],
            signing_key=self.kga_key,
            cert=self.kga_certificate,
            e_content=e_content_data,
            digest_hash_name="sha384",
            sig_hash_name="sha512",
            negative_signature=True,
        )

        with self.assertRaises(ValueError):
            validate_signed_data_structure(self.signed_data, trustanchors=self.trustanchors)


if __name__ == "__main__":
    unittest.main()
