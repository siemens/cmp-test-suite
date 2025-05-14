# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pq_logic.hybrid_structures import MLDSA87PrivateKeyASN1, MLDSA65PrivateKeyASN1, MLDSA44PrivateKeyASN1
from pyasn1.codec.der import decoder
from pyasn1_alt_modules.rfc5958 import OneAsymmetricKey

from resources import utils


class TestMLKEMChoicesLoading(unittest.TestCase):
    """Test the MLKEMChoicesWithRFC class."""

    @classmethod
    def setUpClass(cls):
        cls.dir_name = "./data/rfc_test_vectors"

    def test_mldsa44_seed_key(self):
        """
        GIVEN the Test vector seed for ML-DSA-44.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mldsa44_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        private_key_data = decoded_data["privateKey"].asOctets()
        self.assertEqual("2.16.840.1.101.3.4.3.17", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA44PrivateKeyASN1())

        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()

        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(seed_val.hex(), expected_hex)

    def test_mldsa44_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-DSA-44.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mldsa44_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA44PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 2560)

    def test_mldsa44_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-DSA-44.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mldsa44_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA44PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 2560)
        seed_val = private_key["both"]["seed"].asOctets()
        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(expected_hex, seed_val.hex())

    def test_mldsa65_seed(self):
        """
        GIVEN the Test vector seed for ML-DSA-65.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mldsa65_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        private_key_data = decoded_data["privateKey"].asOctets()

        self.assertEqual("2.16.840.1.101.3.4.3.18", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA65PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()
        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(len(seed_val), 32)
        self.assertEqual(seed_val.hex(), expected_hex)

    def test_mldsa65_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-DSA-65.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mldsa65_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.3.18", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA65PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 4032)

    def test_mldsa65_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-DSA-65.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mldsa65_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.3.18", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA65PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 4032)
        seed_val = private_key["both"]["seed"].asOctets()
        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(expected_hex, seed_val.hex())

    def test_mldsa87_seed(self):
        """
        GIVEN the Test vector seed for ML-DSA-87.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mldsa87_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        private_key_data = decoded_data["privateKey"].asOctets()

        self.assertEqual("2.16.840.1.101.3.4.3.19", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA87PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()
        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(len(seed_val), 32)
        self.assertEqual(expected_hex, seed_val.hex())

    def test_mldsa87_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-DSA-87.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mldsa87_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.3.19", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA87PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 4896)

    def test_mldsa87_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-DSA-87.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mldsa87_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.3.19", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLDSA87PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 4896)
        seed_val = private_key["both"]["seed"].asOctets()
        expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        self.assertEqual(expected_hex, seed_val.hex())
