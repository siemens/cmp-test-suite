# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pq_logic.hybrid_structures import MLKEM512PrivateKeyASN1, MLKEM768PrivateKeyASN1, MLKEM1024PrivateKeyASN1
from pyasn1.codec.der import decoder
from pyasn1_alt_modules.rfc5958 import OneAsymmetricKey

from resources import utils


class TestMLKEMChoicesLoading(unittest.TestCase):
    """Test the MLKEMChoicesWithRFC class."""

    @classmethod
    def setUpClass(cls):
        cls.dir_name = "./data/rfc_test_vectors"

    def test_mlkem512_seed_key(self):
        """
        GIVEN the Test vector seed for ML-KEM-512.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mlkem512_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.1", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM512PrivateKeyASN1())

        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()

        expected_hex = (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
            "1f202122232425262728292a2b2c2d2e2f30313233343536"
            "3738393a3b3c3d3e3f"
        )
        self.assertEqual(seed_val.hex(), expected_hex)

    def test_mlkem512_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-KEM-512.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mlkem512_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.1", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM512PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 1632)

    def test_mlkem512_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-KEM-512.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mlkem512_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)

        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.1", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()

        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM512PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 1632)

        seed_val = private_key["both"]["seed"].asOctets()
        self.assertEqual(
            seed_val.hex(),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
                "1f202122232425262728292a2b2c2d2e2f30313233343536"
                "3738393a3b3c3d3e3f"
            ),
        )

    def test_mlkem768_seed(self):
        """
        GIVEN the Test vector seed for ML-KEM-768.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mlkem768_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.2", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM768PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()
        self.assertEqual(
            seed_val.hex(),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a"
                "1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536373"
                "8393a3b3c3d3e3f"
            ),
        )

    def test_mlkem768_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-KEM-768.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mlkem768_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.2", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM768PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 2400)

    def test_mlkem768_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-KEM-768.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mlkem768_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.2", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM768PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 2400)

        seed_val = private_key["both"]["seed"].asOctets()
        self.assertEqual(
            seed_val.hex(),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a"
                "1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536373"
                "8393a3b3c3d3e3f"
            ),
        )

    def test_mlkem1024_seed(self):
        """
        GIVEN the Test vector seed for ML-KEM-1024.
        WHEN the test vector is loaded,
        THEN the seed value should be equal to the expected value.
        """
        fpath = "mlkem1024_rfc_cert_draft_seed.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.3", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM1024PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "seed")
        seed_val = private_key["seed"].asOctets()
        self.assertEqual(
            seed_val.hex(),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212"
                "2232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
        )

    def test_mlkem1024_expanded_key(self):
        """
        GIVEN the Test vector expandedKey for ML-KEM-1024.
        WHEN the test vector is loaded,
        THEN the expandedKey value should be equal to the expected value.
        """
        fpath = "mlkem1024_rfc_cert_draft_expanded.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.3", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM1024PrivateKeyASN1())
        self.assertEqual(private_key.getName(), "expandedKey")
        expanded_key_val = private_key["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 3168)

    def test_mlkem1024_both(self):
        """
        GIVEN the Test vector with the `both` Sequence set, for ML-KEM-1024.
        WHEN the test vector is loaded,
        THEN the `both` values should be equal to the expected value.
        """
        fpath = "mlkem1024_rfc_cert_draft_both.pem"
        filename = os.path.join(self.dir_name, fpath)
        der_data = utils.load_and_decode_pem_file(filename)
        decoded_data, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
        self.assertEqual("2.16.840.1.101.3.4.4.3", str(decoded_data["privateKeyAlgorithm"]["algorithm"]))
        private_key_data = decoded_data["privateKey"].asOctets()
        private_key, _ = decoder.decode(private_key_data, asn1Spec=MLKEM1024PrivateKeyASN1())

        self.assertEqual(private_key.getName(), "both")
        expanded_key_val = private_key["both"]["expandedKey"].asOctets()
        self.assertEqual(len(expanded_key_val), 3168)

        seed_val = private_key["both"]["seed"].asOctets()
        self.assertEqual(
            seed_val.hex(),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212"
                "2232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
        )
