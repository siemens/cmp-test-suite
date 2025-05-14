# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import load_public_key_from_cert, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestLoadKeyFromCert(unittest.TestCase):

    def test_load_kem_key(self):
        """
        GIVEN a ml-kem certificate and a ml-kem private key.
        WHEN loading the public key from the certificate and the public key from the private key.
        THEN the public keys should be equal.
        """
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_cert_ml_kem_768.pem"))
        loaded_key = load_public_key_from_cert(cert)
        self.assertTrue(loaded_key == load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem").public_key())

    def load_ml_dsa_key(self):
        """
        GIVEN a ml-dsa certificate and a ml-dsa private key.
        WHEN loading the public key from the certificate and the public key from the private key.
        THEN the public keys should be equal.
        """
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))
        loaded_key = load_public_key_from_cert(cert)
        self.assertTrue(loaded_key == load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem").public_key())

    def test_slh_dsa_key(self):
        """
        GIVEN a slh-dsa certificate and a slh-dsa private key.
        WHEN loading the public key from the certificate and the public key from the private key.
        THEN the public keys should be equal.
        """
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem"))
        loaded_key = load_public_key_from_cert(cert)
        self.assertTrue(loaded_key == load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f-seed.pem").public_key())


    def test_load_xwing_key(self):
        """
        GIVEN xwing certificates and xwing private keys.
        WHEN loading the public key from the certificate and the public key from the private key.
        THEN the public keys should be equal.
        """
        xwing_cert_other = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing_other.pem"))
        xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))
        xwing_key = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
        xwing_key_other = load_private_key_from_file("data/keys/private-key-xwing-other-seed.pem")
        self.assertTrue(load_public_key_from_cert(xwing_cert) == xwing_key.public_key())
        self.assertTrue(load_public_key_from_cert(xwing_cert_other) == xwing_key_other.public_key())
