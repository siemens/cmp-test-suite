# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import HSSPublicKey
from resources import utils
from resources.certutils import parse_certificate, load_public_key_from_cert, verify_cert_signature


class TestLoadHssRFCCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rfc_cert_path = "data/rfc_test_vectors/hss_x509_cert_example.pem"

    def test_load_hss_rfc_cert(self):
        """
        GIVEN an HSS X.509 certificate from the RFC test vectors.
        WHEN loading the certificate.
        THEN the certificate should be loaded successfully without errors.
        """
        der_data = utils.load_and_decode_pem_file(self.rfc_cert_path)
        cert = parse_certificate(der_data)
        public_key = load_public_key_from_cert(cert)
        self.assertIsInstance(public_key, HSSPublicKey)

    def test_hss_rfc_verify_cert(self):
        """
        GIVEN an HSS X.509 certificate from the RFC test vectors.
        WHEN verifying the certificate signature,
        THEN signature verification should succeed without errors.
        """
        der_data = utils.load_and_decode_pem_file(self.rfc_cert_path)
        cert = parse_certificate(der_data)
        verify_cert_signature(cert)

    def test_hss_rfc_cert_load_and_save_same_public_key(self):
        """
        GIVEN an HSS X.509 certificate from the RFC test vectors.
        WHEN loading and then saving the public key.
        THEN the saved public key should match the original public key in the certificate.
        """
        der_data = utils.load_and_decode_pem_file(self.rfc_cert_path)
        cert = parse_certificate(der_data)
        public_key = load_public_key_from_cert(cert)
        saved_pub_bytes = public_key.public_bytes_raw()

        # Load again from saved bytes
        loaded_pub_key = HSSPublicKey.from_public_bytes(saved_pub_bytes)
        self.assertEqual(public_key.public_bytes_raw(), loaded_pub_key.public_bytes_raw())
        spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
        self.assertEqual(public_key.public_bytes_raw(), spki["subjectPublicKey"].asOctets())

if __name__ == "__main__":
    unittest.main()