# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.pq_key_factory import PQKeyFactory
from resources.certbuildutils import build_csr, generate_certificate
from resources.certutils import load_public_key_from_cert, verify_cert_signature
from resources.keyutils import load_public_key_from_spki
from resources.oidutils import id_ml_dsa_65_oid, id_ml_dsa_65_with_sha512


class TestMLDSASign(unittest.TestCase):

    def setUp(self):
        self.ml_dsa_key = PQKeyFactory.generate_pq_key("ml-dsa-65")

    def test_sign_cert(self):
        """
        GIVEN a certificate signed by an ML-DSA private key without a hash algorithm.
        WHEN the certificate is signed and `verify_cert_signature` is called,
        THEN the certificate should have a valid signature, used the correct signature algorithm
        and the loaded public key should match the original key.
        """
        cert = generate_certificate(private_key=self.ml_dsa_key, hash_alg=None, ski=False)
        tbs_cert_sig = cert["tbsCertificate"]["signature"]
        self.assertTrue(tbs_cert_sig.isValue)
        self.assertEqual(tbs_cert_sig["algorithm"], id_ml_dsa_65_oid)
        self.assertFalse(tbs_cert_sig["parameters"].isValue)
        public_key = self.ml_dsa_key.public_key()
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key.public_bytes_raw(), loaded_key.public_bytes_raw())
        verify_cert_signature(cert)

    def test_sign_cert_with_sha512(self):
        """
        GIVEN a certificate signed by an ML-DSA private key and SHA-512 as the hash algorithm.
        WHEN the certificate is signed and `verify_cert_signature` is called,
        THEN the certificate should have a valid signature, used the correct signature algorithm
        and the loaded public key should match the original key.
        """
        cert = generate_certificate(private_key=self.ml_dsa_key, hash_alg="sha512", ski=False)
        tbs_cert_sig = cert["tbsCertificate"]["signature"]
        self.assertTrue(tbs_cert_sig.isValue)
        self.assertEqual(tbs_cert_sig["algorithm"], id_ml_dsa_65_with_sha512)
        self.assertFalse(tbs_cert_sig["parameters"].isValue)
        public_key = self.ml_dsa_key.public_key()
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key.public_bytes_raw(), loaded_key.public_bytes_raw())
        verify_cert_signature(cert)

    def test_sign_csr(self):
        """
        GIVEN a CSR signed by an ML-DSA private key without a hash algorithm.
        WHEN the CSR is signed,
        THEN the CSR should have a valid signature algorithm
        and the loaded public key should match the original key.
        """
        csr = build_csr(signing_key=self.ml_dsa_key, hash_alg=None)
        sig_alg_id = csr["signatureAlgorithm"]
        self.assertTrue(sig_alg_id.isValue)
        self.assertEqual(sig_alg_id["algorithm"], id_ml_dsa_65_oid)
        self.assertFalse(sig_alg_id["parameters"].isValue)
        public_key = self.ml_dsa_key.public_key()
        spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
        loaded_key = load_public_key_from_spki(spki)
        self.assertEqual(public_key.public_bytes_raw(), loaded_key.public_bytes_raw())

    def test_sign_csr_with_sha512(self):
        """
        GIVEN a CSR signed by an ML-DSA private key and SHA-512 as the hash algorithm.
        WHEN the CSR is signed,
        THEN the CSR should have a valid signature algorithm
        and the loaded public key should match the original key.
        """
        csr = build_csr(signing_key=self.ml_dsa_key, hash_alg="sha512")
        sig_alg_id = csr["signatureAlgorithm"]
        self.assertTrue(sig_alg_id.isValue)
        self.assertEqual(sig_alg_id["algorithm"], id_ml_dsa_65_with_sha512)
        self.assertFalse(sig_alg_id["parameters"].isValue)
        public_key = self.ml_dsa_key.public_key()
        spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
        loaded_key = load_public_key_from_spki(spki)
        self.assertEqual(public_key.public_bytes_raw(), loaded_key.public_bytes_raw())

