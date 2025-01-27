# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_csr, generate_certificate, build_cert_from_csr
from resources.keyutils import generate_key, load_public_key_from_spki
from resources.utils import get_openssl_name_notation


class TestPrepareCertFromCsr(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pq_key = generate_key("ml-dsa-65")
        cls.ca_cert = generate_certificate(cls.pq_key, "CN=Test CA")

    def test_prepare_composite_cert(self):
        """
        GIVEN a valid Composite CSR.
        WHEN preparing a certificate from the CSR,
        THEN the certificate is valid.
        """
        comp_key = generate_key("composite-sig")
        csr = build_csr(comp_key, common_name="CN=Test Composite")
        cert = build_cert_from_csr(csr=csr,
                                   ca_key=self.pq_key,
                                   ca_cert=self.ca_cert
                                   )

        name = get_openssl_name_notation(cert['tbsCertificate']['subject'])
        self.assertEqual(name, "CN=Test Composite")
        public_key = load_public_key_from_spki(cert['tbsCertificate']['subjectPublicKeyInfo'])
        self.assertEqual(public_key,
                         comp_key.public_key())

    def test_prepare_pq_cert(self):
        """
        GIVEN a valid PQ CSR.
        WHEN preparing a certificate from the CSR,
        THEN the certificate is valid.
        """
        pq_key = generate_key("ml-dsa-65")
        csr = build_csr(pq_key, common_name="CN=Test PQ")
        cert = build_cert_from_csr(csr=csr,
                                   ca_key=self.pq_key,
                                   ca_cert=self.ca_cert
                                   )
        name = get_openssl_name_notation(cert['tbsCertificate']['subject'])
        self.assertEqual(name, "CN=Test PQ")
        public_key = load_public_key_from_spki(cert['tbsCertificate']['subjectPublicKeyInfo'])
        self.assertEqual(public_key,
                         pq_key.public_key())

