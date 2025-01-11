# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List

from pyasn1_alt_modules import rfc9480
from resources.certutils import verify_cert_chain_openssl

from unit_tests.utils_for_test import load_or_generate_cert_chain


class TestVerifyCertChainOpenssl(unittest.TestCase):
    def setUp(self):
        cert_chain, _ = load_or_generate_cert_chain()
        self.cert_chain: List[rfc9480.CMPCertificate] = cert_chain
        self.root_cert = self.cert_chain[0]
        self.ca1_cert = self.cert_chain[1]
        self.ca2_cert = self.cert_chain[2]
        # expects the chain to start from the end-entity
        self.cert_chain = cert_chain[::-1]

    def test_verify_single_cert(self):
        """
        GIVEN a valid self-signed certificate
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.root_cert])

    def test_verify_two_certs(self):
        """
        GIVEN a valid certificate chain (Intermediate, Root)
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.ca1_cert, self.root_cert])

    def test_verify_three_certs(self):
        """
        GIVEN a valid certificate chain (End-Entity, Intermediate, Root)
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl([self.ca2_cert, self.ca1_cert, self.root_cert])

    def test_verify_more_certs(self):
        """
        GIVEN a valid certificate chain starting from End-Entity, to Root, with length 6.
        WHEN the chain is validated using OpenSSL,
        THEN the chain should be successfully validated without any errors
        """
        verify_cert_chain_openssl(self.cert_chain)
