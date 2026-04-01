# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List

from pyasn1_alt_modules import rfc9480
from resources.certutils import build_cmp_chain_from_pkimessage
from resources.cmputils import prepare_extra_certs

from unit_tests.prepare_ca_response import build_ca_pki_message
from unit_tests.utils_for_test import (
    build_pkimessage,
    compare_pyasn1_objects,
    load_or_generate_cert_chain,
    pretty_print_chain_subject_and_issuer,
)


class TestCheckIfChainInOrder(unittest.TestCase):
    def setUp(self):
        cert_chain, _ = load_or_generate_cert_chain()
        self.cert_chain: List[rfc9480.CMPCertificate] = cert_chain
        self.root_cert = self.cert_chain[0]
        # expects the chain to start from the end-entity
        self.cert_chain = cert_chain[::-1]
        self.ee_cert = self.cert_chain[0]

    def test_cert_chain_from_pki_message_cmp_certs(self):
        """
        GIVEN a PKI message with extra certificates added
        WHEN building a certificate chain from the message
        THEN the resulting chain should have the expected length of 6
        """
        extra_certs = prepare_extra_certs(certs=self.cert_chain)
        pki_message = build_pkimessage()
        pki_message["extraCerts"] = extra_certs
        cert_chain = build_cmp_chain_from_pkimessage(pki_message)
        self.assertEqual(len(cert_chain), 6)
        self.assertEqual(cert_chain[0], self.cert_chain[0])
        self.assertEqual(cert_chain[-1], self.root_cert)

    def test_cert_chain_from_pki_message_issued_cert(self):
        """
        GIVEN a PKI message with extra certificates added but without the ee certificate.
        WHEN building a certificate chain from the PKI message,
        THEN the resulting chain should have the expected length of 6
        """
        # excludes the ee-cert from List
        extra_certs = prepare_extra_certs(certs=self.cert_chain[1:])
        pki_message = build_ca_pki_message(body_type="ip", cert=self.cert_chain[0])
        pki_message["extraCerts"] = extra_certs
        cert_chain = build_cmp_chain_from_pkimessage(pki_message, for_issued_cert=True, cert_number=0)
        self.assertEqual(len(cert_chain), 6)
        self.assertTrue(compare_pyasn1_objects(cert_chain[0], self.cert_chain[0]))
        self.assertTrue(compare_pyasn1_objects(cert_chain[-1], self.root_cert))

    def test_cert_chain_from_pki_message_issued_cert_with_caPubs(self):
        """
        GIVEN a PKI message with extra certificates added but without the ee certificate and root certificate
        WHEN building a certificate chain from the PKI message,
        THEN the resulting chain should have the expected length of 6
        """
        # excludes the ee-cert from List
        extra_certs = prepare_extra_certs(certs=self.cert_chain[1:-1])
        pki_message = build_ca_pki_message(body_type="ip", cert=self.cert_chain[0], ca_pubs=[self.root_cert])
        pki_message["extraCerts"] = extra_certs
        cert_chain = build_cmp_chain_from_pkimessage(pki_message, for_issued_cert=True, cert_number=0)
        print(pretty_print_chain_subject_and_issuer(cert_chain))
        self.assertEqual(len(cert_chain), 6)
        self.assertTrue(compare_pyasn1_objects(cert_chain[0], self.cert_chain[0]))
        self.assertTrue(compare_pyasn1_objects(cert_chain[-1], self.root_cert))
