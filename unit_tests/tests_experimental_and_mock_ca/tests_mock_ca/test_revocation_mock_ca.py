# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from mock_ca.client import build_example_rsa_mac_request

from resources import certutils, cmputils, protectionutils
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.keyutils import load_private_key_from_file, generate_key
from resources.utils import load_and_decode_pem_file, display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestCertificateRevocation(unittest.TestCase):
    def setUp(self):
        self.ca_cert, self.ca_key = load_ca_cert_and_key()
        self.ca_handler = CAHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

    def test_revocation(self):
        """
        GIVEN a certificate.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        example_ir, key = build_example_rsa_mac_request("CN=Hans The Tester1")
        response = self.ca_handler.process_normal_request(example_ir)
        status = cmputils.get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted")
        cert = cmputils.get_cert_from_pkimessage(response)
        self.assertIsNotNone(cert)
        self.assertTrue(certutils.cert_in_list(cert, self.ca_handler.get_details("issued_certs")))

        rr = cmputils.build_cmp_revoke_request(cert=cert, reason="keyCompromise")
        protected_rr = protectionutils.protect_pkimessage(
            rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/"
        )
        response = self.ca_handler.process_normal_request(protected_rr)
        self.assertEqual(response["body"].getName(), "rp")
        status = cmputils.get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted")

    def test_revive(self):
        """
        GIVEN a certificate, which is already issued.
        WHEN a revocation request is processed and the certificate is revoked and a revive request is processed,
        THEN the certificate is successfully revived.
        """
        example_ir, key = build_example_rsa_mac_request("CN=Hans The Tester1")
        response = self.ca_handler.process_normal_request(example_ir)
        status = cmputils.get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted")
        cert = cmputils.get_cert_from_pkimessage(response)
        self.assertIsNotNone(cert)

        # Revoke the certificate
        rr = cmputils.build_cmp_revoke_request(cert=cert, reason="keyCompromise")
        protected_rr = protectionutils.protect_pkimessage(
            rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/"
        )
        self.ca_handler.process_normal_request(protected_rr)

        # Check revoked
        self.assertTrue(certutils.cert_in_list(cert, self.ca_handler.get_details("revoked_certs")))

        # Revive the certificate
        rr = cmputils.build_cmp_revive_request(cert=cert)
        protected_rr = protectionutils.protect_pkimessage(
            rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/"
        )
        response = self.ca_handler.process_normal_request(protected_rr)
        self.assertEqual(response["body"].getName(), "rp")
        status = cmputils.get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted")
        self.assertFalse(certutils.cert_in_list(cert, self.ca_handler.rev_handler.details()["revoked_certs"]))

    def test_simple_revocation(self):
        """
        GIVEN a certificate, which is already issued.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        ca_cert, ca_key = load_ca_cert_and_key()
        cert, _ = build_certificate(
            private_key=key,
            ca_key=ca_key,
            ca_cert=ca_cert,
        )

        self.ca_handler.add_cert_to_issued_certs(cert)

        rr = cmputils.build_cmp_revoke_request(cert=cert, reason="keyCompromise")
        protected_rr = protectionutils.protect_pkimessage(
            rr, "signature", private_key=key, cert=cert, certs_dir="data/unittest/"
        )
        response = self.ca_handler.process_normal_request(protected_rr)

        self.assertEqual(response["body"].getName(), "rp", display_pki_status_info(response))
        status = cmputils.get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(response))
        self.assertTrue(certutils.cert_in_list(cert, self.ca_handler.get_details("issued_certs")))
        self.assertTrue(certutils.cert_in_list(cert, self.ca_handler.get_details("revoked_certs")))
        self.assertTrue(self.ca_handler.rev_handler.is_revoked(cert))
        self.assertTrue(certutils.cert_in_list(cert, self.ca_handler.rev_handler.details()["revoked_certs"]))


if __name__ == "__main__":
    unittest.main()
