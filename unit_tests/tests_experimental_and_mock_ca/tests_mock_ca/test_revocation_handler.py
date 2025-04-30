# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from mock_ca.mock_fun import CertRevStateDB
from mock_ca.rev_handler import RevocationHandler

from resources.certbuildutils import build_certificate
from resources.cmputils import build_cmp_revoke_request, get_pkistatusinfo
from resources.keyutils import generate_key
from resources.protectionutils import protect_hybrid_pkimessage
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestRevocationHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()

        cls.client_key = ec.generate_private_key(ec.SECP256R1())
        cls.client_cert, _ = build_certificate(
            private_key=cls.client_key,
            common_name="CN=Test",
            ca_cert=cls.ca_cert,
            ca_key=cls.ca_key,
        )
        rev_db = CertRevStateDB()
        # Initialize RevocationHandler
        cls.rev_handler = RevocationHandler(rev_db=rev_db)

    def _build_request(self, reason: str):
        rr_message = build_cmp_revoke_request(cert=self.client_cert, reason=reason)
        rr_message = protect_hybrid_pkimessage(
            rr_message,
            private_key=self.client_key,
            cert=self.client_cert,
            certs_path="data/unittest/",
        )
        return rr_message

    def test_revocation(self):
        """
        GIVEN a certificate.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        rr_message = self._build_request(reason="keyCompromise")

        response, _ = self.rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=[self.client_cert],
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        self.assertFalse(self.rev_handler.is_revoked(self.ca_cert))
        self.assertEqual(len(self.rev_handler.rev_db.rev_entry_list), 1)
        self.assertTrue(self.rev_handler.is_revoked(self.client_cert))

    def test_revive_request(self):
        """
        GIVEN a revoked certificate.
        WHEN a revive request is processed.
        THEN the certificate is no longer revoked.
        """
        client_cert, client_key = build_certificate(
            private_key=generate_key("ecc"),
            common_name="CN=Test",
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        rr_message = build_cmp_revoke_request(cert=client_cert, reason="keyCompromise")
        rr_message = protect_hybrid_pkimessage(
            rr_message,
            private_key=client_key,
            cert=client_cert,
            certs_path="data/unittest/",
        )

        rev_handler = RevocationHandler()

        response, revived_cert = rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=[client_cert],
        )
        self.assertEqual(len(revived_cert), 0)
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        revive_request = build_cmp_revoke_request(cert=client_cert, reason="removeFromCRL")
        revive_request = protect_hybrid_pkimessage(
            revive_request,
            private_key=client_key,
            cert=client_cert,
            certs_path="data/unittest/",
        )
        response, revived_cert = rev_handler.process_revocation_request(
            pki_message=revive_request,
            issued_certs=[client_cert],
        )

        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())
        self.assertFalse(rev_handler.is_revoked(client_cert))
        self.assertEqual(len(rev_handler.rev_db.rev_entry_list), 0)
        self.assertFalse(rev_handler.is_revoked(self.ca_cert))
        self.assertEqual(len(revived_cert), 1)

    def test_revoked_request(self):
        """
        GIVEN a revoked certificate.
        WHEN a revocation request is processed, with a revoked certificate,
        THEN is the request rejected.
        """
        rr_message = self._build_request(reason="keyCompromise")
        response, revived_certs = self.rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=[self.client_cert],
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "rejection", status.prettyPrint())
        self.assertEqual(len(revived_certs), 0)


if __name__ == "__main__":
    unittest.main()
