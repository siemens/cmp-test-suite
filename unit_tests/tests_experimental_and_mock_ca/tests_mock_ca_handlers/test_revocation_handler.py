# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from mock_ca.mock_fun import CertificateDB, CertStateEnum
from mock_ca.rev_handler import RevocationHandler

from resources.certbuildutils import build_certificate
from resources.certutils import cert_in_list
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
        rev_db = CertificateDB()
        rev_db.add_cert(cls.client_cert, cert_state=CertStateEnum.CONFIRMED)
        # Initialize RevocationHandler
        cls.rev_handler = RevocationHandler(rev_db=rev_db)

    def _build_revoke_request(self, reason: str):
        rr_message = build_cmp_revoke_request(cert=self.client_cert, reason=reason)
        rr_message = protect_hybrid_pkimessage(
            rr_message,
            private_key=self.client_key,
            cert=self.client_cert,
            certs_path="data/unittest/",
        )
        return rr_message

    def test_revocation_with_rev_handler(self):
        """
        GIVEN a certificate.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        db = CertificateDB()
        db.add_cert(
            self.client_cert,
            cert_state=CertStateEnum.CONFIRMED,
        )
        rev_handler = RevocationHandler(
            rev_db=db,
        )

        rr_message = self._build_revoke_request(reason="keyCompromise")

        response, _ = rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=rev_handler.rev_db.issued_certs,
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        self.assertFalse(rev_handler.is_revoked(self.ca_cert))
        self.assertEqual(len(rev_handler.rev_db.revoked_certs), 1)
        self.assertTrue(rev_handler.is_revoked(self.client_cert))
        self.assertTrue(cert_in_list(self.client_cert, rev_handler.details()["revoked_certs"]))

    def test_revocation_with_rev_handler_with_db(self):
        """
        GIVEN a certificate.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        rr_message = self._build_revoke_request(reason="keyCompromise")

        response, _ = self.rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=self.rev_handler.rev_db.issued_certs,
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "accepted", status.prettyPrint())

        self.assertFalse(self.rev_handler.is_revoked(self.ca_cert))
        self.assertEqual(len(self.rev_handler.rev_db.revoked_certs), 1)
        self.assertTrue(self.rev_handler.is_revoked(self.client_cert))
        self.assertTrue(cert_in_list(self.client_cert, self.rev_handler.details()["revoked_certs"]))

    def test_revive_request_with_rev_handler(self):
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

        rev_db = CertificateDB()
        rev_db.add_cert(client_cert, cert_state=CertStateEnum.CONFIRMED)
        rev_handler = RevocationHandler(
            rev_db=rev_db,
        )

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
        self.assertEqual(len(rev_handler.rev_db.revoked_certs), 0)
        self.assertFalse(rev_handler.is_revoked(self.ca_cert))
        self.assertEqual(len(revived_cert), 1)
        self.assertTrue(cert_in_list(client_cert, revived_cert), "Revived cert not in revived cert list")

    def test_revoked_request(self):
        """
        GIVEN a revoked certificate.
        WHEN a revocation request is processed, with a revoked certificate,
        THEN is the request rejected.
        """
        rr_message = self._build_revoke_request(reason="keyCompromise")
        response, revived_certs = self.rev_handler.process_revocation_request(
            pki_message=rr_message,
            issued_certs=[self.client_cert],
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(str(status["status"]), "rejection", status.prettyPrint())
        self.assertEqual(len(revived_certs), 0)


if __name__ == "__main__":
    unittest.main()
