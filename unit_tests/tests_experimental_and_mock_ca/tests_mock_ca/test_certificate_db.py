# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.mock_fun import CertDBEntry, CertificateDB, CertStateEnum

from resources.asn1utils import encode_to_der
from resources.certutils import cert_in_list, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import compute_hash
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import compare_pyasn1_objects


class TestCertificateDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example_cert = parse_certificate(load_and_decode_pem_file("./data/unittest/ca2_cert_rsa.pem"))
        cls.example_key = load_private_key_from_file(
            "./data/keys/private-key-rsa.pem",
            password=None,
        )
        cls.example_cert2 = parse_certificate(load_and_decode_pem_file("./data/unittest/ca1_cert_ecdsa.pem"))

        cls.cert1_digest = compute_hash("sha1", encode_to_der(cls.example_cert))
        cls.updated_cert_digest = compute_hash("sha1", encode_to_der(cls.example_cert2))

    def test_add_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database.
        THEN it should be retrievable from the database.
        """
        # Assuming CertificateDB has an add_cert method
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)

        # Check if the certificate is in the database
        self.assertTrue(cert_in_list(self.example_cert, db.issued_certs))
        self.assertIsNone(db.get_cert(self.example_cert2))
        self.assertIsNotNone(db.get_cert(self.example_cert))
        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.CONFIRMED)
        self.assertTrue(compare_pyasn1_objects(self.example_cert, cert_entry.cert))
        self.assertEqual(self.cert1_digest, cert_entry.cert_digest)

    def test_change_cert_state_revoked(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate state is changed to revoked.
        THEN it should be reflected in the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)

        # Change the state to revoked
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.REVOKED)

        # Check if the state is updated
        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.REVOKED)

    def test_change_cert_state_revoked_to_confirmed(self):
        """
        GIVEN a revoked certificate and a CertificateDB instance.
        WHEN the certificate state is changed to confirmed.
        THEN it should raise a ValueError.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.REVOKED)

        with self.assertRaises(ValueError):
            db.change_cert_state(cert=self.example_cert, new_state=CertStateEnum.CONFIRMED)

    def test_not_confirmed_updated_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database with a state other than CONFIRMED.
        THEN it should not be retrievable from the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )

        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertIsNone(db.get_cert(self.example_cert2))

        cert_entry: CertDBEntry = db.get_cert(self.example_cert)
        self.assertEqual(cert_entry.cert_state, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED)
        self.assertTrue(compare_pyasn1_objects(self.example_cert, cert_entry.cert))
        self.assertEqual(self.cert1_digest, cert_entry.cert_digest)
        self.assertEqual(self.updated_cert_digest, cert_entry.update_cert_digest)

    def test_update_cert(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is updated in the database.
        THEN it should be retrievable and the state should be correct.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )

        # Check if the updated certificate is in the database
        self.assertIsNone(db.get_cert(self.example_cert2))
        with self.assertRaises(ValueError):
            db.change_cert_state(
                cert=self.example_cert,
                new_state=CertStateEnum.CONFIRMED,
                updated_cert=self.example_cert2,
            )

    def test_confirm_not_update_then_updated(self):
        """
        GIVEN a certificate and a CertificateDB instance.
        WHEN the certificate is added to the database with a state other than CONFIRMED.
        THEN it should not be retrievable from the database.
        """
        db = CertificateDB(hash_alg="sha1")
        db.add_cert(cert=self.example_cert, cert_state=CertStateEnum.CONFIRMED)
        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED_BUT_NOT_CONFIRMED,
            updated_cert=self.example_cert2,
        )
        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertEqual(db.get_cert(self.example_cert).cert_state, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED)

        db.change_cert_state(
            cert=self.example_cert,
            new_state=CertStateEnum.UPDATED,
            updated_cert=None,
        )
        self.assertIsNotNone(db.get_cert(self.example_cert))
        self.assertIsNone(db.get_cert(self.example_cert2))
