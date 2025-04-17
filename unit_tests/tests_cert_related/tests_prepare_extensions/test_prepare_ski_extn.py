# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography import x509
from pyasn1_alt_modules import rfc9480, rfc5280

from resources.certbuildutils import prepare_ski_extension, prepare_extensions
from resources.certextractutils import get_subject_key_identifier, get_extension
from resources.keyutils import load_private_key_from_file


class TestPrepareSKI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", None)


    def _extract(self, extn: rfc5280.Extension):
        """Extract the SKI extension."""
        cert = rfc9480.CMPCertificate()
        cert['tbsCertificate']['extensions'].append(extn)
        extracted_ski = get_subject_key_identifier(
            cert
        )

        self.assertIsNotNone(
            extracted_ski
        )
        return extracted_ski

    def test_prepare_valid_ski(self):
        """
        GIVEN a valid public key.
        WHEN the ski is prepared.
        THEN the ski extension is correctly prepared.
        """
        ski_extn = prepare_ski_extension(
            key=self.key.public_key()
        )

        extracted_ski = self._extract(ski_extn)

        x509_ski = x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()).digest
        self.assertEqual(
            x509_ski, extracted_ski
        )

    def test_prepare_invalid_ski(self):
        """
        GIVEN an invalid public key.
        WHEN the ski is prepared.
        THEN the ski extension is not prepared.
        """
        ski_extn = prepare_ski_extension(
            key=self.key,
            invalid_ski=True
        )

        extracted_ski = self._extract(ski_extn)

        x509_ski = x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()).digest
        self.assertNotEqual(
            x509_ski, extracted_ski
        )

    def test_prepare_ski_with_extension_fun(self):
        """
        GIVEN a valid public key.
        WHEN the ski is prepared.
        THEN the ski extension is correctly prepared.
        """
        extns = prepare_extensions(
            key=self.key,
            critical=True,
        )
        out = get_extension(
            extensions=extns, oid=rfc5280.id_ce_subjectKeyIdentifier
        )
        self.assertIsNotNone(
            out
        )
        extracted_ski = self._extract(out)
        self.assertEqual(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()).digest, extracted_ski
        )

        self.assertTrue(out['critical'])