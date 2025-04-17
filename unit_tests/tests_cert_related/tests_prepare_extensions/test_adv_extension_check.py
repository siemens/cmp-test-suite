# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.certbuildutils import check_extensions, prepare_cert_template, prepare_extensions, check_logic_extensions
from resources.exceptions import BadCertTemplate
from resources.keyutils import load_private_key_from_file


class TestCheckExtension2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.cm = "CN=Hans the Tester"

    def _get_cert_template(self, extensions: rfc9480.Extensions) -> rfc9480.CertTemplate:
        """Prepare a certificate template."""
        return prepare_cert_template(
            self.rsa_key, subject=self.cm, extensions=extensions
        )

    def test_invalid_basic_constraint_and_key_usage(self):
        """
        GIVEN a certificate template with invalid basic constraint and key usage.
        WHEN checking the extensions,
        THEN a BadCertTemplate exception is raised.
        """
        extensions = prepare_extensions(key_usage="keyCertSign", is_ca=False)
        self.assertEqual(len(extensions), 2)
        cert_template = self._get_cert_template(extensions)
        self.assertEqual(len(cert_template["extensions"]), 2)
        with self.assertRaises(BadCertTemplate):
            check_logic_extensions(cert_template=cert_template)


    def test_invalid_basic_constraint_for_ee(self):
        """
        GIVEN a certificate template with invalid basic constraint for end entity
        WHEN checking the extensions,
        THEN a BadCertTemplate exception is raised.
        """
        extensions = prepare_extensions(is_ca=False, path_length=5)
        cert_template = self._get_cert_template(extensions)
        self.assertEqual(len(cert_template["extensions"]), 1)
        with self.assertRaises(BadCertTemplate):
            check_extensions(cert_template=cert_template, ca_public_key=self.rsa_key.public_key())
