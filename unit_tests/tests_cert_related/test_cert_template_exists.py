# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.ca_ra_utils import cert_template_exists
from resources.certbuildutils import prepare_cert_template, build_certificate
from resources.keyutils import load_private_key_from_file


class TestCertTemplateExists(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


    def _gen_template(self) -> rfc9480.CertTemplate:
         """Generate a certificate template."""
         return prepare_cert_template(
            subject="CN=Test",
            key=self.key,
        )

    def test_cert_template_is_inside(self):
        """
        GIVEN a certificate template and a certificate.
        WHEN it is checked if the template is inside the list of certificates.
        THEN the result should be True.
        """
        template = self._gen_template()
        cert, _ = build_certificate(self.key, common_name="CN=Test")
        result = cert_template_exists(cert_template=template, certs=[cert])
        self.assertTrue(result)

    def test_cert_template_not_inside(self):
        """
        GIVEN a certificate template and a certificate.
        WHEN it is checked if the template is inside the list of certificates.
        THEN the result should be False.
        """
        template = self._gen_template()
        cert, _ = build_certificate(self.key, common_name="CN=Test2",)
        result = cert_template_exists(cert_template=template, certs=[cert])
        self.assertFalse(result)
