# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import prepare_cert_template
from resources.certutils import parse_certificate
from resources.compareutils import compare_cert_template_and_cert
from resources.utils import load_and_decode_pem_file


class TestCheckIfChainInOrder(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.asn1cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

    def test_compare_with_valid_set_public_key_and_issuer(self):
        """
        GIVEN a certificate template including publicKey, issuer, and subject fields.
        WHEN comparing this template with the actual certificate.
        THEN the comparison should return True, indicating a match with the certificate's public key and issuer.
        """
        cert_template = prepare_cert_template(cert=self.asn1cert, include_fields="publicKey,issuer,subject")
        self.assertTrue(compare_cert_template_and_cert(cert_template, issued_cert=self.asn1cert))

    def test_compare_with_different_subject_and_strict_issuer(self):
        """
        GIVEN a certificate template with a different subject from the actual certificate.
        WHEN comparing this template with strict subject validation enabled.
        THEN the comparison should return False, indicating a mismatch due to different subjects.
        """
        cert_template = prepare_cert_template(subject="CN=Hans the Tester1", include_fields="subject")
        self.assertTrue(cert_template["subject"].isValue, cert_template.prettyPrint())
        self.assertFalse(
            compare_cert_template_and_cert(cert_template, issued_cert=self.asn1cert, strict_subject_validation=True)
        )

    def test_compare_with_valid_subject_and_strict(self):
        """
        GIVEN a certificate template with the correct subject matching the actual certificate.
        WHEN comparing this template with strict subject validation enabled.
        THEN the comparison should return True, indicating a match on the subject.
        """
        cert_template = prepare_cert_template(subject="CN=Hans the Tester", include_fields="subject")
        self.assertTrue(cert_template["subject"].isValue, cert_template.prettyPrint())
        self.assertTrue(
            compare_cert_template_and_cert(cert_template, issued_cert=self.asn1cert, strict_subject_validation=True)
        )


if __name__ == "__main__":
    unittest.main()
