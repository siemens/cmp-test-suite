# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_csr, generate_certificate, prepare_extensions
from resources.compareutils import compare_csr_and_cert
from resources.keyutils import load_private_key_from_file


class TestCompareCsrAndCert(unittest.TestCase):

    def setUp(self):
        self.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    def test_compare_csr_and_cert_subject_without_strict(self):
        """
        GIVEN a CSR and a certificate.
        WHEN the subject of both is compared, with subject_strict=False,
        THEN the result should be True if eq and False if neq.
        """
        csr = build_csr(signing_key=self.key, common_name="CN=Hans the Tester")
        issued_cert = generate_certificate(private_key=self.key,
                                           common_name="L=DE, OU=Test, CN=Hans the Tester")

        result = compare_csr_and_cert(csr, issued_cert, subject_strict=False)
        self.assertTrue(result)

    def test_cert_compare_subject_strict(self):
        """
        GIVEN a CSR and a certificate.
        WHEN the subject of both is compared, with subject_strict=True,
        THEN the result should be False.
        """
        csr = build_csr(signing_key=self.key, common_name="CN=Hans the Tester")
        issued_cert = generate_certificate(private_key=self.key,
                                           common_name="L=DE, CN=Hans the Tester")

        result = compare_csr_and_cert(csr, issued_cert, subject_strict=True)
        self.assertFalse(result)


    def test_compare_csr_and_cert_mismatch(self):
        """
        GIVEN a CSR and a certificate and different keys.
        WHEN the key of both is compared,
        THEN the result should be False.
        """
        csr = build_csr(signing_key=self.key, common_name="CN=Hans the Tester")
        other_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        issued_cert = generate_certificate(private_key=other_key,
                                           common_name="CN=Hans the Tester")

        result = compare_csr_and_cert(csr, issued_cert, subject_strict=False)
        self.assertFalse(result)

    def test_compare_extensions(self):
        """
        GIVEN a CSR and a certificate and different extensions.
        WHEN the extensions of both are compared,
        THEN the result should be False.
        """
        extn = prepare_extensions(key=self.key, is_ca=True)
        csr = build_csr(signing_key=self.key, common_name="CN=Hans the Tester",
                        extensions=extn)
        extn = prepare_extensions(key=self.key, is_ca=False)
        issued_cert = generate_certificate(private_key=self.key,
                                           common_name="CN=Hans the Tester",
                                           extensions=extn)

        result = compare_csr_and_cert(csr, issued_cert, subject_strict=True)
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
