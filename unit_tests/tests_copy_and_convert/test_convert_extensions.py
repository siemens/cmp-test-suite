# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography import x509
from pyasn1_alt_modules import rfc5280
from resources.certbuildutils import build_certificate
from resources.deprecatedutils import x509_to_pyasn1_extensions

from unit_tests.utils_for_test import compare_certificate_extensions, convert_to_crypto_lib_cert


class TestCertificateExtensions(unittest.TestCase):
    def setUp(self):
        with open("data/example-csr.pem", "rb") as csr_file:
            self.csr = x509.load_pem_x509_csr(csr_file.read())

        cert, _ = build_certificate(ski=True, is_ca=True, key_usage="digitalSignature")
        self.certificate = convert_to_crypto_lib_cert(cert)

    def test_extension_types(self):
        """
        GIVEN a CSR and a certificate
        WHEN accessing their extensions attribute,
        THEN the extensions should be of the x509.Extensions type.
        """
        self.assertIsInstance(self.csr.extensions, x509.Extensions)
        self.assertIsInstance(self.certificate.extensions, x509.Extensions)

    def test_certificate_extension_conversion(self):
        """
        GIVEN a certificate with extensions
        WHEN converting its extensions to pyasn1 format,
        THEN the result should be an instance of rfc5280.Extensions.
        """
        extensions = x509_to_pyasn1_extensions(self.certificate)
        self.assertIsInstance(extensions, rfc5280.Extensions)

    def test_csr_extension_conversion(self):
        """
        GIVEN a CSR with extensions
        WHEN converting its extensions to pyasn1 format,
        THEN the result should be an instance of rfc5280.Extensions.
        """
        extensions = x509_to_pyasn1_extensions(self.csr)
        self.assertIsInstance(extensions, rfc5280.Extensions)

    def test_certificate_extension_comparison(self):
        """
        GIVEN a certificate and its pyasn1-formatted extensions
        WHEN comparing the cryptography and pyasn1 extension formats,
        THEN the comparison should confirm that they match.
        """
        extensions = x509_to_pyasn1_extensions(self.certificate)
        result = compare_certificate_extensions(self.certificate, extensions)
        self.assertTrue(result, "The extensions of the certificate should match.")

    def test_csr_extension_comparison(self):
        """
        GIVEN a CSR and its pyasn1-formatted extensions
        WHEN comparing the cryptography and pyasn1 extension formats,
        THEN the comparison should confirm that they match.
        """
        extensions = x509_to_pyasn1_extensions(self.csr)
        result = compare_certificate_extensions(self.csr, extensions)
        self.assertTrue(result, "The extensions of the CSR should match.")


if __name__ == "__main__":
    unittest.main()
