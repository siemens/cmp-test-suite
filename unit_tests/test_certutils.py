# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import parse_certificate, validate_certificate_pkilint, validate_certificate_openssl
from resources.utils import load_and_decode_pem_file


class TestCertUtils(unittest.TestCase):
    def test_load_certificate(self):
        """
        GIVEN a DER-encoded X509 certificate
        WHEN we try to parse it into a pyasn1 object
        THEN no errors will occur
        """
        raw = load_and_decode_pem_file('data/dummy-cert.pem')
        result = parse_certificate(raw)
        self.assertIsNotNone(result)

    def test_invalidate_broken_certificate(self):
        """
        GIVEN a problematic DER-encoded X509 certificate without a signature
        WHEN we try to validate it with OpenSSL and PKILint
        THEN exceptions will be thrown to signalize an error
        """
        raw = load_and_decode_pem_file('data/cert-nosig.pem')
        with self.assertRaises(Exception):
            validate_certificate_pkilint(raw)

        with self.assertRaises(Exception):
            validate_certificate_openssl(raw)
