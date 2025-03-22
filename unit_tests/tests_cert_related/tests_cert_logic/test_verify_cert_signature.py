# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import certutils
from resources.certbuildutils import build_certificate
from resources.keyutils import load_private_key_from_file


class TestCertificateSignatureValidation(unittest.TestCase):
    def setUp(self):
        private_key = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        certificate, self.private_key = build_certificate(private_key=private_key)
        self.asn1cert = certificate

    def test_verification_for_a_valid_certificate(self):
        """
        GIVEN a valid certificate with a correct signature
        WHEN verify_cert_signature is called with the certificate,
        THEN no exception should be raised, indicating the certificate signature is valid.
        """
        certutils.verify_cert_signature(self.asn1cert)


if __name__ == "__main__":
    unittest.main()
