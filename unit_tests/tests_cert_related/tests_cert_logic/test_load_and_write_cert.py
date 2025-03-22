# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import unittest

from cryptography import x509
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import build_certificate, generate_signed_csr
from resources.certutils import load_os_truststore, parse_certificate, validate_key_usage
from resources.utils import load_and_decode_pem_file, write_cmp_certificate_to_pem


class TestLoadAndWriteCert(unittest.TestCase):
    def test_write_and_load_correct_cert(self):
        """
        GIVEN a valid certificate with key usage set to 'digitalSignature'.
        WHEN the certificate is written to a PEM file and then loaded.
        THEN the loaded certificate should match the original certificate, validate the 'digitalSignature' key usage,
        and be readable by the OpenSSL command line tool.
        """
        cert_valid, _ = build_certificate(key_usage="digitalSignature")
        os.makedirs("data/unittest", exist_ok=True)
        write_cmp_certificate_to_pem(cert_valid, path="data/unittest/test_write.pem")
        der_data = load_and_decode_pem_file("data/unittest/test_write.pem")
        loaded_cert = parse_certificate(der_data)
        self.assertIsInstance(loaded_cert, rfc9480.CMPCertificate)
        validate_key_usage(cert=loaded_cert, strictness=3, key_usages="digitalSignature")
        command = "openssl x509 -in data/unittest/test_write.pem -text -noout".split(" ")
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        os.remove("data/unittest/test_write.pem")

    def test_load_os_truststore(self):
        """
        GIVEN a system truststore with accessible certificates.
        WHEN load_os_truststore() is called.
        THEN the function should return a list of certificates loaded from the trust store,
        confirming that certificates are accessible from the OS truststore.
        """
        certs = load_os_truststore()
        self.assertTrue(len(certs), 0)

    def test_csr_to_pem(self):
        """
        GIVEN CSR generated with pyasn1
        WHEN the argument return_as_pem is True, and loaded with the cryptography library,
        THEN the CSR should be able to be loaded.
        """
        csr_pem, key = generate_signed_csr(common_name="CN=Hans the Tester", return_as_pem=True)
        csr = x509.load_pem_x509_csr(csr_pem)
        self.assertEqual(csr.subject.rfc4514_string(), "CN=Hans the Tester")
