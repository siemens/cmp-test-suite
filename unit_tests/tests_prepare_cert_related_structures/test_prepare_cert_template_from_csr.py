# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography import x509
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import build_csr, prepare_cert_template_from_csr, prepare_extensions
from resources.keyutils import load_private_key_from_file
from resources.utils import get_openssl_name_notation


class TestPrepareCertTemplateFromCSR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key_rsa = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        cls.private_key_ecc = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        cls.subject = "CN=Hans the Tester"

    def test_prepare_simple_csr(self):
        """
        GIVEN a CSR generated using an RSA private key
        WHEN `prepare_cert_template_from_csr` is called,
        THEN it should create a valid certificate template that matches the CSR, with the subject set correctly.
        """
        csr = build_csr(common_name=self.subject, signing_key=self.private_key_rsa)
        cert_template = prepare_cert_template_from_csr(csr)
        der_data = encoder.encode(cert_template)
        decoded_template, rest = decoder.decode(der_data, rfc9480.CertTemplate())
        self.assertEqual(rest, b"")
        self.assertEqual("CN=Hans the Tester", get_openssl_name_notation(decoded_template["subject"]))


    def test_prepare_with_extensions(self):
        """
        GIVEN a CSR generated using an ECC private key with specific extensions
        WHEN `prepare_cert_template_from_csr` is called,
        THEN it should create a valid certificate template that matches the CSR, including the extensions.
        """
        extensions = prepare_extensions(eku="cmcCA",
                                        key=self.private_key_ecc,
                                        key_usage="digitalSignature")
        csr = build_csr(common_name=self.subject,
                        signing_key=self.private_key_ecc,
                        extensions=extensions)
        cert_template = prepare_cert_template_from_csr(csr)
        der_data = encoder.encode(cert_template)
        decoded_template, rest = decoder.decode(der_data, rfc9480.CertTemplate())
        self.assertEqual(rest, b"")
        self.assertEqual("CN=Hans the Tester", get_openssl_name_notation(decoded_template["subject"]))

        csr_der = encoder.encode(csr)
        crypto_lib_csr = x509.load_der_x509_csr(csr_der)
        # Ensure that the extensions are present in the CSR (will throw an exception if not found)
        crypto_lib_csr.extensions.get_extension_for_oid(x509.SubjectKeyIdentifier.oid)
        crypto_lib_csr.extensions.get_extension_for_oid(x509.ExtendedKeyUsage.oid)
        crypto_lib_csr.extensions.get_extension_for_oid(x509.KeyUsage.oid)
