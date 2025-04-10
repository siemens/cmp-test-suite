# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from resources.certbuildutils import build_certificate, prepare_extensions
from resources.certutils import parse_certificate, validate_certificate_pkilint
from resources.cmputils import build_ir_from_key, get_cert_from_pkimessage
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


class TestMockCaIssueCertLint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ecdsa_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.ed_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_issue_cert_ecdsa(self):
        """
        GIVEN valid extensions and a build ECDSA certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.ecdsa_key, ca_key=self.ecdsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.ecdsa_key, extensions=extensions)
        validate_certificate_pkilint(cert)

    def test_issue_cert_rsa(self):
        """
        GIVEN valid extensions and a build RSA certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.rsa_key, ca_key=self.rsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.rsa_key, extensions=extensions, ra_verified=True, use_rsa_pss=False)
        validate_certificate_pkilint(cert)

    def test_issue_cert_rsa_pss(self):
        """
        GIVEN valid extensions and a build RSA-PSS certificate.
        WHEN the certificate is validated,
        THEN should the certificate be accepted.
        """
        extensions = prepare_extensions(key=self.rsa_key, ca_key=self.rsa_key.public_key(), critical=False)
        cert, key = build_certificate(self.rsa_key, extensions=extensions, ra_verified=True, use_rsa_pss=True)
        validate_certificate_pkilint(cert)

    def test_issue_with_mock_ca(self):
        """
        GIVEN valid extensions and an IR.
        WHEN the MOCK-CA processes the certificate request,
        THEN should a valid certificate be created.
        """
        handler = CAHandler(ca_cert=self.root_cert, ca_key=self.ed_key, config={}, pre_shared_secret=b"SiemensIT")
        ir = build_ir_from_key(self.rsa_key, for_mac=True, sender="CN=Hans the Tester")
        prot_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")
        response = handler.process_normal_request(prot_ir)
        self.assertEqual(response["body"].getName(), "ip", response["body"].prettyPrint())
        cert = get_cert_from_pkimessage(pki_message=response)
        validate_certificate_pkilint(cert)
