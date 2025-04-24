# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from resources.cert_linters_utils import validate_ocsp_pkilint
from resources.certutils import build_ocsp_response, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestLintOCSP(unittest.TestCase):
    def test_ocsp_response_lint(self):
        """
        GIVEN an OCSP response.
        WHEN the OCSP response is validated using the pkilint tool.
        THEN a ValueError is raised.
        """
        ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        ca_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        data = build_ocsp_response(cert=cert, ca_cert=ca_cert, responder_key=ca_key, status="good", hash_alg=None)
        validate_ocsp_pkilint(data)

    def test_ocsp_response_lint_bad_nonce(self):
        """
        GIVEN an OCSP response with an bad nonce.
        WHEN the OCSP response is validated using the pkilint tool.
        THEN a ValueError is raised.
        """
        ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        ca_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        data = build_ocsp_response(
            cert=cert,
            ca_cert=ca_cert,
            responder_key=ca_key,
            status="good",
            hash_alg=None,
            # the allowed range is 1-32, according to RFC8954.
            nonce=os.urandom(60),
        )
        with self.assertRaises(ValueError):
            validate_ocsp_pkilint(data)
