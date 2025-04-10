# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from resources.certbuildutils import generate_certificate
from resources.certutils import build_ocsp_response, check_ocsp_response, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestProcessOCSPResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        leaf_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert"),
            ]
        )
        cls.leaf_cert = generate_certificate(
            private_key=cls.leaf_key,
            common_name="CN=Leaf Cert",
            issuer_cert=cls.ca_cert,
            signing_key=cls.ca_key,
        )


    def test_ocsp_expected_status_good(self):
        """
        GIVEN a valid OCSP response with a good status.
        WHEN checking the OCSP response,
        THEN the response should be accepted.
        """
        status = "good"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
            hash_alg="sha256",
            revocation_reason=None,
            responder_cert=None,  # By default, it will use ca_cert as the responder cert
            responder_hash_alg="sha256",
            build_by_key=False,
        )

        check_ocsp_response(ocsp_response, self.leaf_cert, expected_status="good")

    def test_ocsp_expected_status_revoked(self):
        """
        GIVEN a valid OCSP response with a revoked status.
        WHEN checking the OCSP response,
        THEN the response should be accepted.
        """
        status = "revoked"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
        )
        check_ocsp_response(ocsp_response=ocsp_response, cert=self.leaf_cert, expected_status="revoked")

    def test_check_ocsp_response_with_invalid_status(self):
        """
        GIVEN an OCSP response with an invalid status.
        WHEN checking the OCSP response,
        THEN a ValueError should be raised.
        """
        status = "unknown"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
        )

        with self.assertRaises(ValueError):
            check_ocsp_response(ocsp_response=ocsp_response,
                                cert=self.leaf_cert,
                                expected_status="good",
                                )

    def test_check_ocsp_response_with_unknown_allowed(self):
        """
        GIVEN an OCSP response with an unknown status.
        WHEN checking the OCSP response, with "allow_unknown_status" set to True,
        THEN the response should be accepted.
        """
        status = "unknown"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
            hash_alg="sha256",
        )

        check_ocsp_response(ocsp_response=ocsp_response,
                            cert=self.leaf_cert,
                            expected_status="good",
                            allow_unknown_status=True,
                            )
