# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta

from cryptography.x509 import ExtensionNotFound

from resources.certbuildutils import prepare_ocsp_extension
from resources.certutils import build_ocsp_response, check_ocsp_response_for_cert, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file



def _create_cert_with_ocsp_extension(ca_key, ca_cert, ocsp_url):
    """Create a certificate with an OCSP extension."""
    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            x509.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)
        )
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Leaf Cert")
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(aia, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert


class TestCheckOcspResponseForCert(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
            cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

            cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

            cert['tbsCertificate']['extensions'].append(prepare_ocsp_extension("http://ocsp.test.com"))

            cls.cert = cert

            cls.ocsp_url = "http://ocsp.test.com"

            # if pyasn1 is not trusted, the following line will do the same as the above.
            # cls.ca_cert = convert_to_crypto_lib_cert(cls.ca_cert)
            #cls.leaf_cert = create_cert_with_ocsp_extension(cls.leaf_key, cls.ca_cert, cls.ocsp_url)


        def test_ocsp_without_extension_entries(self):

            cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

            with self.assertRaises(ExtensionNotFound):
                check_ocsp_response_for_cert(cert=cert,
                                             issuer=self.ca_cert,
                                             must_be_present=True,
                                             )

        @patch("resources.certutils._post_ocsp_request")
        def test_ocsp_expected_status_good(self, mock_get):
            """
            GIVEN a valid OCSP response with a good status.
            WHEN checking the OCSP response,
            THEN the response should be accepted.
            """
            status = "good"
            ocsp_response = build_ocsp_response(cert=self.cert,
                                                ca_cert=self.ca_cert,
                                                status=status,
                                                responder_key=self.ca_key,
                                                )
            mock_get.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)
            check_ocsp_response_for_cert(cert=self.cert,
                                         issuer=self.ca_cert,
                                         must_be_present=True,
                                         expected_status=status,
                                         )

        @patch("resources.certutils._post_ocsp_request")
        def test_ocsp_expected_status_revoked(self, mock_get):
            """
            GIVEN a valid OCSP response with a revoked status.
            WHEN checking the OCSP response,
            THEN the response should be accepted.
            """
            status = "revoked"
            ocsp_response = build_ocsp_response(cert=self.cert,
                                                ca_cert=self.ca_cert,
                                                status=status,
                                                responder_key=self.ca_key,
                                                )
            mock_get.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)
            check_ocsp_response_for_cert(cert=self.cert,
                                         issuer=self.ca_cert,
                                         must_be_present=True,
                                         expected_status=status,
                                         )
        @patch("resources.certutils._post_ocsp_request")
        def test_check_ocsp_response_with_invalid_status(self, mock_get):
            """
            GIVEN an OCSP response with an invalid status.
            WHEN checking the OCSP response,
            THEN a ValueError should be raised.
            """
            status = "unknown"

            ocsp_response = build_ocsp_response(cert=self.cert,
                                                ca_cert=self.ca_cert,
                                                status=status,
                                                responder_key=self.ca_key,
                                                )
            mock_get.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)
            with self.assertRaises(ValueError):
                check_ocsp_response_for_cert(cert=self.cert,
                                             issuer=self.ca_cert,
                                             must_be_present=True,
                                             expected_status="good",
                                             )



