# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_ocsp_extension, generate_certificate
from resources.deprecatedutils import prepare_crl_distribution_point_extension
from resources.certutils import validate_if_certificate_is_revoked,  \
    build_ocsp_response, parse_certificate
from resources.exceptions import CertRevoked
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import convert_to_crypto_lib_cert, build_crl_crypto_lib


class TestValidateIfCertificateIsRevoked(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject_issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")
        ])
        cls.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject_issuer)
            .issuer_name(subject_issuer)
            .public_key(cls.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=365))
            .sign(cls.ca_key, hashes.SHA256())
        )

        cls.ocsp_url = "http://ocsp.test.com"
        cls.leaf_cert = convert_to_crypto_lib_cert(generate_certificate("rsa"))
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        cls.cert["tbsCertificate"]["extensions"].append(
            prepare_ocsp_extension(cls.ocsp_url)
        )
        extn = prepare_crl_distribution_point_extension("http://crl.test.com")
        extension = rfc5280.Extension()
        extension["extnID"] = rfc5280.id_ce_cRLDistributionPoints
        extension["critical"] = False
        extension["extnValue"] = univ.OctetString(extn.value.public_bytes())

        cls.cert["tbsCertificate"]["extensions"].append(
            extension
        )


    @patch("resources.certutils._post_ocsp_request")
    @patch("requests.get")
    def test_certificate_revoked_by_crl(self, mock_requests_get, mock_post_ocsp):
        """
        GIVEN a CRL check indicating the certificate is revoked
        WHEN validating revocation status,
        THEN a CertRevoked exception should be raised.
        """
        cert = convert_to_crypto_lib_cert(self.cert)
        crl_data = build_crl_crypto_lib(self.ca_key, self.ca_cert, cert)

        ocsp_response = build_ocsp_response(self.cert, self.ca_cert, self.ca_key, status="good")
        mock_post_ocsp.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)
        mock_requests_get.return_value.status_code = 200
        mock_requests_get.return_value.content = crl_data

        with self.assertRaises(CertRevoked):
            validate_if_certificate_is_revoked(cert=self.cert, ca_cert=self.ca_cert)

    @patch("resources.certutils._post_ocsp_request")
    def test_validate_cert_revoked_by_ocsp(self, mock_get):
        """
        GIVEN an OCSP check indicating the certificate is revoked
        WHEN validating revocation status,
        THEN a CertRevoked exception should be raised.
        """
        ocsp_response = build_ocsp_response(self.cert, self.ca_cert, self.ca_key, status="revoked")
        mock_get.return_value.status_code = 200
        mock_get.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)
        with self.assertRaises(CertRevoked):
            validate_if_certificate_is_revoked(self.cert, ca_cert=self.ca_cert)

    @patch("resources.certutils._post_ocsp_request")
    @patch("requests.get")
    def test_validate_cert_not_revoked(self, mock_requests_get, mock_post_ocsp):
        """
        GIVEN a certificate that is not revoked
        WHEN validating revocation status,
        THEN no exception should be raised.
        """

        ocsp_response = build_ocsp_response(self.cert, self.ca_cert, self.ca_key, status="good")
        mock_post_ocsp.return_value.status_code = 200
        mock_post_ocsp.return_value.content = ocsp_response.public_bytes(serialization.Encoding.DER)

        crl_data = build_crl_crypto_lib(self.ca_key, self.ca_cert, self.leaf_cert)

        mock_requests_get.return_value.status_code = 200
        mock_requests_get.return_value.content = crl_data

        validate_if_certificate_is_revoked(self.cert, ca_cert=self.ca_cert)




if __name__ == "__main__":
    unittest.main()
