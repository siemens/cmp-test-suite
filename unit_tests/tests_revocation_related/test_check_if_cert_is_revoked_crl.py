# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480

from resources.certbuildutils import build_certificate
from resources.certutils import (
    check_if_cert_is_revoked_crl, parse_certificate,
)
from resources.exceptions import CertRevoked
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import build_crl_crypto_lib, convert_to_crypto_lib_cert


def _convert_to_pyasn1_cert(cert):
    """Convert a cryptography certificate to a pyasn1 certificate."""
    cert_bytes = cert.public_bytes(Encoding.DER)
    cert_pyasn1, _ = decoder.decode(cert_bytes, asn1Spec=rfc9480.CMPCertificate())
    return cert_pyasn1


def _create_cert_with_crl_distribution(ca_key, ca_cert):
    crl_dp = x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://test.com/crl")],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
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
        .add_extension(crl_dp, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert


class TestCheckIfCertIsRevokedCRL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        cls.ca_cert = convert_to_crypto_lib_cert(ca_cert)

        cls.leaf_cert = _create_cert_with_crl_distribution(cls.ca_key, cls.ca_cert)
        cls.leaf2_cert_pyasn1, _ = build_certificate(
            private_key=cls.leaf_key,
            common_name="CN=Leaf Cert 2",
            ca_cert=ca_cert,
            ca_key=cls.ca_key,
        )
        cls.crl_data = build_crl_crypto_lib(cls.ca_key, cls.ca_cert, cls.leaf_cert)
        cls.leaf_cert_pyasn1 = _convert_to_pyasn1_cert(cls.leaf_cert)

    @patch("requests.get")
    def test_check_if_cert_is_revoked_crl(self, mock_get):
        """
        GIVEN a certificate with a CRL distribution point.
        WHEN checking if the certificate is revoked.
        THEN an exception is raised.
        """
        mock_get.return_value.content = self.crl_data
        with self.assertRaises(CertRevoked):
            check_if_cert_is_revoked_crl(self.leaf_cert_pyasn1, crl_url="http://test.com/crl")

    @patch("requests.get")
    def test_check_if_cert_is_revoked_crl_not_revoked(self, mock_get):
        """
        GIVEN a certificate with a CRL distribution point.
        WHEN checking if the certificate is revoked.
        THEN no exception is raised.
        """
        mock_get.return_value.content = self.crl_data
        check_if_cert_is_revoked_crl(self.leaf2_cert_pyasn1, crl_url="http://test.com/crl")

    @patch("requests.get")
    def test_check_if_cert_is_revoked_crl_With_cdp(self, mock_get):
        """
        GIVEN a certificate with a CRL distribution point.
        WHEN checking if the certificate is revoked.
        THEN an exception is raised.
        """
        mock_get.return_value.content = self.crl_data
        with self.assertRaises(CertRevoked):
            check_if_cert_is_revoked_crl(self.leaf_cert_pyasn1, crl_url=None)


if __name__ == "__main__":
    unittest.main()
