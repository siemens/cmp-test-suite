# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import CertResponseTMP
from resources.ca_ra_utils import prepare_cert_response
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_enveloped_data, prepare_ktri
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestPrepareCertResponse(unittest.TestCase):

    def setUp(self):
        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

    def test_simple_prep_cert_response(self):

        cert_response = prepare_cert_response(
            status="accepted",
            cert=None,
            cert_req_id="0"
        )

        self.assertTrue(cert_response["status"].isValue)
        self.assertEqual(str(cert_response["status"]["status"]), "accepted")
        self.assertEqual(int(cert_response["certReqId"]), 0)
        self.assertFalse(cert_response["certifiedKeyPair"].isValue)
        self.assertFalse(cert_response["rspInfo"].isValue)

        der_data = try_encode_pyasn1(cert_response)
        _, rest = try_decode_pyasn1(der_data, CertResponseTMP())
        self.assertEqual(rest, b"")


    def test_prepare_cert_response_with_cert(self):
        """
        GIVEN a valid certificate.
        WHEN preparing a certificate response.
        THEN the `CertResponse` structure is correctly prepared.
        """
        cert_response = prepare_cert_response(
            status="accepted",
            cert=self.cert,
            cert_req_id="0"
        )

        self.assertTrue(cert_response["status"].isValue)
        self.assertEqual(int(cert_response["certReqId"]), 0)
        self.assertTrue(cert_response["certifiedKeyPair"].isValue)
        self.assertFalse(cert_response["rspInfo"].isValue)

        der_data = try_encode_pyasn1(cert_response)
        _, rest = try_decode_pyasn1(der_data, CertResponseTMP())
        self.assertEqual(rest, b"")
        


    def test_prepare_invalid_status_and_cert_present(self):
        """
        GIVEN a valid certificate.
        WHEN preparing a certificate response with an invalid status.
        THEN the `CertResponse` structure is correctly prepared.
        """
        cert_response = prepare_cert_response(
            status="rejection",
            cert=self.cert,
            cert_req_id="0"
        )

        self.assertTrue(cert_response["status"].isValue)
        self.assertEqual(str(cert_response["status"]["status"]), "rejection")
        self.assertEqual(int(cert_response["certReqId"]), 0)
        self.assertTrue(cert_response["certifiedKeyPair"].isValue)
        self.assertFalse(cert_response["rspInfo"].isValue)

        der_data = try_encode_pyasn1(cert_response)
        _, rest = try_decode_pyasn1(der_data, CertResponseTMP())
        self.assertEqual(rest, b"")


    def test_prepare_cert_response_with_private_key(self):
        """
        GIVEN a valid certificate.
        WHEN preparing a certificate response with a private key.
        THEN the `CertResponse` structure is correctly prepared.
        """
        key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        ktri = prepare_ktri(
            ee_key=key.public_key(),
            cmp_protection_cert=self.cert,
            cek=b"\x00" * 32,
        )

        enveloped_data = prepare_enveloped_data(
            recipient_infos=ktri,
            data_to_protect=b"Encrypted private key",
            version=2,
            cek=b"\x00" * 32,
        )

        cert_response = prepare_cert_response(
            status="accepted",
            cert=self.cert,
            private_key=enveloped_data,
            cert_req_id="0"
        )

        self.assertTrue(cert_response["certifiedKeyPair"].isValue)
        self.assertTrue(cert_response["certifiedKeyPair"]["privateKey"].isValue)
        self.assertTrue(cert_response["certifiedKeyPair"]["privateKey"]["envelopedData"].isValue)

        _, rest = try_decode_pyasn1(try_encode_pyasn1(cert_response), CertResponseTMP())
        self.assertEqual(rest, b"")
