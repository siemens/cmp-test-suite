# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5652
from resources.ca_ra_utils import build_ip_cmp_message, prepare_cert_response
from resources.certbuildutils import build_certificate, build_csr
from resources.certutils import parse_certificate
from resources.cmputils import build_p10cr_from_csr, parse_csr, prepare_cert_req_msg, build_ir_from_key
from resources.envdatautils import prepare_enveloped_data, prepare_ktri
from resources.exceptions import BadRequest
from resources.keyutils import load_private_key_from_file, generate_key
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildIpCmpMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cek = b"A" * 32
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.rsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        cls.common_name = "CN=Hans the Tester"
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


        kari = prepare_ktri(
            cmp_protection_cert=cls.rsa_cert,
            ee_key=cls.rsa_key.public_key(),
            cek=cls.cek,
        )
        cls.enc_cert = prepare_enveloped_data(
            enc_oid=rfc5652.id_data,
            recipient_infos=kari,
            cek=cls.cek,
            data_to_protect=b"Encrypted Data",
        )
        cls.cert_req_id = 0
        cls.ca_pubs = [cls.rsa_cert]
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        cls.request =  build_p10cr_from_csr(
            csr=csr
        )

    def test_build_ip_cmp_message_with_cert(self):
        """
        GIVEN a certificate.
        WHEN the function is called with the certificate.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            cert=self.rsa_cert,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_with_enc_cert(self):
        """
        GIVEN an encrypted certificate.
        WHEN the function is called with the encrypted certificate.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            enc_cert=self.enc_cert,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_with_responses(self):
        """
        GIVEN an already prepared response.
        WHEN the function is called with the response.
        THEN a valid PKIMessage is created.
        """
        cert, key = build_certificate()
        responses = prepare_cert_response(
            cert=cert,
        )
        pki_message, _ = build_ip_cmp_message(
            responses=responses,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        _ = de_and_encode_pkimessage(pki_message)

    def test_build_ip_cmp_message_with_request(self):
        """
        GIVEN a request.
        WHEN the function is called with the request.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            request=self.request,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
            ca_cert=self.rsa_cert,
            ca_key=self.rsa_key,
        )
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_raises_value_error(self):
        """
        GIVEN no arguments.
        WHEN the function is called.
        THEN a ValueError is raised.
        """
        with self.assertRaises(ValueError):
            build_ip_cmp_message()

    def test_build_ip_cmp_message_from_p10cr(self):
        """
        GIVEN a P10CR.
        WHEN the IP PKIMessage is built from the P10CR.
        THEN a valid PKIMessage is created.
        """
        key = generate_key("composite-sig")
        csr = build_csr(key)
        p10cr = build_p10cr_from_csr(csr)
        ip, certs = build_ip_cmp_message(
            request=p10cr,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        self.assertEqual(len(certs), 1)
        self.assertEqual(len(ip["body"]["ip"]["response"]), 1)

        _ = de_and_encode_pkimessage(ip)

    def test_build_ip_cmp_message_multi_requests(self):
        """
        GIVEN multiple certificate requests.
        WHEN the IP PKIMessage is built from the requests.
        THEN a valid PKIMessage is created.
        """
        key = generate_key("rsa")

        cert_req_msg = prepare_cert_req_msg(
            common_name=self.common_name,
            private_key=key,
            cert_req_id=1,
        )
        key2 = generate_key("rsa")
        cert_req_msg2 = prepare_cert_req_msg(
            common_name=self.common_name,
            private_key=key2,
            cert_req_id=1,
        )

        ir = build_ir_from_key(
            signing_key=None,
            cert_req_msg=[cert_req_msg, cert_req_msg2],
        )
        ip, certs = build_ip_cmp_message(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            enforce_lwcmp=False,
        )
        self.assertEqual(len(ip["body"]["ip"]["response"]), 2)
        self.assertEqual(len(certs), 2)
        _ = de_and_encode_pkimessage(ip)

    def test_build_ip_cmp_message_multi_requests_but_lwcmp(self):
        """
        GIVEN multiple certificate requests.
        WHEN the IP PKIMessage is built from the requests with lwcmp enforcement.
        THEN a BadRequest is raised.
        """
        key = generate_key("rsa")

        cert_req_msg = prepare_cert_req_msg(
            common_name=self.common_name,
            private_key=key,
            cert_req_id=0,
        )
        key2 = generate_key("rsa")
        cert_req_msg2 = prepare_cert_req_msg(
            common_name=self.common_name,
            private_key=key2,
            cert_req_id=1,
        )

        ir = build_ir_from_key(
            signing_key=None,
            cert_req_msg=[cert_req_msg, cert_req_msg2],
        )
        with self.assertRaises(BadRequest):
            _ = build_ip_cmp_message(
                request=ir,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                enforce_lwcmp=True,
            )

if __name__ == "__main__":
    unittest.main()