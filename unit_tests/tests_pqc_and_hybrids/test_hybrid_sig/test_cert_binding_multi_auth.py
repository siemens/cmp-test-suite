# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

import resources.certutils
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import (
    add_csr_related_cert_request_attribute,
    get_related_cert_from_list,
    prepare_related_cert_extension,
    prepare_requester_certificate,
    validate_multi_auth_binding_csr,
)
from pq_logic.hybrid_structures import RequesterCertificate
from pyasn1.codec.der import decoder, encoder

from resources import utils
from resources.certbuildutils import build_csr, generate_certificate, sign_csr
from resources.certutils import (
    build_cert_chain_from_dir,
    load_certificates_from_dir,
    parse_certificate,
)
from resources.exceptions import BadCertTemplate
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file

from unit_tests.utils_for_test import compare_pyasn1_objects


class TestCertBindingMultiAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert = parse_certificate(utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")

        cls.cm = "CN=Hans the Tester"
        cls.csr_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.uri = "https://localhost:8080/cmp/cert-bindings-for-multiple-authentication"
        cls.pq_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65.pem")
        cls.cert_a_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.cert_a = generate_certificate(cls.cert_a_key, "CN=Test RSA", issuer_cert=cls.ca_cert, signing_key=cls.ca_key)
        cls.cert_b = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))
        cls.cert_related = generate_certificate(private_key=cls.cert_a_key, issuer_cert=cls.cert_b, hash_alg="sha256")

    def test_prepare_requester_certificate(self):
        """
        GIVEN a certificate and a private key.
        WHEN the RequesterCertificate is prepared,
        THEN the RequesterCertificate is correctly prepared.
        """
        req_cert = prepare_requester_certificate(self.cert_a,
                                                 self.cert_a_key,
                                                 self.uri,
                                                 hash_alg="sha256",
                                                 request_time=1609459200)

        self.assertIsInstance(req_cert, RequesterCertificate)

        der_data = encoder.encode(req_cert)
        dec_req_cert, rest = decoder.decode(der_data, asn1Spec=RequesterCertificate())
        self.assertEqual(rest, b"")
        self.assertEqual(int(dec_req_cert['requestTime']), 1609459200)
        self.assertEqual(str(dec_req_cert['locationInfo']), self.uri)
        self.assertTrue(dec_req_cert['signature'].isValue)


    def test_get_related_cert_from_list_pos(self):
        """
        GIVEN a certificate and a list of certificates.
        WHEN the related certificate is searched for in the list,
        THEN the related certificate is found.
        """
        extn = prepare_related_cert_extension(cert_a=self.cert_a,
                                              hash_alg="sha256", critical=False)
        cert = generate_certificate(private_key=self.cert_a_key,
                                    extensions=[extn], hash_alg="sha256")

        certs = load_certificates_from_dir("data/unittest") + [self.cert_a]
        related_cert = get_related_cert_from_list(certs, cert)
        self.assertTrue(compare_pyasn1_objects(related_cert, self.cert_a))

    def test_get_related_cert_from_list_neg(self):
        """
        GIVEN a certificate and a list of certificates.
        WHEN the related certificate is searched for in the list,
        THEN the related certificate is not found.
        """
        cert_a = generate_certificate(private_key=self.cert_a_key)
        certs = load_certificates_from_dir("data/unittest")
        with self.assertRaises(ValueError):
            get_related_cert_from_list(certs, cert_a)

    @patch("resources.utils.load_certificate_from_uri")
    def test_cert_binding_multi_auth_build_csr(self, mock_load_cert):
        """
        GIVEN a certificate and a private key.
        WHEN a CSR is built with the certificate and the private key,
        THEN the CSR is correctly verified, and the cert_A is correctly verified
        and returned.
        """
        certs = [self.cert_a, self.ca_cert]
        mock_load_cert.return_value = certs

        csr = build_csr(signing_key=self.csr_key, common_name=self.cm, hash_alg="sha256")

        req_cert = prepare_requester_certificate(self.cert_a,
                                                 self.cert_a_key,
                                                 self.uri,
                                                 hash_alg="sha512",
                                                 request_time=None)

        csr = add_csr_related_cert_request_attribute(csr, requester_cert=req_cert)
        csr = sign_csr(csr, self.csr_key, hash_alg="sha256")
        resources.certutils.verify_csr_signature(csr)


        cert_a = validate_multi_auth_binding_csr(csr=csr, trustanchors="data/unittest",
                                                 crl_check=False,
                                                 load_chain=False)

        self.assertTrue(compare_pyasn1_objects(cert_a, self.cert_a))

    @patch("resources.utils.load_certificate_from_uri")
    def test_cert_binding_multi_auth_build_csr_with_ca_cert(self, mock_load_cert):
        """
        GIVEN a certificate and a private key.
        WHEN a CSR is built with the certificate and the private key,
        THEN the CSR is correctly verified, and the cert_A is correctly verified
        and returned.
        """
        certs = build_cert_chain_from_dir(self.ca_cert, "data/unittest")
        mock_load_cert.return_value = certs

        csr = build_csr(signing_key=self.csr_key, common_name=self.cm, hash_alg="sha256")

        req_cert = prepare_requester_certificate(self.ca_cert,
                                                 self.ca_key,
                                                 self.uri,
                                                 request_time=None)

        csr = add_csr_related_cert_request_attribute(csr, requester_cert=req_cert)
        csr = sign_csr(csr, self.csr_key, hash_alg="sha256")
        resources.certutils.verify_csr_signature(csr)

        with self.assertRaises(BadCertTemplate):
            _ = validate_multi_auth_binding_csr(csr=csr, trustanchors="data/unittest",
                                                crl_check=False,
                                                load_chain=True)
