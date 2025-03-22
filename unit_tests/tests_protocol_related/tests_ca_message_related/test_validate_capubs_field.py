# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import parse_certificate
from resources.checkutils import validate_ca_msg_ca_pubs_field
from resources.cmputils import prepare_extra_certs
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_ca_pki_message


class TestCheckCaPubs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        cls.ca1_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.ca2_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem"))

    def test_valid_caPubs_field_ir_with_caPubs(self):
        """
        GIVEN a PKI message of type 'ip' with caPubs containing the root certificate.
        WHEN validate_ca_msg_caPubs_field is called with used_p10cr set to True.
        THEN it should validate successfully with no exceptions.
        """
        ca_message = build_ca_pki_message(body_type="ip", cert_req_id=0, ca_pubs=[self.root_cert], cert=self.ca2_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca1_cert])
        validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=True, trustanchors="data/unittest")

    def test_valid_caPubs_field_p10cr_with_caPubs(self):
        """
        GIVEN a PKI message of type 'cp' with caPubs containing the root certificate.
        WHEN validate_ca_msg_caPubs_field is called with used_p10cr set to True.
        THEN it should validate successfully with no exceptions.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=-1, ca_pubs=[self.root_cert], cert=self.ca2_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca1_cert])
        validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=True, trustanchors="data/unittest")

    def test_valid_caPubs_field_for_p10cr_without_caPubs(self):
        """
        GIVEN a PKI message of type 'cp' without caPubs but with extraCerts containing the root certificate
        and ca2 certificate.
        WHEN validate_ca_msg_caPubs_field is called with used_p10cr set to True.
        THEN it should validate successfully with no exceptions.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=-1, cert=self.ca1_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca2_cert, self.root_cert])
        validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=True, trustanchors="data/unittest")

    def test_valid_cr_resp_caPubs_is_absent(self):
        """
        GIVEN a PKI message of type 'cp' without `caPubs` field.
        WHEN validate_ca_msg_caPubs_field is called with used_p10cr set to False.
        THEN it should validate successfully with no exceptions.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=0, cert=self.ca2_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca1_cert, self.root_cert])
        validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_valid_caPubs_field_for_kur(self):
        """
        GIVEN a PKI message of type 'kup' with extraCerts containing the root certificate.
        WHEN validate_ca_msg_caPubs_field is called with used_p10cr set to False.
        THEN it should validate successfully with no exceptions.
        """
        ca_message = build_ca_pki_message(body_type="kup", cert_req_id=0, status="accepted", cert=self.ca1_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca2_cert, self.root_cert])
        validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_caPubs_when_certifiedKeyPair_is_not_set(self):
        """
        GIVEN a PKI message of type 'ip' with caPubs set but without a certifiedKeyPair.
        WHEN validate_ca_msg_caPubs_field is called.
        THEN it should raise a ValueError due to missing certifiedKeyPair.
        """
        cert_der_data = load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem")
        cert = parse_certificate(cert_der_data)
        ca_message = build_ca_pki_message(body_type="ip", ca_pubs=[cert])
        with self.assertRaises(ValueError):
            validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_newly_issued_cert_but_no_chain_present(self):
        """
        GIVEN a PKI message of type 'ip' with a newly issued certificate but without a full certificate chain.
        WHEN validate_ca_msg_caPubs_field is called.
        THEN it should raise a ValueError due to incomplete certificate chain.
        """
        ca_message = build_ca_pki_message(body_type="ip", ca_pubs=[self.root_cert], cert=self.cert)
        with self.assertRaises(ValueError):
            validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_valid_caPubs_present_but_cert_was_not_issued(self):
        """
        GIVEN a PKI message of type 'ip' with caPubs but the certificate was not issued by the chain.
        WHEN validate_ca_msg_caPubs_field is called.
        THEN it should raise a ValueError due to certificate not being issued by the CA chain.
        """
        ca_message = build_ca_pki_message(body_type="ip", ca_pubs=[self.root_cert], cert=self.cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca1_cert])
        with self.assertRaises(ValueError):
            validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_not_allowed_caPubs_in_kup(self):
        """
        GIVEN a PKI message of type 'kup' with caPubs set, which is not allowed.
        WHEN validate_ca_msg_caPubs_field is called.
        THEN it should raise a ValueError as `caPubs` is not allowed in a 'kup' message type.
        """
        ca_message = build_ca_pki_message(body_type="kup", ca_pubs=[self.root_cert], cert=self.ca1_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_msg_ca_pubs_field(ca_message, used_p10cr=False, trustanchors="data/unittest")
