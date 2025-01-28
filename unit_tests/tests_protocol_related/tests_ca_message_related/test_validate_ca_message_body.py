# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import parse_certificate
from resources.checkutils import validate_ca_message_body
from resources.cmputils import prepare_extra_certs
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_ca_pki_message
from resources.ca_ra_utils import prepare_cert_response


class TestValidateCAMessageBody(unittest.TestCase):
    def setUp(self):
        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        self.ca1_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        self.ca2_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem"))

    def test_invalid_cert_req_id_for_p10cr(self):
        """
        GIVEN a CA message with `body_type` set to "cp" and `certReqId` set to 0 for a p10cr request.
        WHEN `validate_ca_message_body` is called with `used_p10cr=True`.
        THEN it should raise a ValueError due to an invalid `certReqId` for p10cr.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=0, cert=self.ca1_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=True)

    def test_invalid_cert_req_id_for_cr(self):
        """
        GIVEN a CA message with `body_type` set to "cp" and `certReqId` set to -1 for a cr request.
        WHEN `validate_ca_message_body` is called with `used_p10cr` set to False.
        THEN it should raise a ValueError due to an invalid `certReqId` for a cr response.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=-1, cert=self.ca1_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False)

    def test_valid_ca_resp_cp(self):
        """
        GIVEN a valid CA response message with `body_type` set to "cp" and `certReqId` set to 0.
        WHEN `validate_ca_message_body` is called.
        THEN it should pass without raising any exception.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=0, cert=self.ca2_cert)
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_ca_resp_cp_cert_set_but_status_rejection(self):
        """
        GIVEN a CA response message with `status` set to "rejection" but with `cert` field set.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError because the certificate should not be present with a "rejection" status.
        """
        ca_message = build_ca_pki_message(
            body_type="cp", cert_req_id=0, status="rejection", failinfo="badAlg", cert=self.ca2_cert
        )
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_ca_resp_cp_caPubs_set_but_status_rejection(self):
        """
        GIVEN a CA response message with `status` set to "rejection" but with `caPubs` field set.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError because `caPubs` should not be present with a "rejection" status.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=0, status="rejection", ca_pubs=[self.ca2_cert])
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_ca_resp_cp_not_accepted_status(self):
        """
        GIVEN a CA response message with a non-accepted `status`.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError because `caPubs` should only be present with an "accepted" status.
        """
        ca_message = build_ca_pki_message(body_type="cp", cert_req_id=0, status="revocationWarning")
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_ca_resp_cp_invalid_size(self):
        """
        GIVEN a CA response message with multiple responses but `expected_size` set to 1.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError due to an unexpected response size.
        """
        resp = prepare_cert_response(cert_req_id=0, cert=self.ca2_cert)
        ca_message = build_ca_pki_message(body_type="cp", responses=[resp, resp])
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, expected_size=1, trustanchors="data/unittest")

    def test_invalid_ca_resp_failinfo_set_but_status_accepted(self):
        """
        GIVEN a CA response message with `status` set to "accepted" but `failInfo` field set.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError because `failInfo` should not be present with an "accepted" status.
        """
        ca_message = build_ca_pki_message(
            body_type="cp", cert_req_id=0, status="accepted", failinfo="badAlg", ca_pubs=[self.ca2_cert]
        )
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")

    def test_invalid_ca_resp_failinfo_set_but_status_grantedWithMods(self):
        """
        GIVEN a CA response message with `status` set to "grantedWithMods" but `failInfo` field set.
        WHEN `validate_ca_message_body` is called.
        THEN it should raise a ValueError because `failInfo` should not be present with a "grantedWithMods" status.
        """
        ca_message = build_ca_pki_message(
            body_type="cp", cert_req_id=0, status="grantedWithMods", failinfo="badAlg", ca_pubs=[self.ca2_cert]
        )
        ca_message["extraCerts"] = prepare_extra_certs(certs=[self.root_cert, self.ca2_cert])
        with self.assertRaises(ValueError):
            validate_ca_message_body(ca_message, used_p10cr=False, trustanchors="data/unittest")


if __name__ == "__main__":
    unittest.main()
