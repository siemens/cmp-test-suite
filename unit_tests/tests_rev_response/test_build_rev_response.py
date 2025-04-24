# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1utils import is_bit_set, asn1_get_named_value, get_set_bitstring_names
from resources.ca_ra_utils import build_rp_from_rr
from resources.certutils import parse_certificate
from resources.cmputils import build_cmp_revoke_request, get_pkistatusinfo, build_cmp_revive_request, \
    prepare_crl_reason_extensions
from resources.exceptions import BadMessageCheck
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


class TestBuildRevResponse(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_build_rev_response(self):
        """
        GIVEN a valid rr PKIMessage.
        WHEN the PKIMessage is processed, and a response is built,
        THEN must a PKIMessage with a status of 'accepted' be returned.
        """
        rr = build_cmp_revoke_request(
            cert=self.cert,
            private_key=self.private_key,
            reason="keyCompromise",
        )
        prot_rr = protect_pkimessage(
            rr,
            protection="signature",
            cert=self.cert,
            private_key=self.private_key,
        )
        rp, data = build_rp_from_rr(prot_rr, certs=[self.cert])
        self.assertEqual(len(rp["body"]["rp"]["status"]), 1)
        status_info = get_pkistatusinfo(rp)
        self.assertEqual(str(status_info["status"]), "accepted")
        self.assertEqual(data[0]["reason"], "keyCompromise")

    def test_build_rp_from_revive_request(self):
        """
        GIVEN a valid rr PKIMessage for reviving a certificate.
        WHEN the PKIMessage is processed, and a response is built,
        THEN must a PKIMessage with a status of 'accepted' be returned.
        """
        rr = build_cmp_revive_request(
            cert=self.cert,
            private_key=self.private_key,
        )
        prot_rr = protect_pkimessage(
            rr,
            protection="signature",
            cert=self.cert,
            private_key=self.private_key,
        )
        rp, data = build_rp_from_rr(prot_rr, certs=[self.cert], revoked_certs=[self.cert])
        self.assertEqual(len(rp["body"]["rp"]["status"]), 1)
        status_info = get_pkistatusinfo(rp)
        self.assertEqual(str(status_info["status"]), "accepted")
        self.assertEqual(data[0]["reason"], "removeFromCRL")

    def test_build_rp_from_rr_must_detect_bad_msg_check(self):
        """
        GIVEN invalid protected PKIMessage.
        WHEN the PKIMessage is processed, and a response is built,
        THEN the status must be 'rejection' and the failinfo must be 'badMessageCheck'.
        """
        rr = build_cmp_revoke_request(
            cert=self.cert,
            private_key=self.private_key,
            reason="keyCompromise",
        )
        prot_rr = protect_pkimessage(
            rr,
            protection="signature",
            cert=self.cert,
            private_key=self.private_key,
            bad_message_check=True
        )

        rp, _ = build_rp_from_rr(prot_rr, certs=[self.cert], verify=True)
        status = get_pkistatusinfo(rp)
        self.assertEqual(str(status["status"]), "rejection")
        result = is_bit_set(
            status["failInfo"],
            "badMessageCheck",
        )
        self.assertTrue(result)

    def test_build_rp_from_rr_invalid_req(self):
        """
        GIVEN A PKIMessage with an invalid CRLReason extension.
        WHEN the PKIMessage is processed, and a response is built,
        THEN the status must be 'rejection' and the failinfo must be 'badDataFormat'.
        """
        crl_entry_details = prepare_crl_reason_extensions(
            invalid_der=True,
        )
        rr = build_cmp_revoke_request(
            cert=self.cert,
            crl_entry_details=crl_entry_details,
            private_key=self.private_key,
            reason="keyCompromise",
        )
        rp, data = build_rp_from_rr(rr, certs=[self.cert], verify=False)
        status = get_pkistatusinfo(rp)
        self.assertEqual(str(status["status"]), "rejection")
        result = is_bit_set(
            status["failInfo"],
            "badDataFormat",
        )

        out = get_set_bitstring_names(
            status["failInfo"],
        )
        self.assertTrue(result, f"Got: {out}")
        self.assertTrue(len(data) == 0, data)
