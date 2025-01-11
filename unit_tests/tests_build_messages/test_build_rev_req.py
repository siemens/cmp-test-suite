# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280, rfc9480
from resources import certbuildutils
from resources.asn1utils import encode_to_der
from resources.cmputils import build_cmp_revoke_request


class TestBuildCmpRevRequest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example_sender = "test-cmp-cli@example.com"
        cls.example_recipient = "test-cmp-srv@example.com"
        cls.serial_number = 1122122313231
        cls.reason = "superseded"

    def test_build_rr_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a rr body.
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        rr_msg = build_cmp_revoke_request(
            exclude_fields=None,
            serial_number=self.serial_number,
            reason=self.reason,
            sender=self.example_sender,
            recipient=self.example_recipient,
        )

        der_data = encode_to_der(rr_msg)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")

        # Check that the request header is correct, but cannot use built in methode. Not all values are set.
        sender = rfc9480.GeneralName().setComponentByName("rfc822Name", self.example_sender)
        recipient = rfc9480.GeneralName().setComponentByName("rfc822Name", self.example_recipient)

        self.assertEqual((pki_msg["header"]["sender"]), sender)
        self.assertEqual((pki_msg["header"]["recipient"]), recipient)
        self.assertEqual(int(pki_msg["header"]["pvno"]), 2)

        rev_details: rfc9480.RevDetails = rr_msg["body"]["rr"][0]
        cert_template: rfc9480.CertTemplate = rev_details[0]
        self.assertEqual(int(cert_template["serialNumber"]), self.serial_number)

        extn_id = rev_details["crlEntryDetails"][0]["extnID"]
        extn_value = rev_details["crlEntryDetails"][0]["extnValue"]
        self.assertEqual(extn_id, rfc5280.id_ce_cRLReasons)
        data, rest = decoder.decode(extn_value, rfc5280.CRLReason())
        self.assertEqual(rest, b"")

    def test_build_rr_without_cert_template_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a rr body.
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        rr_msg = build_cmp_revoke_request(
            exclude_fields=None,
            reason=self.reason,
            sender=self.example_sender,
            recipient=self.example_recipient,
            exclude_cert_template=True,
        )
        der_data = encode_to_der(rr_msg)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")

        # Check that the request header is correct, but cannot use built in methode. Not all values are set.
        sender = rfc9480.GeneralName().setComponentByName("rfc822Name", self.example_sender)
        recipient = rfc9480.GeneralName().setComponentByName("rfc822Name", self.example_recipient)

        self.assertEqual((pki_msg["header"]["sender"]), sender)
        self.assertEqual((pki_msg["header"]["recipient"]), recipient)
        self.assertEqual(int(pki_msg["header"]["pvno"]), 2)

        rev_details: rfc9480.RevDetails = rr_msg["body"]["rr"][0]

        # cannot check for no Value because of pyasn1-alt-module error
        # if constructed already contains an empty OptionalValidity value.
        # self.assertFalse(cert_template.isValue)

        extn_id = rev_details["crlEntryDetails"][0]["extnID"]
        extn_value = rev_details["crlEntryDetails"][0]["extnValue"]
        self.assertEqual(extn_id, rfc5280.id_ce_cRLReasons)
        data, rest = decoder.decode(extn_value, rfc5280.CRLReason())
        self.assertEqual(rest, b"")

    def test_build_rr_with_cert_en_and_decode(self):
        """
        GIVEN a PKIMessage with a certificate.
        WHEN the PKIMessage is encoded as DER format and decoded back.
        THEN the message should be successfully decoded without any errors.
        """
        cert, key = certbuildutils.build_certificate(serial_number=5000977898927223441, ski=True)
        pkiM = build_cmp_revoke_request(cert=cert, exclude_fields=None)
        pki_msg, rest = decoder.decode(encode_to_der(pkiM), asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
