# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import generate_certificate, generate_signed_csr
from resources.checkutils import validate_transaction_id
from resources.cmputils import build_p10cr_from_csr, build_polling_request, build_polling_response, parse_csr
from resources.utils import decode_pem_string


def _patch_recip_nonce(msg: rfc9480.PKIMessage):
    """Initialize the PKIMessage recipNonce field."""
    msg["header"]["recipNonce"] = univ.OctetString(os.urandom(16)).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
    )


class TestBuildPollingStructures(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr)
        _patch_recip_nonce(pki_message)
        cls.certificate = generate_certificate(private_key=private_key, common_name="CN=Hans")
        cls.pki_message = pki_message
        cls.private_key = private_key
        cls.sender = "CN=Hans the Tester"
        cls.recipient = "CN=Hans the Tester"

    def test_pollRep_encode_decode(self):
        """
        GIVEN a polling response PKIMessage.
        WHEN the message is encoded using DER and then decoded.
        THEN the decoded message should match the original structure, with no remaining undecoded data.
        """
        pki_message = build_polling_response(sender=self.sender, recipient=self.recipient)
        encoded_message = encoder.encode(pki_message)
        dec_pki_msg, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")

    def test_pollReq_encode_decode(self):
        """
        GIVEN a polling request PKIMessage.
        WHEN the message is encoded using DER and then decoded.
        THEN the decoded message should match the original structure, with no remaining undecoded data.
        """
        pki_message = build_polling_response(sender=self.sender, recipient=self.recipient)
        encoded_message = encoder.encode(pki_message)
        dec_pki_msg, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")

    def test_pollRep_encode_decode_with_pki_message(self):
        """
        GIVEN a polling response PKIMessage with a provided polling request.
        WHEN the message is encoded using DER and then decoded.
        THEN the decoded message should match the original structure, with no remaining undecoded data.
        """
        req_pki_message = build_polling_response(sender=self.sender, recipient=self.recipient)
        _patch_recip_nonce(req_pki_message)
        pki_message = build_polling_response(
            req_pki_message=req_pki_message, sender=self.sender, recipient=self.recipient
        )

        encoded_message = encoder.encode(pki_message)
        dec_pki_msg, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        validate_transaction_id(dec_pki_msg, req_pki_message)

    def test_pollReq_encode_decode_with_pki_message(self):
        """
        GIVEN a polling request PKIMessage with a provided polling request.
        WHEN the message is encoded using DER and then decoded.
        THEN the decoded message should match the original structure, with no remaining undecoded data.
        """
        pki_message = build_polling_request(
            resp_pki_message=self.pki_message, sender=self.sender, recipient=self.recipient
        )
        encoded_message = encoder.encode(pki_message)
        dec_pki_msg, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        validate_transaction_id(dec_pki_msg, self.pki_message)
