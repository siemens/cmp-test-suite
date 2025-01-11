# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_alt_modules import rfc5480, rfc9480

from unit_tests.asn1_wrapper_class.pki_message_wrapper import PKIHeader
from unit_tests.asn1_wrapper_class.wrapper_alg_id import AlgorithmIdentifier


class TestPKIHeader(unittest.TestCase):

    def test_pki_header_encoding_decoding(self):
        """
        GIVEN a PKIHeader object
        WHEN it is encoded to DER format and then decoded back
        THEN the decoded object should match the original object.
        """
        header = PKIHeader(
            pvno=2,
            sender="test_sender@example.com",
            recipient="test_recipient@example.com",
            messageTime=datetime.now(),
            protectionAlg=AlgorithmIdentifier(algorithm="sha256"),
            senderKID=b"sender_key_identifier",
            recipKID=b"recipient_key_identifier",
            transactionID=b"transaction_id_123",
            senderNonce=b"sender_nonce_abc",
            recipNonce=b"recipient_nonce_xyz",
            freeText=["Free text 1", "Free text 2"],
            generalInfo=None,
        )

        encoded = header.encode()

        asn1_obj, _ = der_decode(encoded, asn1Spec=rfc9480.PKIHeader())


        self.assertTrue(asn1_obj["pvno"].isValue)
        self.assertEqual(int(asn1_obj["pvno"]), 2)

        self.assertTrue(asn1_obj["sender"].isValue)
        self.assertEqual(str(asn1_obj["sender"]["rfc822Name"]), "test_sender@example.com")

        self.assertTrue(asn1_obj["recipient"].isValue)
        self.assertEqual(str(asn1_obj["recipient"]["rfc822Name"]), "test_recipient@example.com")

        self.assertTrue(asn1_obj["messageTime"].isValue)

        self.assertTrue(asn1_obj["protectionAlg"].isValue)
        self.assertEqual(str(asn1_obj["protectionAlg"]["algorithm"]), str(rfc5480.id_sha256))

        self.assertTrue(asn1_obj["senderKID"].isValue)
        self.assertEqual(bytes(asn1_obj["senderKID"]), b"sender_key_identifier")

        self.assertTrue(asn1_obj["recipKID"].isValue)
        self.assertEqual(bytes(asn1_obj["recipKID"]), b"recipient_key_identifier")

        self.assertTrue(asn1_obj["transactionID"].isValue)
        self.assertEqual(bytes(asn1_obj["transactionID"]), b"transaction_id_123")

        self.assertTrue(asn1_obj["senderNonce"].isValue)
        self.assertEqual(bytes(asn1_obj["senderNonce"]), b"sender_nonce_abc")

        self.assertTrue(asn1_obj["recipNonce"].isValue)
        self.assertEqual(bytes(asn1_obj["recipNonce"]), b"recipient_nonce_xyz")

        self.assertTrue(asn1_obj["freeText"].isValue)
        self.assertEqual([str(x) for x in asn1_obj["freeText"]], ["Free text 1", "Free text 2"])

        self.assertFalse(asn1_obj["generalInfo"].isValue)

        header_decoded = PKIHeader.from_asn1(asn1_obj)

        self.assertEqual(header_decoded.pvno, header.pvno)
        self.assertEqual(header_decoded.sender, header.sender)
        self.assertEqual(header_decoded.recipient, header.recipient)
        # are not entirely the same.
        self.assertEqual(header_decoded.messageTime.date(), header.messageTime.date())
        self.assertEqual(header_decoded.senderKID, header.senderKID)
        self.assertEqual(header_decoded.recipKID, header.recipKID)
        self.assertEqual(header_decoded.transactionID, header.transactionID)
        self.assertEqual(header_decoded.senderNonce, header.senderNonce)
        self.assertEqual(header_decoded.recipNonce, header.recipNonce)
        self.assertEqual(header_decoded.freeText, header.freeText)
        self.assertEqual(header_decoded.generalInfo, header.generalInfo)

if __name__ == "__main__":
    unittest.main()
