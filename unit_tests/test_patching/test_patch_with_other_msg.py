# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import validate_nested_message_unique_nonces_and_ids
from resources.cmputils import build_nested_pkimessage, patch_pkimessage_header_with_other_message
from resources.keyutils import generate_key

from unit_tests.utils_for_test import build_pkimessage


class TestPatchPKIMessageWithOtherMessage(unittest.TestCase):

    def setUp(self):
        self.key = generate_key("rsa")
        self.target = build_pkimessage(key=self.key,
                                       transaction_id=b"txIDTarget",
                                       sender_nonce=b"senderNonceTarget",
                                       recip_nonce=b"recipNonceTarget",
                                       sender_kid=b"senderKIDTarget",
                                       recip_kid=b"recipKIDTarget"
                                       )
        self.other_msg = build_pkimessage(key=self.key,
                                          transaction_id=b"txID",
                                          sender_nonce=b"senderNonce",
                                          recip_nonce=b"recipNonce",
                                          sender_kid=b"senderKID",
        recip_kid=b"recipKID")

    def test_for_added_protection(self):
        """
        GIVEN a PKIMessage
        WHEN patch_pkimessage_header_with_other_message is called with for_added_protection=True,
        THEN the header of the PKIMessage should be updated with the same transactionID and senderNonce as the nested message.
        """
        nested_target = build_nested_pkimessage(other_messages=self.target)
        result = patch_pkimessage_header_with_other_message(
            target=nested_target,
            for_added_protection=True
        )

        self.assertEqual(result["header"]["transactionID"].asOctets(), b"txIDTarget")
        self.assertEqual(result["header"]["senderNonce"].asOctets(), b"senderNonceTarget")

    def test_include_fields(self):
        """
        GIVEN a PKIMessage
        WHEN patch_pkimessage_header_with_other_message is called with include_fields,
        THEN the specified fields in the header should be updated from the other_message.
        """
        result = patch_pkimessage_header_with_other_message(
            target=self.target,
            other_message=self.other_msg,
            include_fields="transactionID,senderNonce"
        )

        self.assertEqual(result["header"]["transactionID"].asOctets(), b"txID")
        self.assertEqual(result["header"]["senderNonce"].asOctets(), b"senderNonce")


    def test_for_exchange(self):
        """
        GIVEN a PKIMessage
        WHEN patch_pkimessage_header_with_other_message is called with for_exchange=True,
        THEN the header of the PKIMessage should be updated for exchange.
        """
        result = patch_pkimessage_header_with_other_message(
            target=self.target,
            other_message=self.other_msg,
            for_exchange=True
        )
        self.assertEqual(result["header"]["transactionID"].asOctets(), b"txID")
        self.assertEqual(result["header"]["senderNonce"].asOctets(), b"recipNonce")
        self.assertEqual(result["header"]["recipNonce"].asOctets(), b"senderNonce")
        self.assertEqual(result["header"]["senderKID"].asOctets(), b"recipKID")
        self.assertEqual(result["header"]["recipKID"].asOctets(), b"senderKID")

    def test_for_exchange_with_exclude(self):
        """
        GIVEN a PKIMessage.
        WHEN patch_pkimessage_header_with_other_message is called with for_exchange=True, and exclude_fields,
        THEN the header of the PKIMessage should be updated for exchange, excluding sender and recipient.
        """
        result = patch_pkimessage_header_with_other_message(
            target=self.target,
            other_message=self.other_msg,
            for_exchange=True,
            exclude_fields="senderKID,senderNonce"
        )
        self.assertEqual(result["header"]["transactionID"].asOctets(), b"txID")

        self.assertEqual(result["header"]["recipNonce"].asOctets(), b"senderNonce")
        self.assertEqual(result["header"]["recipKID"].asOctets(), b"senderKID")

        # not updated fields
        self.assertEqual(result["header"]["senderKID"].asOctets(), b"senderKIDTarget")
        self.assertEqual(result["header"]["senderNonce"].asOctets(), b"senderNonceTarget")




    def test_for_nested(self):
        """
        GIVEN a nested PKIMessage with messages.
        WHEN patch_pkimessage_header_with_other_message is called with for_nested=True,
        THEN the nested PKIMessage should be patched with unique transactionID and senderNonce.
        """
        msg1 = build_pkimessage(transaction_id=b"123", sender_nonce=b"abc", recip_nonce=b"xyz")
        msg2 = build_pkimessage(transaction_id=b"456", sender_nonce=b"def", recip_nonce=b"uvw")
        msg3 = build_pkimessage(transaction_id=b"789", sender_nonce=b"ghi", recip_nonce=b"rst")
        messages = [msg1, msg2, msg3]

        nested_target = build_nested_pkimessage(other_messages=messages,
                                                transaction_id=b"123",
                                                sender_nonce=b"abc",
                                               )
        result = patch_pkimessage_header_with_other_message(
            target=nested_target,
            for_nested=True
        )

        self.assertNotEqual(result["header"]["transactionID"].asOctets(), b"123")
        self.assertNotEqual(result["header"]["senderNonce"].asOctets(), b"abc")
        validate_nested_message_unique_nonces_and_ids(nested_target, check_recip_nonce=False)

if __name__ == "__main__":
    unittest.main()
