# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List, Optional

from resources.asn1_structures import PKIMessageTMP
from resources.checkutils import validate_nested_message_unique_nonces_and_ids
from resources.cmputils import prepare_pki_message, generate_unique_byte_values
from resources.exceptions import BadSenderNonce, BadRequest, BadRecipientNonce


class TestValidateNestedNoncesAndIds(unittest.TestCase):

    @staticmethod
    def _generate_messages(ids: List[bytes],
                           sender_nonces: List[bytes],
                           recipient_nonces: List[Optional[bytes]]) -> PKIMessageTMP:
        """Generate a list of PKIMessages with the given IDs and nonces."""
        messages = []
        for i, (tx_id, sender_nonce, recipient_nonce) in enumerate(zip(ids, sender_nonces, recipient_nonces)):
            msg = prepare_pki_message(
                sender_nonce=sender_nonce,
                transaction_id=tx_id,
                recip_nonce=recipient_nonce,
            )
            messages.append(msg)

        msgs = messages[0]
        msgs["body"]["nested"].extend(messages[1:])
        return msgs

    def test_valid_batch_message_size(self):
        """
        GIVEN a valid batch message.
        WHEN the message is validated,
        THEN must the message be accepted.
        """
        ids = generate_unique_byte_values(
            length=4, size=16
        )
        sender_nonces = generate_unique_byte_values(
            length=4, size=16
        )
        recipient_nonces = generate_unique_byte_values(
            length=4, size=16
        )

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)
        validate_nested_message_unique_nonces_and_ids(
            messages,
            check_sender_nonce=True,
            check_recip_nonce=True,
            check_transaction_id=True,
            check_length=True,
        )

    def test_valid_batch_message(self):
        """
        GIVEN a valid batch message.
        WHEN the message is validated,
        THEN must the message be accepted.
        """

        ids = [b"1234", b"5678", b"9101"]
        sender_nonces = [b"1234", b"5678", b"9101"]
        recipient_nonces = [b"1234", b"5678", b"9101"]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        validate_nested_message_unique_nonces_and_ids(
            messages,
            check_sender_nonce=True,
            check_recip_nonce=True,
            check_transaction_id=True,
            check_length=False,
        )

    def test_valid_batch_request(self):
        """
        GIVEN a valid batch request message.
        WHEN the message is validated,
        THEN must the message be accepted.
        """

        ids = [b"1234", b"5678", b"9101"]
        sender_nonces = [b"1234", b"5678", b"9101"]
        recipient_nonces = [None, None, None]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        validate_nested_message_unique_nonces_and_ids(
            messages,
            check_sender_nonce=True,
            check_recip_nonce=False,
            check_transaction_id=True,
            check_length=False,
        )

    def test_batch_msg_not_unique_sender_nonce(self):
        """
        GIVEN a batch message with non-unique sender nonces.
        WHEN the message is validated,
        THEN a BadSenderNonce exception must be raised.
        """
        ids = [b"1234", b"5678", b"9101"]
        sender_nonces = [b"1234", b"1234", b"9101"]
        recipient_nonces = [b"1234", b"5678", b"9101"]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        with self.assertRaises(BadSenderNonce):
            validate_nested_message_unique_nonces_and_ids(
                messages,
                check_sender_nonce=True,
                check_recip_nonce=True,
                check_transaction_id=True,
                check_length=False,
            )

    def test_batch_msg_not_unique_recipient_nonce(self):
        """
        GIVEN a batch message with non-unique recipient nonces.
        WHEN the message is validated,
        THEN a BadRecipientNonce exception must be raised.
        """
        ids = [b"1234", b"5678", b"9101"]
        sender_nonces = [b"1234", b"5678", b"9101"]
        recipient_nonces = [b"1234", b"1234", b"9101"]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        with self.assertRaises(BadRecipientNonce):
            validate_nested_message_unique_nonces_and_ids(
                messages,
                check_sender_nonce=True,
                check_recip_nonce=True,
                check_transaction_id=True,
                check_length=False,
            )

    def test_batch_msg_not_unique_transaction_id(self):
        """
        GIVEN a batch message with non-unique transaction IDs.
        WHEN the message is validated,
        THEN a BadRequest exception must be raised.
        """
        ids = [b"1234", b"5678", b"1234"]
        sender_nonces = [b"1234", b"5678", b"9101"]
        recipient_nonces = [b"1234", b"5678", b"9101"]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        with self.assertRaises(BadRequest):
            validate_nested_message_unique_nonces_and_ids(
                messages,
                check_sender_nonce=True,
                check_recip_nonce=True,
                check_transaction_id=True,
                check_length=False,
            )

    def test_batch_msg_not_16_bytes_long(self):
        """
        GIVEN a batch message with a transaction ID that is not 16 bytes long.
        WHEN the message is validated,
        THEN a BadRequest exception must be raised.
        """
        ids = [b"1234", b"5678", b"9101"]
        sender_nonces = [b"1234", b"5678", b"9101"]
        recipient_nonces = [b"1234", b"5678", b"9101"]

        messages = self._generate_messages(ids, sender_nonces, recipient_nonces)

        # The validation starts with the tx and then the nonces.
        with self.assertRaises(BadRequest):
            validate_nested_message_unique_nonces_and_ids(
                messages,
                check_sender_nonce=True,
                check_recip_nonce=True,
                check_transaction_id=True,
                check_length=True,
            )

