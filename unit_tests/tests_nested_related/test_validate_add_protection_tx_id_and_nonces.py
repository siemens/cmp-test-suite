# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple, Optional

from resources.asn1_structures import PKIMessageTMP
from resources.certutils import parse_certificate
from resources.checkutils import validate_add_protection_tx_id_and_nonces
from resources.cmputils import build_cert_conf, \
    build_nested_pkimessage, build_ir_from_key
from resources.exceptions import BadSenderNonce, BadRequest, BadRecipientNonce
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestValidateAddedProtectionNoncesAndIds(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")


    def _generate_messages(self,
            tx_id: Tuple[Optional[bytes], Optional[bytes]],
            sender_nonce: Tuple[Optional[bytes], Optional[bytes]],
            recip_nonce: Tuple[Optional[bytes], Optional[bytes]],
            for_ir: bool,
                           ) -> PKIMessageTMP:
        """Generate the added protection messages."""

        if for_ir:
            msg = build_ir_from_key(
                self.private_key,
                sender_nonce=sender_nonce[0],
                transaction_id=tx_id[0],
                recip_nonce=recip_nonce[0],
            )
        else:
            msg = build_cert_conf(
                cert=self.cert,
                hash_alg="sha256",
                sender_nonce=sender_nonce[0],
                transaction_id=tx_id[0],
                recip_nonce=recip_nonce[0],
            )

        msgs = build_nested_pkimessage(
            other_messages=msg,
            sender_nonce=sender_nonce[1],
            transaction_id=tx_id[1],
            recip_nonce=recip_nonce[1],
            for_added_protection=True,
        )
        return msgs

    def test_valid_added_protection_request(self):
        """
        GIVEN a valid added protection request message.
        WHEN the message is validated,
        THEN must the message be accepted.
        """
        tx_id = (None, None)
        sender_nonce = (None, None)
        recip_nonce = (None, None)
        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=True)

        validate_add_protection_tx_id_and_nonces(
            nested,
            check_length=False,
        )

    def test_valid_added_protection_cert_conf(self):
        """
        GIVEN a valid added protection certificate confirmation message.
        WHEN the message is validated,
        THEN must the message be accepted.
        """
        tx_id = (None, None)
        sender_nonce = (None, None)
        recip_nonce = (b"1234", None)
        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=False)

        validate_add_protection_tx_id_and_nonces(
            nested,
            check_length=False,
        )

    def test_invalid_added_protection_transaction_id(self):
        """
        GIVEN an invalid added protection request due to a mismatch of the transaction ID.
        WHEN the message is validated,
        THEN a BadRequest exception must be raised.
        """
        tx_id = (b"1234", b"5678")
        sender_nonce = (b"1234", b"1234")
        recip_nonce = (b"1234", b"1234")

        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=True)

        with self.assertRaises(BadRequest):
            validate_add_protection_tx_id_and_nonces(
                nested,
                check_length=False,
            )

    def test_invalid_added_protection_sender_nonce(self):
        """
        GIVEN an invalid added protection request due to a mismatch of the sender nonce.
        WHEN the message is validated,
        THEN a BadSenderNonce exception must be raised.
        """
        tx_id = (b"1234", b"1234")
        sender_nonce = (b"1234", b"5679")
        recip_nonce = (b"1234", b"1234")

        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=True)

        with self.assertRaises(BadSenderNonce):
            validate_add_protection_tx_id_and_nonces(
                nested,
                check_length=False,
            )

    def test_invalid_added_protection_recipient_nonce(self):
        """
        GIVEN an invalid added protection request due to a mismatch of the recipient nonce.
        WHEN the message is validated,
        THEN a BadRecipientNonce exception must be raised.
        """
        tx_id = (b"1234", b"1234")
        sender_nonce = (b"1234", b"1234")
        recip_nonce = (b"1234", b"5679")

        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=False)

        with self.assertRaises(BadRecipientNonce):
            validate_add_protection_tx_id_and_nonces(
                nested,
                check_length=False,
            )

    def test_invalid_added_protection_invalid_length(self):
        """
        GIVEN an invalid added protection request due to a mismatch of the lengths.
        WHEN the message is validated,
        THEN a BadRequest exception must be raised.
        """
        tx_id = (b"1234", b"1234")
        sender_nonce = (b"1234", b"1234")
        recip_nonce = (b"1234", b"1234")

        nested = self._generate_messages(tx_id, sender_nonce, recip_nonce, for_ir=False)

        with self.assertRaises(BadRequest):
            validate_add_protection_tx_id_and_nonces(
                nested,
                check_length=True,
            )





