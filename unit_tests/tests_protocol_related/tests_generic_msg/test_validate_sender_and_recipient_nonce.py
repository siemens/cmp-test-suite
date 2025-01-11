# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import validate_sender_and_recipient_nonce
from resources.cmputils import patch_recipnonce, patch_sendernonce

from unit_tests.utils_for_test import build_pkimessage

SENDER_NONCE_REQ = b"A" * 16


class TestValidateNonces(unittest.TestCase):
    def test_valid_sender_and_recip_nonce_matching(self):
        """
        GIVEN a request PKI message with a sender nonce and a response PKI message with a recipient
        nonce patched to match.
        WHEN validate_sender_and_recipient_nonce is called.
        THEN it should confirm that the recipient nonce in the response matches the sender nonce in the request.
        """
        request_pki_message = build_pkimessage(sender_nonce=SENDER_NONCE_REQ)
        response_pki_message = build_pkimessage()
        response_pki_message = patch_recipnonce(response_pki_message, SENDER_NONCE_REQ)
        validate_sender_and_recipient_nonce(response=response_pki_message, request=request_pki_message)
        self.assertEqual(SENDER_NONCE_REQ, response_pki_message["header"]["recipNonce"])

    def test_invalid_sender_nonce_length_responder(self):
        """
        GIVEN a request PKI message with a valid sender nonce and a response PKI message with an
        invalid sender nonce length.
        WHEN validate_sender_and_recipient_nonce is called.
        THEN it should raise a ValueError due to the invalid sender nonce length in the response.
        """
        request_pki_message = build_pkimessage(sender_nonce=SENDER_NONCE_REQ)
        response_pki_message = build_pkimessage(omit_fields="senderNonce")
        sender_nonce = request_pki_message["header"]["senderNonce"].asOctets()
        response_pki_message = patch_recipnonce(response_pki_message, sender_nonce)
        response_pki_message = patch_sendernonce(response_pki_message, sender_nonce=b"" * 10)
        with self.assertRaises(ValueError):
            validate_sender_and_recipient_nonce(response=response_pki_message, request=request_pki_message)

    def test_mismatched_sender_recipient_nonce(self):
        """
        GIVEN a request PKI message with a sender nonce and a response PKI message with modified,
        recipient nonce.
        WHEN validate_sender_and_recipient_nonce is called.
        THEN it should raise a ValueError because the recipient nonce in the response does not match
        the sender nonce in the request.
        """
        request_pki_message = build_pkimessage(sender_nonce=SENDER_NONCE_REQ)
        response_pki_message = build_pkimessage()
        modified = b"A" * 15 + b"B"
        response_pki_message = patch_recipnonce(response_pki_message, modified)
        with self.assertRaises(ValueError):
            validate_sender_and_recipient_nonce(response_pki_message, request_pki_message)


if __name__ == "__main__":
    unittest.main()
