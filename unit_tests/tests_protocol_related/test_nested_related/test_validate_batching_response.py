# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import validate_ids_and_nonces_for_nested_response
from resources.cmputils import build_nested_pkimessage, patch_recipnonce, patch_sendernonce, patch_transaction_id

from unit_tests.prepare_ca_response import build_ca_pki_message
from unit_tests.utils_for_test import build_pkimessage


class TestValidateIdsAndNoncesForNestedResponse(unittest.TestCase):
    def setUp(self):
        request_pki_message = build_pkimessage(body_type="p10cr")
        self.transaction_id = b'AAAAAAAAAAAAAAAA'
        self.sender_nonce = b'BBBBBBBBBBBBBBBB'
        self.nested_id = b'CCCCCCCCCCCCCCCC'
        request_pki_message = patch_transaction_id(request_pki_message, self.transaction_id)
        request_pki_message = patch_sendernonce(request_pki_message, sender_nonce=self.sender_nonce)
        self.nested_request = build_nested_pkimessage(exclude_fields=None,
                                                      other_messages=request_pki_message,
                                                      transaction_id=self.nested_id,
                                                      sender_nonce=self.sender_nonce)


    def test_validate_ids_and_nonces_for_correct_nested_response(self):
        """
        GIVEN a nested PKI request and a valid nested PKI response
        WHEN `validate_ids_and_nonces_for_nested_response` is called,
        THEN it should validate the transactionIDs and nonces without raising any errors.
        """
        response_pki_message = build_ca_pki_message(body_type="cp")
        response_pki_message = patch_transaction_id(response_pki_message, self.transaction_id)
        response_pki_message = patch_recipnonce(response_pki_message, self.sender_nonce)
        nested_resp = build_nested_pkimessage(exclude_fields=None,
                                              other_messages=response_pki_message,
                                              recip_nonce=self.sender_nonce,
                                              transaction_id=self.nested_id)
        validate_ids_and_nonces_for_nested_response(self.nested_request, nested_resp)

    def test_validate_ids_and_nonces_with_incorrect_body_type(self):
        """
        GIVEN a nested PKI request and a nested PKI response with an incorrect body type
        ("cr" and got "cr" as response)
        WHEN `validate_ids_and_nonces_for_nested_response` is called
        THEN it should raise a `ValueError` indicating an incorrect PKIBody type.
        """
        incorrect_response = build_pkimessage(body_type="cr", transaction_id=self.transaction_id)
        incorrect_response = patch_recipnonce(incorrect_response, self.sender_nonce)
        nested_resp = build_nested_pkimessage(exclude_fields=None,
                                              other_messages=incorrect_response,
                                              recip_nonce=self.sender_nonce,
                                              transaction_id=self.nested_id)

        with self.assertRaises(ValueError):
            validate_ids_and_nonces_for_nested_response(self.nested_request, nested_resp)


    def test_validate_ids_and_nonces_with_invalid_transaction_id(self):
        """
        GIVEN a nested PKI request and a nested PKI response with a different transactionID
        (inside the nested structure)
        WHEN `validate_ids_and_nonces_for_nested_response` is called,
        THEN it should raise a `ValueError` the mismatch.
        """
        incorrect_transaction_id = b'DDDDDDDDDDDDDDDD'
        incorrect_response = build_ca_pki_message(body_type="cp")
        incorrect_response = patch_recipnonce(incorrect_response, recip_nonce=self.sender_nonce)
        incorrect_response = patch_transaction_id(incorrect_response, incorrect_transaction_id)

        incorrect_resp_message = build_nested_pkimessage(exclude_fields=None,
                                                         other_messages=incorrect_response,
                                                         recip_nonce=self.sender_nonce,
                                                         transaction_id=self.nested_id)
        with self.assertRaises(ValueError):
            validate_ids_and_nonces_for_nested_response(self.nested_request, incorrect_resp_message)


    def test_validate_ids_and_nonces_with_invalid_sender_nonce(self):
        """
        GIVEN a nested PKI request and a nested PKI response with a different senderNonce
        (inside the nested structure)
        WHEN `validate_ids_and_nonces_for_nested_response` is called,
        THEN it should raise a `ValueError` indicating that the response did not contain the response for a message.
        """
        incorrect_sender_nonce = b'EEEEEEEEEEEEEEEE'
        incorrect_response = build_ca_pki_message(body_type="cp")
        incorrect_response = patch_recipnonce(incorrect_response, recip_nonce=incorrect_sender_nonce)
        incorrect_response = patch_transaction_id(incorrect_response, self.transaction_id)
        incorrect_resp_message = build_nested_pkimessage(exclude_fields=None,
                                                         other_messages=incorrect_response,
                                                         recip_nonce=self.sender_nonce,
                                                         transaction_id=self.nested_id)

        with self.assertRaises(ValueError):
            validate_ids_and_nonces_for_nested_response(self.nested_request, incorrect_resp_message)



if __name__ == "__main__":
    unittest.main()
