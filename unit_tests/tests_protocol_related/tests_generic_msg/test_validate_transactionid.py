# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import validate_transaction_id
from resources.cmputils import patch_transaction_id
from resources.exceptions import BadRequest, BadDataFormat
from resources.utils import manipulate_first_byte

from unit_tests.utils_for_test import build_pkimessage


class TestValidateTransactionID(unittest.TestCase):
    def test_valid_transaction_id_matching(self):
        """
        GIVEN a request PKI message with a transaction ID and a response PKI message with a matching transaction ID.
        WHEN validate_transaction_id is called.
        THEN it should confirm that the transaction IDs match, raising no exceptions.
        """
        request_pki_message = build_pkimessage()
        response_pki_message = build_pkimessage(omit_fields="transactionID")
        other_id = request_pki_message["header"]["transactionID"].asOctets()
        response_pki_message = patch_transaction_id(response_pki_message, other_id)
        validate_transaction_id(response_pki_message, request_pki_message)

    def test_invalid_transaction_id_length(self):
        """
        GIVEN a response PKI message with an incorrect transaction ID length.
        WHEN validate_transaction_id is called.
        THEN it should raise a ValueError indicating that the transaction ID must be 128 bits long.
        """
        request_pki_message = build_pkimessage()
        response_pki_message = build_pkimessage(omit_fields="transactionID")
        response_pki_message = patch_transaction_id(response_pki_message, b"A" * 10)
        with self.assertRaises(BadRequest) as context:
            validate_transaction_id(response_pki_message, request_pki_message)
        self.assertIn("The `transactionID` must be 128 bits long", str(context.exception))

    def test_mismatched_transaction_id(self):
        """
        GIVEN a request PKI message and a response PKI message with differing transaction IDs.
        WHEN validate_transaction_id is called.
        THEN it should raise a ValueError due to the mismatch in transaction IDs.
        """
        request_pki_message = build_pkimessage(omit_fields="transactionID")
        response_pki_message = build_pkimessage(omit_fields="transactionID")
        trans_id = b"A" * 16
        modified = manipulate_first_byte(trans_id)

        response_pki_message = patch_transaction_id(response_pki_message, modified)
        request_pki_message = patch_transaction_id(request_pki_message, trans_id)
        with self.assertRaises(BadRequest) as context:
            validate_transaction_id(response_pki_message, request_pki_message)
        self.assertIn("`transactionID`", str(context.exception))

    def test_no_request_provided(self):
        """
        GIVEN a response PKI message with a valid transaction ID and no request PKI message.
        WHEN validate_transaction_id is called.
        THEN it should confirm that the transaction ID length is correct, raising no exceptions.
        """
        response_pki_message = build_pkimessage(transaction_id=b"A" * 16)
        validate_transaction_id(response_pki_message)

    def test_no_request_invalid_length(self):
        """
        GIVEN a response PKI message with an invalid transaction ID length and no request PKI message.
        WHEN validate_transaction_id is called.
        THEN it should raise a ValueError indicating that the transaction ID must be 128 bits long.
        """
        response_pki_message = build_pkimessage(omit_fields="transactionID")
        response_pki_message = patch_transaction_id(response_pki_message, b"A" * 10)
        with self.assertRaises(BadRequest) as context:
            validate_transaction_id(response_pki_message)
        self.assertIn("The `transactionID` must be 128 bits long", str(context.exception))

    def test_absent_transaction_id(self):
        """
        GIVEN a response PKI message without an transaction ID.
        WHEN validate_transaction_id is called.
        THEN it should raise a BadDataFormat exception.
        """
        response_pki_message = build_pkimessage(exclude_fields="transactionID")
        with self.assertRaises(BadDataFormat):
            validate_transaction_id(response_pki_message)


if __name__ == "__main__":
    unittest.main()
