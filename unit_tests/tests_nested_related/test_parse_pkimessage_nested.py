# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.cmputils import build_ir_from_key, build_nested_pkimessage, parse_pkimessage
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestParsePKIMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")


    def test_parse_nested_pkimessage(self):
        """
        GIVEN a valid nested PKIMessage.
        WHEN the PKIMessage is parsed.
        THEN must a PKIMessage be returned.
        """

        ir = build_ir_from_key(
            self.private_key
        )
        der_data_before = try_encode_pyasn1(ir)
        nested = build_nested_pkimessage(
            other_messages=ir,
            sender_nonce=b"sender_nonce",
            transaction_id=b"transaction_id",
            recip_nonce=b"recip_nonce",
            for_added_protection=True,
            exclude_fields=None,
        )
        der_data = try_encode_pyasn1(nested)
        nested, rest = try_decode_pyasn1(der_data, PKIMessageTMP(), for_nested=True)
        nested: PKIMessageTMP
        self.assertEqual(rest, b"")
        self.assertEqual(len(nested["body"]["nested"]), 1)
        self.assertEqual(nested["body"]["nested"][0]["body"].getName(), "ir")
        der_data = try_encode_pyasn1(nested["body"]["nested"][0])
        self.assertEqual(der_data, der_data_before, "The nested ir message is not the same as the original ir message.")
