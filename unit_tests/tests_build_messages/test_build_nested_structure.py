# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.cmputils import build_ir_from_key, build_nested_pkimessage
from resources.keyutils import load_private_key_from_file


def _nested_example() -> rfc9480.PKIMessage:  # noqa D417 undocumented-param
    """Build fresh messages to ensure new ones can be added to a nested message."""
    messages = []
    key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")

    for x in range(5):
        pki_message = build_ir_from_key(key, sender=f"test{x}@example.com")
        messages.append(pki_message)

    nested_structure = build_nested_pkimessage(other_messages=messages, exclude_fields=None)
    return nested_structure


class TestNestedPKIMessage(unittest.TestCase):
    def test_encode_decode_nested_pkimessage(self):
        """
        GIVEN a nested PKIMessage generated using the `build_nested_pkimessage` function.
        WHEN the message is encoded into DER format and decoded back.
        THEN the decoded message should match the original PKIMessage structure, and no data should be
        lost in the process.
        """
        original_message = build_nested_pkimessage(exclude_fields=None)
        encoded_message = encoder.encode(original_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertTrue(decoded_message["body"].getName() == "nested")

    def test_append_to_nested_structure(self):
        """
        GIVEN a nested PKIMessage and multiple other PKIMessages.
        WHEN these messages are appended to the nested structure.
        THEN the final nested PKIMessage should contain all appended messages without any errors.
        """
        messages = [build_nested_pkimessage(sender=f"test{x}@example.com") for x in range(3)]
        nested_message = build_nested_pkimessage(other_messages=messages)
        self.assertEqual(
            len(nested_message["body"]["nested"]),
            3,
            "The nested structure should contain exactly 3 appended messages.",
        )

    def test_nested_example_integration(self):
        """
        GIVEN a nested PKIMessage structure with multiple appended PKIMessages.
        WHEN the `nested_example` function is used to build the structure.
        THEN the nested message should contain 5 appended PKIMessages.
        """
        nested_message = _nested_example()
        self.assertEqual(
            len(nested_message["body"]["nested"]), 5, "The nested structure should contain exactly 5 messages."
        )

        der_data = encoder.encode(nested_message)
        decoded_message, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertTrue(decoded_message["body"].getName() == "nested")




if __name__ == "__main__":
    unittest.main()
