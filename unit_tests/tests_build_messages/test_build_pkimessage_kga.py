# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import build_csr
from resources.cmputils import (
    build_cr_from_key,
    build_ir_from_key,
    build_key_update_request,
    build_p10cr_from_csr,
    get_cmp_message_type,
)
from resources.keyutils import generate_key


class TestPKIMessageKGA(unittest.TestCase):
    def setUp(self):
        self.sender = "CN=Sender"
        self.recipient = "CN=Recipient"
        self.common_name = "CN=Hans the Tester"
        self.key_kga = generate_key("rsa")
        self.certificate = None
        self.omit_fields = None

    def test_pkimessage_cr_en_and_decoding(self):
        """
        GIVEN a PKIMessage for certificate request ('cr').
        WHEN it is encoded to DER format and decoded back.
        THEN the message type should still be 'cr' and no additional data should remain.
        """
        pki_message = build_cr_from_key(
            body="cr",
            sender=self.sender,
            recipient=self.recipient,
            common_name=self.common_name,
            signing_key=self.key_kga,
            for_kga=True,
            cert=self.certificate,
            exclude_fields=self.omit_fields,
        )
        encoded_message = encoder.encode(pki_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(decoded_message), "cr")

    def test_pkimessage_p10cr_en_and_decoding(self):
        """
        GIVEN a PKIMessage for P10 certificate request ('p10cr').
        WHEN it is encoded to DER format and decoded back.
        THEN the message type should still be 'p10cr' and the PKIBody should not be empty.
        """
        csr = build_csr(for_kga=True, signing_key=self.key_kga)
        pki_message = build_p10cr_from_csr(
            csr=csr,
            sender=self.sender,
            recipient=self.recipient,
            common_name=self.common_name,
            body="p10cr",
            cert=self.certificate,
            exclude_fields=self.omit_fields,
        )
        encoded_message = encoder.encode(pki_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(decoded_message), "p10cr")
        self.assertTrue(decoded_message["body"]["p10cr"].isValue, "PKIBody 'p10cr' should not be empty.")

    def test_pkimessage_ir_en_and_decoding(self):
        """
        GIVEN a PKIMessage for initialization request ('ir').
        WHEN it is encoded to DER format and decoded back.
        THEN the message type should still be 'ir' and no additional data should remain.
        """
        pki_message = build_ir_from_key(
            sender=self.sender,
            recipient=self.recipient,
            common_name=self.common_name,
            signing_key=self.key_kga,
            for_kga=True,
            cert=self.certificate,
            exclude_fields=self.omit_fields,
        )
        encoded_message = encoder.encode(pki_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(decoded_message), "ir")

    def test_pkimessage_kur_en_and_decoding(self):
        """
        GIVEN a PKIMessage for key update request ('kur').
        WHEN it is encoded to DER format and decoded back.
        THEN the message type should still be 'kur' and no additional data should remain.
        """
        pki_message = build_key_update_request(
            signing_key=self.key_kga,
            sender=self.sender,
            recipient=self.recipient,
            common_name=self.common_name,
            for_kga=True,
            cert=self.certificate,
            exclude_fields=self.omit_fields,
        )
        encoded_message = encoder.encode(pki_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(decoded_message), "kur")

    def test_pkimessage_kur_en_and_decoding_without_alg(self):
        """
        GIVEN a PKIMessage for key update request ('kur') without specifying a key algorithm.
        WHEN it is encoded to DER format and decoded back.
        THEN the message type should still be 'kur' and no additional data should remain.
        """
        pki_message = build_key_update_request(
            sender=self.sender,
            recipient=self.recipient,
            common_name=self.common_name,
            for_kga=True,
            signing_key=None,
            cert=self.certificate,
            exclude_fields=self.omit_fields,
        )
        encoded_message = encoder.encode(pki_message)
        decoded_message, rest = decoder.decode(encoded_message, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(decoded_message), "kur")


if __name__ == "__main__":
    unittest.main()
