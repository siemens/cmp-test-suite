# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.certbuildutils import build_certificate
from resources.cmputils import (
    build_key_update_request,
    get_cmp_message_type,
)
from resources.keyutils import generate_key


class TestBuildKUR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = "test-cmp-cli@example.com"
        cls.recipient = "test-cmp-srv@example.com"
        cls.common_name = "CN=Hans the Tester"
        cls.cert, cls.key = build_certificate()

    def test_build_kur_with_cert_and_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a kur body, with a provided private key and certificate
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        key = generate_key("ec")
        pki_message = build_key_update_request(
            signing_key=key, cert=self.cert, sender=self.sender, recipient=self.recipient,
            exclude_fields=None
        )
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "kur")

    def test_build_kur_and_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a kur body with a provided private key
        WHEN the PKIMessage encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        key = generate_key("ec")
        pki_message = build_key_update_request(
            signing_key=key, exclude_fields=None,
            sender=self.sender, recipient=self.recipient)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "kur")

    def test_build_kur_with_controls_and_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a kur body, with a provided private key and certificate,
        with the `use_controls` flag.
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        key = generate_key("ec")
        pki_message = build_key_update_request(
            signing_key=key,
            cert=self.cert,
            exclude_fields=None,
            sender=self.sender,
            recipient=self.recipient,
            use_controls=True,
        )
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "kur")
