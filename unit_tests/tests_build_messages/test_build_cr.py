# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_signed_csr
from resources.cmputils import build_cr_from_csr, build_cr_from_key, get_cmp_message_type, parse_csr
from resources.keyutils import generate_key
from resources.utils import decode_pem_string


class TestBuildCr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = "test-cmp-cli@example.com"
        cls.recipient = "test-cmp-srv@example.com"
        cls.common_name = "CN=Hans the Tester"

    def test_build_cr_from_key_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a cr body from a provided private key
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        key = generate_key("ec")
        pki_message = build_cr_from_key(key, sender=self.sender, recipient=self.recipient)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "cr")

    def test_build_cr_from_csr_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a cr body from a provided CSR
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        csr, key = generate_signed_csr(common_name=self.common_name, key="rsa")
        csr = parse_csr(decode_pem_string(csr))
        pki_message = build_cr_from_csr(csr, key, sender=self.sender, recipient=self.recipient)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "cr")
