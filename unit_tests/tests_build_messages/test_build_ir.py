# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_signed_csr
from resources.cmputils import build_ir_from_csr, build_ir_from_key, get_cmp_message_type, parse_csr
from resources.keyutils import generate_key
from resources.utils import decode_pem_string
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildIR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = "test-cmp-cli@example.com"
        cls.recipient = "test-cmp-srv@example.com"
        cls.common_name = "CN=Hans the Tester"

    def test_build_ir_from_key_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a ir body from a provided private key
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        key = generate_key("ec")
        pki_message = build_ir_from_key(key, sender=self.sender, recipient=self.recipient)
        pki_msg = de_and_encode_pkimessage(pki_message)
        self.assertEqual(get_cmp_message_type(pki_msg), "ir")

    def test_build_ir_from_csr_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with a ir body from a provided CSR
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        csr, key = generate_signed_csr(common_name=self.common_name, key="rsa")
        csr = parse_csr(decode_pem_string(csr))
        pki_message = build_ir_from_csr(csr, key, sender=self.sender, recipient=self.recipient)
        _ = de_and_encode_pkimessage(pki_message)
