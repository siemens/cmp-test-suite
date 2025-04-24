# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources.asn1utils import encode_to_der
from resources.cmputils import (
    build_cmp_error_message,
    get_cmp_message_type,
    verify_pkistatusinfo,
    verify_statusstring,
)
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildErrorBody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = "test-cmp-cli@example.com"
        cls.recipient = "test-cmp-srv@example.com"
        cls.common_name = "CN=Hans the Tester"

    def test_build_error_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with an error body
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        pki_message = build_cmp_error_message(sender=self.sender, recipient=self.recipient)
        _ = de_and_encode_pkimessage(pki_message)

    def test_build_error_text_and_failinfo_en_and_decode(self):
        """
        GIVEN a valid PKIMessage with an error body with failinfo and PKIFreeText and status.
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        pki_message = build_cmp_error_message(
            sender=self.sender,
            recipient=self.recipient,
            status="rejection",
            texts="This is my text",
            failinfo="badAlg,badMessageCheck",
        )

        pki_msg = de_and_encode_pkimessage(pki_message)
        verify_pkistatusinfo(pki_msg, failinfos="badAlg", exclusive=False)
        verify_statusstring(pki_msg, all_text="This is my text", any_text="This is my text")
