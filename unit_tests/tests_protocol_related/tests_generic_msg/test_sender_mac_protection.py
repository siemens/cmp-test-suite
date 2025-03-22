# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import check_sender_cmp_protection
from resources.cmputils import (
    prepare_general_name,
)
from resources.protectionutils import protect_pkimessage

from unit_tests.utils_for_test import build_pkimessage, de_and_encode_pkimessage


class TestSenderFieldForMacProtection(unittest.TestCase):
    def test_check_sender_is_directoryName(self):
        """
        GIVEN a PKIMessage with MAC-based protection and the sender's GeneralName set to 'directoryName'
        WHEN check_sender_cmp_protection is called,
        THEN the function should pass without raising an exception
        """
        pki_message = build_pkimessage(body_type="p10cr", sender=prepare_general_name("directoryName", "CN=Hans"))

        protected_msg = protect_pkimessage(
            pki_message=pki_message,
            cert=None,
            private_key=None,
            protection="pbmac1",
            password="PASSWORD",
            exclude_cert=False,
        )

        protected_msg = de_and_encode_pkimessage(protected_msg)
        check_sender_cmp_protection(pki_message=protected_msg, allow_failure=False)

    def test_check_sender_not_directoryName(self):
        """
        GIVEN a PKIMessage with MAC-based protection and the sender's GeneralName NOT set to 'directoryName'
        WHEN check_sender_cmp_protection is called,
        THEN a ValueError should be raised indicating that the sender's GeneralName is invalid for MAC-based protection
        """
        pki_message = build_pkimessage(body_type="p10cr", sender="CN=Hans")

        protected_msg = protect_pkimessage(
            pki_message=pki_message,
            cert=None,
            private_key=None,
            protection="pbmac1",
            password="PASSWORD",
            exclude_cert=False,
        )
        protected_msg = de_and_encode_pkimessage(protected_msg)

        with self.assertRaises(ValueError):
            check_sender_cmp_protection(pki_message=protected_msg, allow_failure=False)
