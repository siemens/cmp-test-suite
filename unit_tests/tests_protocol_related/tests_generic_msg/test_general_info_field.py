# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources import checkutils
from resources.cmputils import patch_generalinfo

from unit_tests.utils_for_test import build_pkimessage


class TestGeneralInfoField(unittest.TestCase):
    def test_implicit_confirm_is_null(self):
        """
        GIVEN a PKI message with `implicitConfirm` set to NULL
        WHEN checking the `GeneralInfo` field,
        THEN it should pass the validation for implicitConfirm.
        """
        pki_message = build_pkimessage(implicit_confirm=False)
        pki_message = patch_generalinfo(pki_message, implicit_confirm=True)
        der_data = encoder.encode(pki_message)

        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())
        checkutils.check_generalinfo_field(pki_message)

    def test_implicit_confirm_absent(self):
        """
        GIVEN a PKI message without `implicitConfirm`
        WHEN checking the `GeneralInfo` field,
        THEN it should pass as implicitConfirm is not required.
        """
        pki_message = build_pkimessage(implicit_confirm=False)
        pki_message = patch_generalinfo(pki_message, implicit_confirm=True)
        der_data = encoder.encode(pki_message)
        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())
        checkutils.check_generalinfo_field(pki_message)

    def test_confirm_wait_time_valid(self):
        """
        GIVEN a PKI message with a valid `confirmWaitTime`
        WHEN checking the `confirmWaitTime` field,
        THEN it should pass validation.
        """
        pki_message = build_pkimessage()
        pki_message = patch_generalinfo(pki_message, confirm_wait_time=2000, implicit_confirm=False)
        der_data = encoder.encode(pki_message)
        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())
        checkutils.check_generalinfo_field(pki_message)

    def test_confirm_wait_time_and_implicit_confirm_invalid(self):
        """
        GIVEN a PKI message with both `confirmWaitTime` and `implicitConfirm`
        WHEN checking the `GeneralInfo` field,
        THEN it should raise a validation error as both fields cannot coexist.
        """
        pki_message = build_pkimessage()
        pki_message = patch_generalinfo(pki_message, implicit_confirm=True, confirm_wait_time=2000)
        der_data = encoder.encode(pki_message)
        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())

        with self.assertRaises(ValueError, msg="`confirmWaitTime` and `implicitConfirm` cannot coexist."):
            checkutils.check_generalinfo_field(pki_message)

    def test_confirm_wait_time_absent(self):
        """
        GIVEN a PKI message without `confirmWaitTime`
        WHEN checking the `confirmWaitTime` field,
        THEN it should pass as confirmWaitTime is optional.
        """
        pki_message = build_pkimessage()
        pki_message = patch_generalinfo(pki_message, confirm_wait_time=None, implicit_confirm=False)
        der_data = encoder.encode(pki_message)
        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())
        checkutils.check_confirmwaittime_in_generalinfo(pki_message)

    def test_invalid_confirm_wait_time(self):
        """
        GIVEN a PKI message with an invalid `confirmWaitTime`
        WHEN checking the `confirmWaitTime` field,
        THEN it should raise a validation error.
        """
        pki_message = build_pkimessage()
        pki_message = patch_generalinfo(pki_message, confirm_wait_time=-2000, implicit_confirm=False)
        der_data = encoder.encode(pki_message)
        pki_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())

        with self.assertRaises(ValueError):
            checkutils.check_confirmwaittime_in_generalinfo(pki_message)
