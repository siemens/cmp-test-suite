# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.cmputils import build_cmp_error_message, verify_pkistatusinfo


class TestVerifyPKIStatusInfo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_message = build_cmp_error_message(
            texts="This is a sample status text", status="rejection", failinfo="badPOP",
            allow_failure_info=False
        )

    def test_verify_status_success(self):
        """
        GIVEN a `PKIMessage` with a rejection status
        WHEN verifying the status in the message,
        THEN it should pass if the status matches the expected rejection status.
        """
        verify_pkistatusinfo(self.pki_message, status="rejection", allow_failure_info=False)

    def test_verify_status_rejection_with_failinfo(self):
        """
        GIVEN a `PKIMessage` with a rejection status and a failinfo set to "badPOP"
        WHEN verifying the status and failinfo in the message,
        THEN it should pass if both status and failinfo match as expected.
        """
        verify_pkistatusinfo(self.pki_message, failinfos="badPOP", exclusive=True, allow_failure_info=False)

    def test_verify_status_failure(self):
        """
        GIVEN a `PKIMessage` with a rejection status
        WHEN verifying the status as "accepted"
        THEN it should raise a ValueError due to the mismatched status.
        """
        with self.assertRaises(ValueError):
            verify_pkistatusinfo(self.pki_message, status="accepted", allow_failure_info=False)

    def test_verify_failinfo_failure(self):
        """
        GIVEN a `PKIMessage` with a failinfo set to "badPOP"
        WHEN verifying the failinfo as "badSig"
        THEN it should raise a ValueError due to the mismatched failinfo.
        """
        with self.assertRaises(ValueError):
            verify_pkistatusinfo(self.pki_message, failinfos="badSig", exclusive=True, allow_failure_info=False)
