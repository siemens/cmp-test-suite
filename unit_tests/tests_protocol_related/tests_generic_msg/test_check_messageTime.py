# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from resources.certbuildutils import generate_signed_csr
from resources.checkutils import check_message_time_field
from resources.cmputils import build_p10cr_from_csr, parse_csr, patch_messageTime
from resources.exceptions import BadTime
from resources.utils import decode_pem_string


class TestCheckMessageTimeField(unittest.TestCase):
    @classmethod
    def setUp(cls):
        csr, private_key = generate_signed_csr(common_name="CN=Hans")
        csr = decode_pem_string(csr)
        csr = parse_csr(csr)
        pki_message = build_p10cr_from_csr(csr, exclude_fields="messageTime")

        cls.pki_message = pki_message
        cls.private_key = private_key

    def test_request_time_within_interval(self):
        """
        GIVEN a PKI response with a 'messageTime' set within the allowed time interval
        WHEN check_messagetime_field is called with a 60-second allowed interval
        THEN the function should pass without raising an exception.
        """
        request_time = datetime.datetime.now(datetime.timezone.utc)
        response_time = request_time + datetime.timedelta(seconds=30)
        response_pki_message = patch_messageTime(pki_message=self.pki_message, new_time=response_time)
        with self.assertLogs(level="INFO") as log:
            check_message_time_field(pki_message=response_pki_message, allowed_interval=60, request_time=request_time)
            # Normally, it returns 29 seconds, but I'll be forgiving.
            time_msg1 = "INFO:root:time difference between request and response: 29" in log.output[0]
            time_msg2 = "INFO:root:time difference between request and response: 30" in log.output[0]
            time_msg3 = "INFO:root:time difference between request and response: 28" in log.output[0]
            self.assertTrue(time_msg1 or time_msg2 or time_msg3)

    def test_messagetime_exceeds_allowed_interval(self):
        """
        GIVEN a PKI response with a 'messageTime' that exceeds the allowed time interval
        WHEN check_messagetime_field is called with a 60-second allowed interval
        THEN the function should pass without raising an exception
        """
        request_time = datetime.datetime.now(datetime.timezone.utc)
        response_time = request_time + datetime.timedelta(seconds=120)
        response_pki_message = patch_messageTime(pki_message=self.pki_message, new_time=response_time)

        with self.assertRaises(BadTime):
            check_message_time_field(response_pki_message, allowed_interval=60, request_time=request_time)
