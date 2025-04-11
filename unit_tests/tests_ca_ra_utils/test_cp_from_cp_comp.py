# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from resources.ca_ra_utils import build_cp_from_p10cr
from resources.certbuildutils import build_csr
from resources.checkutils import validate_ca_message_body
from resources.cmputils import build_p10cr_from_csr
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestCPFromP10crComplete(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


    def test_cp_from_cp_comp(self):
        """
        GIVEN a PKIMessage with a P10CR body.
        WHEN building a CP message,
        THEN the CP message is correctly built.
        """
        csr = build_csr(self.rsa_key)
        tx_id = os.urandom(16)
        sender_nonce = os.urandom(16)
        p10cr = build_p10cr_from_csr(csr,
                             sender="CN=Hans the Tester",
                             recipient="CN=Mock CA",
                             transaction_id=tx_id,
                             sender_nonce=sender_nonce,
                             )

        cp, _ = build_cp_from_p10cr(p10cr, ca_cert=self.ca_cert, ca_key=self.ca_key)
        validate_ca_message_body(cp, used_p10cr=True)
        self.assertEqual(cp["header"]["transactionID"].asOctets(), tx_id)
        self.assertEqual(cp["header"]["recipNonce"].asOctets(), sender_nonce)
        self.assertEqual(str(cp["header"]["recipient"]["rfc822Name"]), "CN=Hans the Tester")
