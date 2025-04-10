# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.ca_ra_utils import get_cert_req_msg_from_pkimessage
from resources.cmputils import add_reg_info_to_pkimessage, build_ir_from_key, prepare_reg_token_controls, \
    prepare_authenticator_control
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestAddRegInfoToPkiMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.new_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_add_single_entry(self):
        """
        GIVEN a PKIMessage and a reqInfo object.
        WHEN add_reg_info_to_pkimessage is called,
        THEN the PKIMessage should contain the new entry in the regInfo field
        """

        ir = build_ir_from_key(self.new_key, implicit_confirm=True)
        entry = prepare_reg_token_controls(
            "SuperSecretToken",
        )

        result = add_reg_info_to_pkimessage(ir, entry)
        cert_req_msg = get_cert_req_msg_from_pkimessage(result)

        self.assertEqual(len(cert_req_msg["regInfo"]), 1)
        der_data = try_encode_pyasn1(result)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        obj: PKIMessageTMP
        self.assertEqual(rest, b"")

        cert_req_msg = get_cert_req_msg_from_pkimessage(obj)
        self.assertEqual(len(cert_req_msg["regInfo"]), 1)

    def test_add_multiple_entries(self):
        """
        GIVEN a PKIMessage and multiple reqInfo objects.
        WHEN add_reg_info_to_pkimessage is called,
        THEN the PKIMessage should contain all the new entries in the regInfo field
        """

        ir = build_ir_from_key(self.new_key, implicit_confirm=True)
        entry1 = prepare_reg_token_controls(
            "SuperSecretToken1",
        )
        entry2 = prepare_authenticator_control(
            "SuperSecretToken2",
        )

        result = add_reg_info_to_pkimessage(ir, entry1)
        result = add_reg_info_to_pkimessage(result, entry2)
        cert_req_msg = get_cert_req_msg_from_pkimessage(result)
        self.assertEqual(len(cert_req_msg["regInfo"]), 2)
        der_data = try_encode_pyasn1(result)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
