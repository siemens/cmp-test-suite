# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.cmputils import build_ir_from_key, build_nested_pkimessage, prepare_orig_pki_message, \
    add_general_info_values
from resources.exceptions import BadMacProtection, BadMessageCheck
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage, validate_orig_pkimessage
from unit_tests.prepare_ca_response import build_ca_pki_message


class TestValidateOrigPKIMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.password = "SiemensIT"
        cls.key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        cls.cm = "CN=Hans the Tester"

    def test_invalid_password(self):
        """
        GIVEN a PKIMessage protected with a different password.
        WHEN validate_orig_pkimessage is called,
        THEN should the BadMessageCheck exception be raised.
        """
        ir = build_ir_from_key(self.key, sender=self.cm, common_name=self.cm, for_mac=True)
        bad_ir = protect_pkimessage(
            pki_message=ir,
            password=self.password + "wrong",
            protection="pbmac1",
            bad_message_check=False,
        )

        nested = build_nested_pkimessage(
            other_messages=ir,
            for_added_protection=True,
        )

        orig_msg = prepare_orig_pki_message(bad_ir)
        nested = add_general_info_values(nested, orig_msg)

        with self.assertRaises(BadMessageCheck) as context:
            validate_orig_pkimessage(nested, password=self.password, must_be_present=True)
        self.assertEqual(str(context.exception), "The original `PKIMessage` protection is invalid.")

    def test_invalid_bad_protection(self):
        """
        GIVEN an original PKIMessage which was invalidly protected.
        WHEN validate_orig_pkimessage is called,
        THEN should the BadMessageCheck exception be raised.
        """
        ir = build_ir_from_key(self.key, sender=self.cm, common_name=self.cm, for_mac=True)
        bad_ir = protect_pkimessage(
            pki_message=ir,
            password=self.password,
            protection="pbmac1",
            bad_message_check=True,
        )

        nested = build_nested_pkimessage(
            other_messages=ir,
            for_added_protection=True,
        )

        orig_msg = prepare_orig_pki_message(bad_ir)
        nested = add_general_info_values(nested, orig_msg)

        with self.assertRaises(BadMessageCheck) as context:
            validate_orig_pkimessage(nested, password=self.password, must_be_present=True)
        self.assertEqual(str(context.exception), "The original `PKIMessage` protection is invalid.")
