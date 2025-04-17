# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc4211, rfc9480

from resources.asn1utils import try_decode_pyasn1
from resources.ca_ra_utils import get_cert_req_msg_from_pkimessage
from resources.cmputils import build_ir_from_key, prepare_utf8_pairs_req_info, add_reg_info_to_pkimessage, \
    validate_reg_info_utf8_pairs
from resources.exceptions import BadAsn1Data
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestValidateReqInfoUtf8Pairs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_validate_req_info_utf8_pairs(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN validate_req_info_utf8_pairs is called,
        THEN the PKIMessage should contain the new entry in the regInfo field
        and be a valid PKIMessage.
        """
        ir = build_ir_from_key(self.key, implicit_confirm=True)
        data = """
        version?1%corp_company?Example, Inc.%org_unit?Engineering%
        mail_firstName?John%mail_lastName?Smith%jobTitle?Team Leader%
        mail_email?john@example.com%""".replace("\n", "").strip()
        entry = prepare_utf8_pairs_req_info(
            data,
            encode=True,
        )

        der_data = try_encode_pyasn1(entry)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")

        ir = add_reg_info_to_pkimessage(ir, obj)
        cert_req_msg = get_cert_req_msg_from_pkimessage(ir)
        self.assertTrue(cert_req_msg["regInfo"].isValue)
        self.assertEqual(len(cert_req_msg["regInfo"]), 1)
        self.assertEqual(cert_req_msg["regInfo"][0]["type"], rfc4211.id_regInfo_utf8Pairs)
        out = validate_reg_info_utf8_pairs(cert_req_msg["regInfo"])

        out_comp = ""
        for item in out:
            out_comp += f"{item[0]}?{item[1]}%"

        self.assertEqual(data, out_comp)

    def test_validate_req_info_utf8_pairs_invalid(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN validate_req_info_utf8_pairs is called with invalid data,
        THEN an exception should be raised.
        """
        ir = build_ir_from_key(self.key, implicit_confirm=True)
        data = """1version?1"""
        entry = prepare_utf8_pairs_req_info(
            data,
            encode=True,
        )
        der_data = try_encode_pyasn1(entry)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        ir = add_reg_info_to_pkimessage(ir, obj)
        cert_req_msg = get_cert_req_msg_from_pkimessage(ir)
        with self.assertRaises(BadAsn1Data):
            validate_reg_info_utf8_pairs(cert_req_msg["regInfo"])


