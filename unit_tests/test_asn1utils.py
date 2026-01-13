# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import asn1utils
from resources.cmputils import parse_pkimessage
from resources.utils import load_and_decode_pem_file

from unit_tests.utils_for_test import build_pkimessage


class TestASN1Utils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = load_and_decode_pem_file("data/cmp-sample-reject.pem")
        cls.asn1_object = parse_pkimessage(raw)

        default_str = "0" * 26
        default_str_list = list(default_str)
        # Change the characters at the desired indices
        default_str_list[1] = "1"  # change to badPOP
        default_str_list[9] = "1"  # badMessageCheck
        default_str = "".join(default_str_list)

        # not exclusive bit string for test_is_bit_set and test_is_bit_set_with_human_readable_names.
        cls.string_not_exclusive = default_str


    def test_get_asn1_value_as_string_bad_query(self):
        """
        GIVEN a pyasn1 object and a bad query
        WHEN get_asn1_value_as_string is called.
        THEN a ValueError exception is expected
        """
        with self.assertRaises(ValueError):
            asn1utils.get_asn1_value_as_string(self.asn1_object, "bad.query")

    def test_get_asn1_value_as_string(self):
        """
        GIVEN a pyasn1 object and a valid query
        WHEN get_asn1_value_as_string is called.
        THEN a string is expected, and its value must match the expected value
        """
        result = asn1utils.get_asn1_value_as_string(
            self.asn1_object, "header.sender.directoryName.rdnSequence/0/0.value", decode=True
        )
        self.assertIsInstance(result, str)
        self.assertEqual(result, "NetoPay")

    def test_get_asn1_value_as_bytes(self):
        """
        GIVEN a pyasn1 object and a valid query
        WHEN get_asn1_value_as_bytes is called.
        THEN a byte array is returned, and the first few bytes match the expected prefix
        """
        result = asn1utils.get_asn1_value_as_bytes(self.asn1_object, "protection")
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 512)
        expected_prefix = b"\x19 \xe1\x91U\x9ba\xbd\xd3\x8d\xeb\xa9\x89"
        self.assertEqual(result[: len(expected_prefix)], expected_prefix)

    # def test_get_asn1_value_as_integer(self):
    # TODO this example is not actually a number, but a named value, think of another test later
    #     result = asn1utils.get_asn1_value_as_number(self.asn1_object, 'body.error.pKIStatusInfo.failInfo')
    #     self.assertIsInstance(result, int)
    #     self.assertEquals(result, 128)

    def test_asn1_must_contain_fields_positive(self):
        """
        GIVEN a pyasn1 structure and a comma-separated list of fields,
        WHEN all fields are present in the structure,
        THEN no exception must be raised.
        """
        expected_fields = "header,body,protection,extraCerts"
        try:
            asn1utils.asn1_must_contain_fields(self.asn1_object, expected_fields)
        except ValueError:
            self.fail("pkimessage_must_contain_fields() raised ValueError unexpectedly!")

    def test_asn1_must_contain_fields_negative(self):
        """
        GIVEN a pyasn1 structure and a comma-separated list of fields,
        WHEN one or more fields are absent from the structure,
        THEN a ValueError exception must be raised.
        """
        expected_fields = "thisfieldisabsent,soisthisone"
        with self.assertRaises(ValueError):
            asn1utils.asn1_must_contain_fields(self.asn1_object, expected_fields)

    def test_asn1_must_have_values_set_pos(self):
        """
        GIVEN a pyasn1 structure and a comma-separated list of fields,
        WHEN all fields have values set,
        THEN no exception must be raised.
        """
        pki_message = build_pkimessage()
        expected_fields = "header.transactionID,header.sender,header.recipient,body"
        asn1utils.asn1_must_have_values_set(pki_message, expected_fields)




class TestASN1UtilsSet(unittest.TestCase):
    """Test the asn1path setting logic"""
    @classmethod
    def setUpClass(cls):
        cls.raw = load_and_decode_pem_file("data/cmp-sample-reject.pem")

    def setUp(self):
        # We do this for every test, because the asn1_object will be mutated by
        # the setter; while we want to have a fresh start in each test
        self.pkimessage = parse_pkimessage(self.raw)

    def test_set_asn1_value_coerced_integer_primitive(self):
        """
        GIVEN a pyasn1 PKIMessage, an asn1path that points to a univ.Integer according to the schema
        WHEN we set the member of the structure given by asn1path to a Python integer
        THEN the integer becomes univ.Integer and the entire structure is updated correctly
        """
        # pvno is univ.Integer, but we pass a Python primitive integer
        asn1utils.set_asn1_value(self.pkimessage, "header.pvno", 2)
        # TODO consider encoding the whole thing

        updated_val = asn1utils.get_asn1_value(pkimessage, "header.pvno")
        self.assertEqual(int(updated_val), 2)



if __name__ == "__main__":
    unittest.main()
