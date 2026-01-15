# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources import asn1utils
from resources.cmputils import parse_pkimessage
from resources.utils import load_and_decode_pem_file
from resources.prepareutils import prepare_relative_distinguished_name

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

    def test_set_asn1_value_invalid_paths(self):
        """
        GIVEN invalid asn1paths
        WHEN we try to set a value at that path
        THEN ValueError is raised
        """
        bad_paths = ["", "rootonly", "header.", "header/"]

        for path in bad_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    asn1utils.set_asn1_value(self.pkimessage, path, "val")

    def test_set_asn1_value_coerced_integer_primitive(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a univ.Integer according to the schema
        WHEN we set the member of the structure given by asn1path to a Python integer
        THEN the integer becomes univ.Integer and the entire structure is updated correctly
        """
        # pvno is univ.Integer, but we pass a Python primitive integer
        asn1utils.set_asn1_value(self.pkimessage, "header.pvno", 2)
        updated_val = asn1utils.get_asn1_value(self.pkimessage, "header.pvno")
        self.assertEqual(int(updated_val), 2)


    def test_set_asn1_value_type_good_constraints_bad(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a univ.Integer with NamedValues in the schema
        WHEN we set the member of the structure to a number outside the defined NamedValues range
        THEN the structure is updated correctly
        """
        # pvno is univ.Integer with predefined names: ('cmp1999', 1), ('cmp2000', 2), ('cmp2021', 3))
        # but we give it a number that is not defined. It should still work, because named values are not constraints.
        asn1utils.set_asn1_value(self.pkimessage, "header.pvno", 45)

        updated_val = asn1utils.get_asn1_value(self.pkimessage, "header.pvno")
        self.assertEqual(int(updated_val), 45)


    def test_set_asn1_value_complex(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a complex object
        WHEN we set that inner object to a valid value
        THEN the parent pyasn1 object is updated correctly
        """
        # The test structure we try it with has header.sender.directoryName.rdnSequence with 2 entries,
        # we modify the element at index 0
        new_rdn = prepare_relative_distinguished_name("CN=Joe Zeroth")
        asn1utils.set_asn1_value(self.pkimessage, "header.sender.directoryName.rdnSequence/0", new_rdn)


    def test_set_asn1_value_within_bounds(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a set or sequence
        WHEN we set a value at an index that does not exceed the length of the container
        THEN the structure is updated correctly
        """
        # the dummy pkimessage we deal with has 2 rdns, so indices 0 and 1 are valid. It must work for 0 or 1,
        # i.e. if we overwrite it; and for 2 when we expand the list. All higher indices should fail

        new_rdn_1 = prepare_relative_distinguished_name("CN=Joe Primus")
        new_rdn_2 = prepare_relative_distinguished_name("CN=Joe Secundos")

        # this should work
        asn1utils.set_asn1_value(self.pkimessage, "header.sender.directoryName.rdnSequence/0", new_rdn_1)
        asn1utils.set_asn1_value(self.pkimessage, "header.sender.directoryName.rdnSequence/1", new_rdn_2)


    def test_set_asn1_value_edge_bounds(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a set or sequence
        WHEN we set a value at the index that is +1 the length of the container
        THEN the container is extended and the new value is appended to it
        """
        # the dummy pkimessage we deal with has 2 rdns, only indices 0 and 1 exist. If we set a value at index 2,
        # the structure is automatically extended.
        self.assertEqual(len(self.pkimessage['header']['sender']['directoryName']['rdnSequence']), 2)

        new_rdn = prepare_relative_distinguished_name("CN=Joe Dritter")
        asn1utils.set_asn1_value(self.pkimessage, "header.sender.directoryName.rdnSequence/2", new_rdn)

        self.assertEqual(len(self.pkimessage['header']['sender']['directoryName']['rdnSequence']), 3)




    def test_set_asn1_value_outside_bounds(self):
        """
        GIVEN a pyasn1 object, an asn1path that points to a set or sequence
        WHEN we set a value at the index that is > +1 the length of the container
        THEN an error is thrown
        """
        new_rdn = prepare_relative_distinguished_name("CN=Joe Outsider")
        with self.assertRaises(ValueError):
            asn1utils.set_asn1_value(self.pkimessage, "header.sender.directoryName.rdnSequence/4", new_rdn)


    def test_set_asn1_value_bad_value(self):
        """
        GIVEN a pyasn1 object, and a valid asn1path
        WHEN we set a value at the path to a type that violates the schema
        THEN an error is thrown
        """
        # pvno is univ.Integer, but we pass it something completely different
        with self.assertRaises(ValueError):
            asn1utils.set_asn1_value(self.pkimessage, "header.pvno", "haha")

        with self.assertRaises(ValueError):
            asn1utils.set_asn1_value(self.pkimessage, "header.pvno", [1, 2, "haha"])


if __name__ == "__main__":
    unittest.main()
