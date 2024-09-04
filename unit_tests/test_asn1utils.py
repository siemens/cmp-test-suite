import unittest

from pyasn1.type import univ

from resources import cmputils
from resources.asn1utils import is_bit_set, get_asn1_value
from resources import asn1utils
from resources.cmputils import parse_pki_message
from resources.utils import load_and_decode_pem_file

class TestASN1Utils(unittest.TestCase):
    @classmethod
    def setUp(cls):
        raw = load_and_decode_pem_file('data/cmp-sample-reject.pem')
        cls.asn1_object = parse_pki_message(raw)

        default_str = "0" * 26
        default_str_list = list(default_str)
        # Change the characters at the desired indices
        default_str_list[1] = "1" # change to badPOP
        default_str_list[9] = "1" # badMessageCheck
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
            asn1utils.get_asn1_value_as_string(self.asn1_object, 'bad.query')

    def test_get_asn1_value_as_string(self):
        """
        GIVEN a pyasn1 object and a valid query
        WHEN get_asn1_value_as_string is called.
        THEN a string is expected, and its value must match the expected value
        """
        result = asn1utils.get_asn1_value_as_string(self.asn1_object,
                                                    'header.sender.directoryName.rdnSequence/0/0.value')
        self.assertIsInstance(result, str)
        self.assertEqual(result, 'NetoPay')

    def test_get_asn1_value_as_bytes(self):
        """
        GIVEN a pyasn1 object and a valid query
        WHEN get_asn1_value_as_bytes is called.
        THEN a byte array is returned, and the first few bytes match the expected prefix
        """
        result = asn1utils.get_asn1_value_as_bytes(self.asn1_object, 'protection')
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 512)
        expected_prefix = b'\x19 \xe1\x91U\x9ba\xbd\xd3\x8d\xeb\xa9\x89'
        self.assertEqual(result[:len(expected_prefix)], expected_prefix)

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
        expected_fields = 'header,body,protection,extraCerts'
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
        expected_fields = 'thisfieldisabsent,soisthisone'
        with self.assertRaises(ValueError):
            asn1utils.asn1_must_contain_fields(self.asn1_object, expected_fields)


    def test_is_bit_set(self):

        default_str = "0" * 26

        bitstring = univ.BitString(default_str)

        self.assertFalse(is_bit_set(bitstring, "1"), msg='Should is bit set should not return True')

        bitstring = univ.BitString(self.string_not_exclusive)
        self.assertTrue(is_bit_set(bitstring, "1", exclusive=False), msg='Should is bit set should not return True')
        self.assertFalse(is_bit_set(bitstring, "1,9", exclusive=True), msg='Should is bit set should not return True')


    def test_is_bit_set_with_human_readable_names(self):

        set_both_values = get_asn1_value(cmputils._generate_pki_status_info(bit_string=self.string_not_exclusive), "failInfo")

        self.assertFalse(is_bit_set(set_both_values, "badPOP,badMessageCheck", exclusive=True), msg='Should is bit set should not return True')
        self.assertTrue(is_bit_set(set_both_values, "badPOP,badMessageCheck", exclusive=False), msg='Should is bit set should not return True')


        with self.assertRaises(ValueError):
            is_bit_set(set_both_values, "UNDEFINED")



if __name__ == '__main__':
    unittest.main()
