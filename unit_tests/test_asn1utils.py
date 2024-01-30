import unittest

from resources import asn1utils
from resources.cmputils import parse_pki_message
from resources.utils import load_and_decode_pem_file


class TestASN1Utils(unittest.TestCase):
    def setUp(self):
        raw = load_and_decode_pem_file('data/cmp-sample-reject.pem')
        self.pki_message = parse_pki_message(raw)

    def test_get_asn1_value_as_string_bad_query(self):
        """
        GIVEN a pyasn1 pkimessage and a bad query
        WHEN get_asn1_value_as_string is called
        THEN a ValueError exception is expected
        """
        with self.assertRaises(ValueError):
            asn1utils.get_asn1_value_as_string(self.pki_message, 'bad.query')

    def test_get_asn1_value_as_string(self):
        """
        GIVEN a pyasn1 pkimessage and a valid query
        WHEN get_asn1_value_as_string is called
        THEN a string is expected, and its value must match the expected value
        """
        result = asn1utils.get_asn1_value_as_string(self.pki_message, 'header.sender.directoryName.rdnSequence/0/0.value')
        self.assertIsInstance(result, str)
        self.assertEqual(result, 'NetoPay')

    def test_get_asn1_value_as_bytes(self):
        """
        GIVEN a pyasn1 pkimessage and a valid query
        WHEN get_asn1_value_as_bytes is called
        THEN a byte array is returned, and the first few bytes match the expected prefix
        """
        result = asn1utils.get_asn1_value_as_bytes(self.pki_message, 'protection')
        self.assertIsInstance(result, bytes)
        expected_prefix = b'\x19 \xe1\x91U\x9ba\xbd\xd3\x8d\xeb\xa9\x89'
        self.assertEqual(result[:len(expected_prefix)], expected_prefix)

    # def test_get_asn1_value_as_integer(self):
    # TODO this example is not actually a number, but a named value, think of another test later
    #     result = asn1utils.get_asn1_value_as_number(self.pkimessage, 'body.error.pKIStatusInfo.failInfo')
    #     self.assertIsInstance(result, int)
    #     self.assertEquals(result, 128)


if __name__ == '__main__':
    unittest.main()