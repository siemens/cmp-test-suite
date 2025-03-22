# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc4210, rfc5280, rfc9480
from resources.asn1utils import (
    asn1_compare_named_integer,
    asn1_compare_named_values,
    asn1_get_named_value,
    asn1_names_to_bitstring,
    is_bit_set,
)


class TestASN1Utils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default_str = "0" * 26
        default_str_list = list(default_str)
        # Change the characters at the desired indices
        default_str_list[1] = "1"  # change to badPOP
        default_str_list[9] = "1"  # badMessageCheck
        default_str = "".join(default_str_list)
        # not exclusive bit string for test_is_bit_set and test_is_bit_set_with_human_readable_names.
        cls.string_not_exclusive = default_str

    def test_is_bit_set(self):
        """
        GIVEN a BitString object
        WHEN is_bit_set is called with specific bit positions
        THEN the function should correctly identify if the bits are set based on the exclusive parameter
        """
        default_str = "0" * 26
        bitstring = univ.BitString(default_str)

        self.assertFalse(is_bit_set(bitstring, "1"), msg="Should is bit set should not return True")

        bitstring = univ.BitString(self.string_not_exclusive)
        self.assertTrue(is_bit_set(bitstring, "1", exclusive=False), msg="Should is bit set should not return True")
        self.assertFalse(is_bit_set(bitstring, "1,9", exclusive=True), msg="Should is bit set should not return True")

    def test_compare_named_int(self):
        """
        GIVEN an `pyasn` object which has named integer values
        WHEN compared with the human-readable string representation
        THEN should not raise an exception and return either True if equal or False if unequal.
        """
        val = rfc4210.PKIStatus(0)

        self.assertTrue(asn1_compare_named_integer(val, "accepted"))
        self.assertFalse(asn1_compare_named_integer(val, "rejection"))

    def test_compare_named_int_with_invalid_str(self):
        """
        GIVEN an `pyasn` object which has named integer values
        WHEN compared with an invalid human-readable string representation
        THEN should raise an exception.
        """
        val = rfc9480.PKIStatus(0)
        with self.assertRaises(ValueError):
            asn1_compare_named_integer(val, "assaddada")

    def test_get_name_value(self):
        """
        GIVEN an `pyasn` object which has named values
        WHEN extract the value for the human-readable representation.
        THEN should not raise an exception and be equal the expected value.
        """
        self.assertTrue(int(asn1_get_named_value(rfc4210.PKIStatus(), "accepted")) == 0)
        self.assertTrue(int(asn1_get_named_value(rfc4210.PKIFailureInfo(), "badMessageCheck")) == 1)
        self.assertTrue(int(asn1_get_named_value(rfc5280.CRLReason(), "superseded")) == 4)

        # without initiation.
        self.assertTrue(int(asn1_get_named_value(rfc4210.PKIStatus, "accepted")) == 0)
        self.assertTrue(int(asn1_get_named_value(rfc4210.PKIFailureInfo, "badMessageCheck")) == 1)
        self.assertTrue(int(asn1_get_named_value(rfc5280.CRLReason, "superseded")) == 4)

    def test_get_name_value_encoded(self):
        """
        GIVEN an `pyasn` object which has named values
        WHEN extract the value for the human-readable representation.
        THEN should return the wished object.
        """
        self.assertIsInstance((asn1_get_named_value(rfc4210.PKIStatus, "accepted")), rfc9480.PKIStatus)
        self.assertIsInstance((asn1_get_named_value(rfc4210.PKIFailureInfo, "badMessageCheck")), rfc9480.PKIFailureInfo)
        self.assertIsInstance((asn1_get_named_value(rfc5280.CRLReason, "superseded")), rfc5280.CRLReason)

    def test_asn1_names_to_bitstring(self):
        """
        GIVEN human-readable names for bit positions in an ASN.1 BitString (e.g., 'badAlg', 'badTime')
        WHEN asn1_names_to_bitstring is called
        THEN it should return a BitString object with the appropriate bits set based on the input names
        """
        readable_names = "badAlg, badTime"  # badTime has index 3 and badAlg index 0.
        asn1_object = asn1_names_to_bitstring(rfc4210.PKIFailureInfo, readable_names)
        self.assertIsInstance(asn1_object, rfc4210.PKIFailureInfo)
        self.assertEqual(asn1_object.asBinary(), "1001")

        asn1_object2 = asn1_names_to_bitstring(rfc4210.PKIFailureInfo(), readable_names)
        self.assertIsInstance(asn1_object2, rfc4210.PKIFailureInfo)
        self.assertEqual(asn1_object2.asBinary(), "1001")

    def test_asn1_compare_named_values(self):
        """
        GIVEN a pyasn1 object that represents a named value.
        WHEN asn1_compare_named_values is called with human-readable names and the exclusive flag
        THEN it should correctly identify whether the named values or bit positions are set based on the exclusive flag
        """
        asn1_object1 = asn1_get_named_value(rfc9480.PKIStatus, "accepted")
        self.assertTrue(asn1_compare_named_values(asn1_object1, "accepted"))

        asn1_object2 = asn1_names_to_bitstring(rfc4210.PKIFailureInfo, "badAlg, badTime")
        self.assertEqual(asn1_object2.asBinary(), "1001")
        self.assertTrue(asn1_compare_named_values(asn1_object2, " badAlg", exclusive=False))
        self.assertTrue(asn1_compare_named_values(asn1_object2, "badTime ", exclusive=False))
        self.assertTrue(asn1_compare_named_values(asn1_object2, "badAlg, badTime", exclusive=False))

        self.assertFalse(asn1_compare_named_values(asn1_object2, " badAlg", exclusive=True))
        self.assertFalse(asn1_compare_named_values(asn1_object2, "badTime ", exclusive=True))

        with self.assertRaises(ValueError):
            asn1_compare_named_values(asn1_object2, "badAlg", exclusive=True, raise_exception=True)

        with self.assertRaises(ValueError):
            asn1_compare_named_values(asn1_object2, "badTime", exclusive=True, raise_exception=True)

        with self.assertRaises(ValueError):
            asn1_compare_named_values(asn1_object2, "badAlg, badTime", exclusive=True, raise_exception=True)
