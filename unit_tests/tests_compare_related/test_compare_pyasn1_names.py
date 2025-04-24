# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char
from pyasn1_alt_modules import rfc5280, rfc9480
from resources.prepareutils import prepare_name, prepare_general_name
from resources.compareutils import compare_pyasn1_names


def _prepare_name_with_seq(common_name1: str, common_name2: str):
    common_name_oid = rfc5280.id_at_commonName

    attr1 = rfc9480.AttributeTypeAndValue()
    attr1['type'] = common_name_oid
    attr1['value'] = char.UTF8String(common_name1)

    attr2 = rfc9480.AttributeTypeAndValue()
    attr2['type'] = common_name_oid
    attr2['value'] = char.UTF8String(common_name2)

    rdn1 = rfc5280.RelativeDistinguishedName()
    rdn2 = rfc5280.RelativeDistinguishedName()
    rdn1.setComponentByPosition(0, attr1)
    rdn2.setComponentByPosition(0, attr2)
    rdn_sequence = rfc5280.RDNSequence()
    rdn_sequence.setComponentByPosition(0, rdn1)
    rdn_sequence.setComponentByPosition(1, rdn2)
    name = rfc9480.Name()
    name["rdnSequence"] = rdn_sequence

    der_data = encoder.encode(name)
    decoded_name, _ = decoder.decode(der_data, rfc9480.Name())

    return decoded_name

class TestASN1Utils(unittest.TestCase):

    def test_without_tag_compare_valid_input(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names, without considering the tag,
        THEN the general name should be equal to the name.
        """
        gen_name = prepare_general_name(name_type="directoryName", name_str="CN=Hans the Tester")
        name = prepare_name("CN=Hans the Tester")
        is_equal = compare_pyasn1_names(name, gen_name["directoryName"], mode="without_tag")
        self.assertTrue(is_equal)

    def test_strict_with_gen_name_and_name(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names, considering the tag,
        THEN the general name should not be equal to the name.
        """
        gen_name = prepare_general_name(name_type="directoryName", name_str="CN=Hans the Tester")
        name = prepare_name("CN=Hans the Tester")
        is_equal = compare_pyasn1_names(name, gen_name["directoryName"], mode="strict")
        self.assertFalse(is_equal)

    def test_contains_with_correct_values(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names,
        THEN the general name should contain the name.
        """
        name2 = prepare_name("L=DE,CN=Hans the Tester")
        name1 = prepare_name("CN=Hans the Tester")
        is_equal = compare_pyasn1_names(name1, name2, mode="contains")
        self.assertTrue(is_equal)

    def test_contains_incorrect_values(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names,
        THEN the general name should not contain the name.
        """
        # to show that the tagging is not considered.
        gen_name = prepare_general_name(name_type="directoryName", name_str="L=DE,CN=Hans the Tester1")
        name = prepare_name("CN=Hans the Tester")
        is_equal = compare_pyasn1_names(name, gen_name["directoryName"], mode="contains_seq")
        self.assertFalse(is_equal)

    def test_contains_with_valid_input(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names with the correct value in a different sequence,
        THEN the general name should contain the name.
        """
        name = prepare_name("CN=Hans the Tester")

        # remember 2 is the structure to validate against the first.
        name2 = _prepare_name_with_seq("Not Hans",
                                       "Hans the Tester")

        is_equal = compare_pyasn1_names(name, name2, mode="contains")
        self.assertTrue(is_equal)

    def test_contains_with_invalid_input(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names with the incorrect value in a different sequence,
        THEN the general name should not contain the name.
        """
        name = prepare_name("CN=Hans the Tester")

        # remember 2 is the structure to validate against the first.
        name2 = _prepare_name_with_seq("Not Hans",
                                       "Hans the Tester1")
        is_equal = compare_pyasn1_names(name, name2, mode="contains")
        self.assertFalse(is_equal)

    def test_contains_seq_with_invalid_input(self):
        """
        GIVEN a name with a common name and a general name with a common name
        WHEN comparing the two names with the correct value in a different sequence. However, the sequence is considered,
        THEN the general name should not contain the name.
        """
        name = prepare_name("CN=Hans the Tester")

        # remember 2 is the structure to validate against the first.
        name2 = _prepare_name_with_seq("Not Hans",
                                       "Hans the Tester")
        # checks if the sequence position is the same.
        is_equal = compare_pyasn1_names(name, name2, mode="contains_seq")
        self.assertFalse(is_equal)
