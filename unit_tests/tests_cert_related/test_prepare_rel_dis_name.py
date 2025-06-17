# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280

from resources.asn1utils import encode_to_der, try_decode_pyasn1
from resources.exceptions import BadAsn1Data
from resources.prepareutils import prepare_relative_distinguished_name, validate_relative_name_for_correct_data_types
from resources.oidutils import OID_CM_NAME_MAP


class TestPrepareRelDisName(unittest.TestCase):
    def test_prepare_all_known_types(self):
        """
        GIVEN a list of all known types.
        WHEN prepare_relative_dis_name is called
        THEN it should return a valid DER encoded value.
        """
        names = []
        for x in OID_CM_NAME_MAP:
            names.append(f"{x}=test")

        cm = ",".join(names)
        value = prepare_relative_distinguished_name(cm)
        der_data = encode_to_der(value)
        dec_value, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())
        self.assertEqual(b"", rest)

    def test_correctly_build_all_known_types(self):
        """
        GIVEN a list of all known types.
        WHEN prepare_relative_dis_name is called
        THEN it should return a valid DER encoded value.
        """
        names = []
        for x in OID_CM_NAME_MAP:
            if x != "C":
                names.append(f"{x}=test")
            else:
                names.append("C=DE")

        cm = ",".join(names)
        value = prepare_relative_distinguished_name(cm)
        der_data = encode_to_der(value)
        dec_value, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())  # type: ignore
        self.assertEqual(b"", rest)
        dec_value: rfc5280.RelativeDistinguishedName
        validate_relative_name_for_correct_data_types(dec_value)

    def test_prepare_invalid_name(self):
        """
        GIVEN an invalid name.
        WHEN prepare_relative_dis_name is called
        THEN it should raise a ValueError.
        """
        for value in OID_CM_NAME_MAP:
            data = f"{value}=test"
            with self.subTest(value=value):
                attr = prepare_relative_distinguished_name(data, invalid_type=True)
                der_data = encode_to_der(attr)
                with self.assertRaises(BadAsn1Data):
                    dec_data, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())  # type: ignore
                    dec_data: rfc5280.RelativeDistinguishedName
                    validate_relative_name_for_correct_data_types(
                        dec_data,
                    )

    def test_prepare_bad_min_size(self):
        """
        GIVEN a name with a bad minimum size.
        WHEN prepare_relative_dis_name is called
        THEN it should raise a BadAsn1Data.
        """
        for value in OID_CM_NAME_MAP:
            if value in ["DNQ", "DC", "organizationIdentifier"]:
                continue

            data = f"{value}=test"
            with self.subTest(value=value):
                attr = prepare_relative_distinguished_name(data, bad_min_size=True)
                der_data = encode_to_der(attr)
                with self.assertRaises(BadAsn1Data):
                    dec_data, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())
                    dec_data: rfc5280.RelativeDistinguishedName
                    validate_relative_name_for_correct_data_types(
                        dec_data,
                    )

    def test_prepare_bad_max_size(self):
        """
        GIVEN a name with a bad maximum size.
        WHEN prepare_relative_dis_name is called
        THEN it should raise a BadAsn1Data.
        """
        for value in OID_CM_NAME_MAP:
            if value in ["DNQ", "DC", "organizationIdentifier"]:
                continue

            data = f"{value}=test"
            with self.subTest(value=value):
                attr = prepare_relative_distinguished_name(data, bad_max_size=True)
                der_data = encode_to_der(attr)
                with self.assertRaises(BadAsn1Data):
                    dec_data, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())
                    dec_data: rfc5280.RelativeDistinguishedName
                    validate_relative_name_for_correct_data_types(
                        dec_data,
                    )

    def test_add_trailing_data(self):
        """
        GIVEN a name with trailing data.
        WHEN prepare_relative_dis_name is called
        THEN it should raise a BadAsn1Data.
        """
        for value in OID_CM_NAME_MAP:
            data = f"{value}=test"
            with self.subTest(value=value):
                attr = prepare_relative_distinguished_name(data, add_trailing_data=True)
                der_data = encode_to_der(attr)
                with self.assertRaises(BadAsn1Data):
                    dec_data, rest = try_decode_pyasn1(der_data, rfc5280.RelativeDistinguishedName())
                    dec_data: rfc5280.RelativeDistinguishedName
                    validate_relative_name_for_correct_data_types(
                        dec_data,
                    )
