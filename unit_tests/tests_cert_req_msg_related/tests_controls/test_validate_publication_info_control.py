# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.asn1utils import try_decode_pyasn1
from resources.cmputils import prepare_single_publication_info, prepare_pki_publication_information_control, \
    validate_pki_publication_information
from resources.exceptions import BadDataFormat
from unit_tests.utils_for_test import try_encode_pyasn1


class TestValidatePublicationInfoControl(unittest.TestCase):

    def test_validate_publication_info_control(self):
        """
        GIVEN a valid PKIMessage and valid Controls.
        WHEN the controls are parsed,
        THEN should the Controls be valid.
        """
        entry1 =prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        entry2 = prepare_single_publication_info(
            pub_method="ldap",
            pub_location="ldap://example.com",

        )
        attr_info_val = prepare_pki_publication_information_control("pleasePublish",
                                                                    entries=[entry1, entry2])

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")

        controls = rfc9480.Controls()
        controls.append(obj)

        validate_pki_publication_information(controls)

    def test_validate_publication_info_control_with_empty_entries(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN the empty controls are parsed,
        THEN should the Controls be invalid.
        """
        attr_info_val = prepare_pki_publication_information_control("pleasePublish")

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        controls = rfc9480.Controls()
        with self.assertRaises(ValueError) as context:
            validate_pki_publication_information(controls, must_be_present=True)
        contains = str(context.exception)
        self.assertIn("Missing PKIPublicationInfo in controls.", contains)

    def test_validate_publication_info_with_badAction(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN an invalid action is used,
        THEN should the Controls be invalid.
        """
        entry1 = prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        entry2 = prepare_single_publication_info(
            pub_method="ldap",
            pub_location="ldap://example.com",

        )
        attr_info_val = prepare_pki_publication_information_control("badAction", entries=[entry1, entry2])

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        controls = rfc9480.Controls()
        controls.append(obj)
        with self.assertRaises(BadDataFormat) as context:
            validate_pki_publication_information(controls)
        contains = str(context.exception)
        self.assertIn("Invalid action: 2. Must be 0 (dontPublish) or 1 (pleasePublish).", contains)

    def test_validate_publication_info_with_badMethode(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN an invalid pub_method is used,
        THEN should the Controls be invalid.
        """
        entry1 =prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        entry2 = prepare_single_publication_info(
            pub_method="badMethod",
            pub_location="ldap://example.com",

        )
        attr_info_val = prepare_pki_publication_information_control("pleasePublish", entries=[entry1, entry2])

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")

        controls = rfc9480.Controls()
        controls.append(obj)

        with self.assertRaises(BadDataFormat) as context:
            validate_pki_publication_information(controls)
        contains = str(context.exception)
        self.assertIn("Invalid pub_method: 4. Must be 0, 1, 2, or 3.", contains)

    def test_validate_publication_info_control_with_invalid_action_and_option(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN an invalid action is used,
        THEN should the Controls be invalid.
        """
        entry1 =prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        entry2 = prepare_single_publication_info(
            pub_method="web",
            pub_location="https://example.com",

        )
        attr_info_val = prepare_pki_publication_information_control("dontPublish", entries=[entry1, entry2])

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        controls = rfc9480.Controls()
        controls.append(obj)
        with self.assertRaises(BadDataFormat) as context:
            validate_pki_publication_information(controls)
        contains = str(context.exception)
        self.assertIn("If dontPublish is used, the pubInfos field MUST be omitted.", contains)

    def test_validate_publication_info_control_with_dontCare_but_please_Publish(self):
        """
        GIVEN a PKIMessage and an AttributeTypeAndValue object.
        WHEN dontCare is used but the pubInfos field is not empty,
        THEN the Controls should be invalid.
        """
        entry1 = prepare_single_publication_info(
            pub_method="dontCare",
        )

        attr_info_val = prepare_pki_publication_information_control("pleasePublish", entries=[entry1])

        # All univ.Any values have to be encoded to DER and decoded to be validated able.
        der_data = try_encode_pyasn1(attr_info_val)
        obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")

        controls = rfc9480.Controls()
        controls.append(obj)

        with self.assertRaises(BadDataFormat) as context:
            validate_pki_publication_information(controls)
        contains = str(context.exception)
        self.assertIn("If dontCare is used, the pubInfos field MUST be omitted.", contains)
