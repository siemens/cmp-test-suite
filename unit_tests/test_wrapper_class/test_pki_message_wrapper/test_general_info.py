# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime, timedelta, timezone

from pyasn1.codec.der import decoder, encoder

from unit_tests.asn1_wrapper_class.pki_message_wrapper import GeneralInfo


class TestGeneralInfo(unittest.TestCase):
    def setUp(self):
        """Setup common test data."""
        self.confirm_wait_time = datetime.now(timezone.utc) + timedelta(seconds=300)
        self.cert_profile = "TestCertProfile"
        self.info_type_implicit = "implicitConfirm"
        self.info_type_wait_time = "confirmWaitTime"
        self.info_type_cert_profile = "certReqTemplate"

        self.general_info = GeneralInfo()

    def test_add_entry(self):
        """
        GIVEN an empty GeneralInfo object
        WHEN adding an entry with an info_type and info_value
        THEN the entry should be added to the GeneralInfo object.
        """
        self.general_info.add(self.info_type_implicit, b'\x05\x00')
        self.assertEqual(len(self.general_info), 1)
        self.assertEqual(self.general_info.data[0].infoType, self.info_type_implicit)

        self.general_info.add(self.info_type_cert_profile, self.cert_profile)
        self.assertEqual(len(self.general_info), 2)
        self.assertEqual(self.general_info.data[1].infoType, self.info_type_cert_profile)
        self.assertEqual(self.general_info.data[1].infoValue, self.cert_profile)

    def test_contains(self):
        """
        GIVEN a GeneralInfo object with data
        WHEN checking if an entry exists by info_type
        THEN the result should be True if the entry exists, otherwise False.
        """
        self.general_info.add(self.info_type_implicit, b'\x05\x00')
        self.assertTrue(self.general_info.contains(self.info_type_implicit))
        self.assertFalse(self.general_info.contains(self.info_type_cert_profile))

    def test_get(self):
        """
        GIVEN a GeneralInfo object with data
        WHEN retrieving an entry by info_type
        THEN the entry should be returned if it exists, otherwise None.
        """
        self.general_info.add(self.info_type_implicit, b'\x05\x00')
        self.general_info.add(self.info_type_cert_profile, self.cert_profile)

        entry = self.general_info.get(self.info_type_cert_profile)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.infoType, self.info_type_cert_profile)
        self.assertEqual(entry.infoValue, self.cert_profile)

        missing_entry = self.general_info.get(self.info_type_wait_time)
        self.assertIsNone(missing_entry)

    def test_to_dict(self):
        """
        GIVEN a GeneralInfo object with data
        WHEN converting the object to a dictionary
        THEN the dictionary should contain the same data as the GeneralInfo object.
        """
        self.general_info.add(self.info_type_cert_profile, self.cert_profile)
        as_dict = self.general_info.to_dict()
        self.assertEqual(len(self.general_info), 1)
        self.assertEqual(as_dict[self.info_type_cert_profile], self.cert_profile)

    def test_from_dict(self):
        """
        GIVEN a dictionary with GeneralInfo data
        WHEN creating a GeneralInfo object from the dictionary
        THEN the GeneralInfo object should contain the same data as the dictionary.
        """
        info_dict = {
            self.info_type_implicit: b'\x05\x00',
            self.info_type_wait_time: self.confirm_wait_time,
            self.info_type_cert_profile: self.cert_profile,
        }
        general_info = GeneralInfo.from_dict(info_dict)
        self.assertEqual(len(general_info), 3)
        self.assertEqual(general_info.data[1].infoType, self.info_type_wait_time)
        self.assertEqual(general_info.data[1].infoValue, self.confirm_wait_time)

    def test_to_asn1_and_der_encode(self):
        """
        GIVEN a GeneralInfo object with data
        WHEN converting the object to ASN.1 and DER encoding it
        THEN the decoded data should be equal to the original data.
        """
        self.general_info.add(self.info_type_implicit, b'\x05\x00')
        self.general_info.add(self.info_type_cert_profile, self.cert_profile)

        asn1_data = self.general_info.to_asn1()
        der_data = encoder.encode(asn1_data)

        decoded_data, remaining_data = decoder.decode(der_data, asn1_data)
        self.assertEqual(remaining_data, b"")
        general_info_from_der = GeneralInfo.from_asn1(decoded_data)

        self.assertEqual(len(self.general_info), len(general_info_from_der))

        for original_entry, decoded_entry in zip(self.general_info.data, general_info_from_der.data):
            self.assertEqual(original_entry.infoType, decoded_entry.infoType)
            self.assertEqual(original_entry.infoValue, decoded_entry.infoValue)
