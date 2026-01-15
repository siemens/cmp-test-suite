# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import build_hss_name_from_codes
from resources.exceptions import InvalidKeyData


class TestHSSTypeCodeErrorMessages(unittest.TestCase):
    """Test error messages for invalid LMS and LMOTS identifiers."""

    def test_private_use_lms_identifier(self):
        """
        GIVEN an LMS identifier in the private use range (0xFF000000 to 0xFFFFFFFF).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with a specific message about private use.
        """
        # Private use range: 0xFF000000 to 0xFFFFFFFF
        lms_type = (0xFF000001).to_bytes(4, "big")
        lmots_type = (0x00000004).to_bytes(4, "big")  # Valid LMOTS type

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("LMS identifier", error_message)
        self.assertIn("0xff000001", error_message)
        self.assertIn("Private use algorithm", error_message)
        self.assertIn("Either update the code base or fix your id setting", error_message)

    def test_unassigned_lms_identifier(self):
        """
        GIVEN an unassigned LMS identifier (not in the private use range).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with a message about unassigned identifier.
        """
        # Use an unassigned identifier (not in the private use range)
        lms_type = (0x00001234).to_bytes(4, "big")
        lmots_type = (0x00000004).to_bytes(4, "big")  # Valid LMOTS type

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("LMS identifier", error_message)
        self.assertIn("0x00001234", error_message)
        self.assertIn("unassigned or unsupported", error_message)
        self.assertIn("RFC 8554", error_message)

    def test_private_use_lmots_identifier(self):
        """
        GIVEN an LMOTS identifier in the private use range (0xFF000000 to 0xFFFFFFFF).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with a specific message about private use.
        """
        # Private use range: 0xFF000000 to 0xFFFFFFFF
        lms_type = (0x00000006).to_bytes(4, "big")  # Valid LMS type
        lmots_type = (0xFFABCDEF).to_bytes(4, "big")

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("LMOTS identifier", error_message)
        self.assertIn("0xffabcdef", error_message)
        self.assertIn("Private use algorithm", error_message)
        self.assertIn("Either update the code base or fix your id setting", error_message)

    def test_unassigned_lmots_identifier(self):
        """
        GIVEN an unassigned LMOTS identifier (not in the private use range).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with a message about unassigned identifier.
        """
        # Use an unassigned identifier (not in the private use range)
        lms_type = (0x00000006).to_bytes(4, "big")  # Valid LMS type
        lmots_type = (0x00005678).to_bytes(4, "big")

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("LMOTS identifier", error_message)
        self.assertIn("0x00005678", error_message)
        self.assertIn("unassigned or unsupported", error_message)
        self.assertIn("RFC 8554", error_message)

    def test_valid_lms_lmots_combination(self):
        """
        GIVEN valid LMS and LMOTS identifiers.
        WHEN building an HSS name from the codes,
        THEN the function should return the correct algorithm name without raising an exception.
        """
        # Valid combination: LMS_SHA256_M32_H10 (6) and LMOTS_SHA256_N32_W8 (4)
        lms_type = (0x00000006).to_bytes(4, "big")
        lmots_type = (0x00000004).to_bytes(4, "big")

        name = build_hss_name_from_codes(lms_type, lmots_type)
        self.assertEqual(name, "hss_lms_sha256_m32_h10_lmots_sha256_n32_w8")

    def test_private_use_boundary_lower(self):
        """
        GIVEN an LMS identifier at the lower boundary of private use range (0xFF000000).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with private use message.
        """
        lms_type = (0xFF000000).to_bytes(4, "big")
        lmots_type = (0x00000004).to_bytes(4, "big")

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("Private use algorithm", error_message)

    def test_private_use_boundary_upper(self):
        """
        GIVEN an LMOTS identifier at the upper boundary of private use range (0xFFFFFFFF).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with private use message.
        """
        lms_type = (0x00000006).to_bytes(4, "big")
        lmots_type = (0xFFFFFFFF).to_bytes(4, "big")

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("Private use algorithm", error_message)

    def test_just_below_private_use_range(self):
        """
        GIVEN an identifier just below the private use range (0xFEFFFFFF).
        WHEN attempting to build an HSS name from the codes,
        THEN an InvalidKeyData exception should be raised with unassigned message (not private use).
        """
        lms_type = (0xFEFFFFFF).to_bytes(4, "big")
        lmots_type = (0x00000004).to_bytes(4, "big")

        with self.assertRaises(InvalidKeyData) as context:
            build_hss_name_from_codes(lms_type, lmots_type)

        error_message = str(context.exception)
        self.assertIn("unassigned or unsupported", error_message)
        self.assertNotIn("Private use algorithm", error_message)


if __name__ == "__main__":
    unittest.main()

