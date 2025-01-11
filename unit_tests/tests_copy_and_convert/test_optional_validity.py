# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from pyasn1_alt_modules import rfc4211, rfc5280
from resources.convertutils import pyasn1_time_obj_to_py_datetime, validity_to_optional_validity


def create_validity_object_with_generalized_time():
    """Prepare a validity object with as `generalTime` choice."""
    validity = rfc5280.Validity()
    not_before = rfc5280.Time()
    not_after = rfc5280.Time()
    now = datetime.datetime.now()
    future = now + datetime.timedelta(days=365)
    not_before["generalTime"] = not_before["generalTime"].fromDateTime(now)
    not_after["generalTime"] = not_after["generalTime"].fromDateTime(future)
    validity["notBefore"] = not_before
    validity["notAfter"] = not_after
    return validity


def create_validity_object_with_utc_time():
    """Prepare a validity object with `utcTime` as choice."""
    validity = rfc5280.Validity()
    not_before = rfc5280.Time()
    not_after = rfc5280.Time()
    now = datetime.datetime.now()
    future = now + datetime.timedelta(days=365)
    not_before["utcTime"] = not_before["utcTime"].fromDateTime(now)
    not_after["utcTime"] = not_after["utcTime"].fromDateTime(future)
    validity["notBefore"] = not_before
    validity["notAfter"] = not_after
    return validity


class TestValidityToOptionalValidity(unittest.TestCase):
    def test_valid_conversion_generalized_time(self):
        """
        GIVEN a validity object with as `GeneralizedTime` choice.
        WHEN converting it to an `OptionalValidity` object.
        THEN the conversion should be successful.
        """
        validity_obj = create_validity_object_with_generalized_time()
        result = validity_to_optional_validity(validity_obj)
        self.assertIsInstance(result, rfc4211.OptionalValidity)
        self.assertTrue(result["notBefore"].isValue)
        self.assertTrue(result["notAfter"].isValue)
        before = pyasn1_time_obj_to_py_datetime(result["notBefore"])
        after = pyasn1_time_obj_to_py_datetime(result["notAfter"])
        self.assertEqual(before, pyasn1_time_obj_to_py_datetime(validity_obj["notBefore"]))
        self.assertEqual(after, pyasn1_time_obj_to_py_datetime(validity_obj["notAfter"]))

    def test_valid_conversion_utc_time(self):
        """
        GIVEN a validity object with `UTCTime` as choice.
        WHEN converting it to an `OptionalValidity` object.
        THEN the conversion should be successful.
        """
        validity_obj = create_validity_object_with_utc_time()
        result = validity_to_optional_validity(validity_obj)
        self.assertIsInstance(result, rfc4211.OptionalValidity)
        self.assertTrue(result["notBefore"].isValue)
        self.assertTrue(result["notAfter"].isValue)
        before = pyasn1_time_obj_to_py_datetime(result["notBefore"])
        after = pyasn1_time_obj_to_py_datetime(result["notAfter"])
        self.assertEqual(before, pyasn1_time_obj_to_py_datetime(validity_obj["notBefore"]))
        self.assertEqual(after, pyasn1_time_obj_to_py_datetime(validity_obj["notAfter"]))


if __name__ == "__main__":
    unittest.main()
