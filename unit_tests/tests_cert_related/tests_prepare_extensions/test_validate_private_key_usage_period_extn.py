# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime, timedelta, timezone

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480

from resources.certbuildutils import (
    prepare_private_key_usage_period,
    prepare_validity,
    validate_private_key_usage_period,
)
from resources.exceptions import BadAsn1Data, BadCertTemplate


class TestValidatePrivateKeyUsagePeriodExtn(unittest.TestCase):
    def test_validate_private_key_usage_period_extn(self):
        """
        GIVEN a certificate with a `PrivateKeyUsagePeriod` extension.
        WHEN validating the extension,
        THEN the validation should succeed.
        """
        extn = prepare_private_key_usage_period(
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=30),
            critical=False,
        )

        extns = rfc9480.Extensions()
        extns.append(extn)

        validate_private_key_usage_period(extns)

    def test_validate_private_key_usage_period_extn2(self):
        """
        GIVEN a certificate with a `PrivateKeyUsagePeriod` extension.
        WHEN validating the extension,
        THEN the validation should succeed.
        """
        validity = prepare_validity(
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) + timedelta(days=31),
        )

        extn = prepare_private_key_usage_period(
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=30),
            critical=False,
        )

        extns = rfc9480.Extensions()
        extns.append(extn)

        validate_private_key_usage_period(extns, validity=validity, must_be_present=True)

    def test_validate_private_key_usage_period_extn3(self):
        """
        GIVEN a certificate with a `PrivateKeyUsagePeriod` extension.
        WHEN validating the extension,
        THEN the validation should succeed.
        """
        validity = prepare_validity(
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=31),
        )

        extn = prepare_private_key_usage_period(
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=30),
            critical=False,
        )

        extns = rfc9480.Extensions()
        extns.append(extn)

        validate_private_key_usage_period(extns, validity=validity, must_be_present=True)

    def test_missing_extension_raises_if_required(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension that is required.
        WHEN validating the extension,
        THEN an exception should be raised.
        """
        extns = rfc9480.Extensions()
        with self.assertRaises(ValueError) as cm:
            validate_private_key_usage_period(extns, must_be_present=True)
        self.assertIn("missing", str(cm.exception))

    def test_invalid_asn1_data_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with invalid ASN.1 data.
        WHEN validating the extension,
        THEN an exception should be raised.
        """
        extn = prepare_private_key_usage_period(
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            critical=False,
        )

        extn["extnValue"] = univ.OctetString(b"invalid")
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadAsn1Data) as cm:
            validate_private_key_usage_period(extns)

        self.assertIn("PrivateKeyUsagePeriod", str(cm.exception))

    def test_empty_extension_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with no `notBefore` or `notAfter` dates
        WHEN validating the extension,
        THEN an exception should be raised.
        """
        extn = prepare_private_key_usage_period()

        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadAsn1Data) as cm:
            validate_private_key_usage_period(extns)
        self.assertIn("empty", str(cm.exception.message))

    def test_not_before_after_not_after_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notBefore` and `notAfter` dates
        WHEN the `notBefore` date is after the `notAfter` date,
        THEN an exception should be raised.
        """
        nb = datetime.now(timezone.utc) + timedelta(days=1)
        na = datetime.now(timezone.utc)

        extn = prepare_private_key_usage_period(nb, na, critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadAsn1Data) as cm:
            validate_private_key_usage_period(extns)
        self.assertIn("notBefore date is after", str(cm.exception))

    def test_not_before_equal_not_after_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notBefore` and `notAfter` dates
        WHEN the `notBefore` date is equal to the `notAfter` date,
        THEN an exception should be raised.
        """
        now = datetime.now(timezone.utc)

        extn = prepare_private_key_usage_period(now, now, critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadAsn1Data) as cm:
            validate_private_key_usage_period(extns)
        self.assertIn("equal", str(cm.exception))

    def test_not_before_before_validity_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notBefore` date.
        WHEN the `notBefore` date is before the validity period,
        THEN an exception should be raised.
        """
        now = datetime.now(timezone.utc)
        validity = prepare_validity(
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=30),
        )

        extn = prepare_private_key_usage_period(now, now + timedelta(days=10), critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_usage_period(extns, validity=validity)
        self.assertIn("before the validity", str(cm.exception))

    def test_not_before_before_validity_raises2(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notBefore` date.
        WHEN the `notBefore` date is before the validity period,
        THEN an exception should be raised.
        """
        now = datetime.now(timezone.utc)
        validity = prepare_validity(
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=30),
        )

        extn = prepare_private_key_usage_period(not_before=now, not_after=None, critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_usage_period(extns, validity=validity)
        self.assertIn("before the validity", str(cm.exception))

    def test_not_after_after_validity_raises(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notAfter` date.
        WHEN the `notAfter` date is after the validity period,
        THEN an exception should be raised.
        """
        now = datetime.now(timezone.utc)

        validity = prepare_validity(
            not_before=now,
            not_after=now + timedelta(days=5),
        )
        extn = prepare_private_key_usage_period(now, now + timedelta(days=10), critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_usage_period(extns, validity=validity)
        self.assertIn("after the validity", str(cm.exception))

    def test_not_after_after_validity_raises2(self):
        """
        GIVEN a `PrivateKeyUsagePeriod` extension with `notAfter` date.
        WHEN the `notAfter` date is after the validity period,
        THEN an exception should be raised.
        """
        now = datetime.now(timezone.utc)

        validity = prepare_validity(
            not_before=now,
            not_after=now + timedelta(days=5),
        )
        extn = prepare_private_key_usage_period(not_before=None, not_after=now + timedelta(days=10), critical=False)
        extns = rfc9480.Extensions()
        extns.append(extn)

        with self.assertRaises(BadCertTemplate) as cm:
            validate_private_key_usage_period(extns, validity=validity)
        self.assertIn("after the validity", str(cm.exception))
