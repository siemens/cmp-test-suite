# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple

from pyasn1.type import char
from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_distribution_point
from resources.asn1utils import try_decode_pyasn1, get_asn1_value_as_string, is_bit_set, \
    get_all_asn1_named_value_names, get_asn1_value
from resources.compareutils import compare_pyasn1_names
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import try_encode_pyasn1


def _decode_distribution_point(distribution_point: rfc5280.DistributionPoint) \
        -> Tuple[rfc5280.DistributionPoint, bytes]:
    """Decode the DER data into a DistributionPoint object.

    :param distribution_point: The DistributionPoint object to decode.
    :return: The decoded DistributionPoint object and any remaining data.
    """
    der_data = try_encode_pyasn1(distribution_point)
    distribution_point, rest = try_decode_pyasn1(der_data, rfc5280.DistributionPoint())  # type: ignore
    distribution_point: rfc5280.DistributionPoint
    return distribution_point, rest


class TestPrepareDistributionPoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crl_url = "https://example.com/crl"
        cls.relative_name = "CN=Hans the Tester"
        cls.crl_issuer = prepare_name("CN=Issuer CRL Name, O=Issuer Org, C=DE")

    def test_prepare_distribution_point(self):
        """
        GIVEN a CRL URL.
        WHEN prepare_distribution_point is called with the URL.
        THEN it should return a correct DistributionPoint object.
        """
        distribution_point = prepare_distribution_point(
            full_name=self.crl_url,
        )
        self.assertEqual("fullName", distribution_point["distributionPoint"].getName())

        dec_dp, rest = _decode_distribution_point(distribution_point)
        self.assertEqual(rest, b"")

        self.assertEqual("fullName", dec_dp["distributionPoint"].getName())
        get_asn1_value_as_string(dec_dp, "distributionPoint")
        self.assertEqual(self.crl_url, dec_dp["distributionPoint"]["fullName"][0]["uniformResourceIdentifier"].prettyPrint())


    def test_prepare_distribution_point_with_all_reason_flags(self):
        """
        GIVEN a CRL URL and all reason flags.
        WHEN prepare_distribution_point is called with the URL and reason flags.
        THEN it should return a correct DistributionPoint object with the reason flags set.
        """
        distribution_point = prepare_distribution_point(
            full_name=self.crl_url,
            reason_flags="all",
        )
        self.assertEqual("fullName", distribution_point["distributionPoint"].getName())
        self.assertEqual(1, len(distribution_point["distributionPoint"]["fullName"]))

        dec_dp, rest = _decode_distribution_point(distribution_point)
        self.assertEqual(rest, b"")

        is_reason_flags = dec_dp["reasons"].isValue
        self.assertTrue(is_reason_flags)
        self.assertEqual("fullName", dec_dp["distributionPoint"].getName())

        options = get_all_asn1_named_value_names(rfc5280.ReasonFlags) # type: ignore
        self.assertEqual(9, len(options))
        result = is_bit_set(dec_dp["reasons"], ",".join(options), exclusive=False)
        self.assertTrue(result)

    def test_prepare_distribution_point_with_relative_name(self):
        """
        GIVEN a relative name.
        WHEN prepare_distribution_point is called with the relative name.
        THEN it should return a correct DistributionPoint object.
        """
        relative_name = rfc5280.RelativeDistinguishedName()

        attr_and_value = rfc5280.AttributeTypeAndValue()
        attr_and_value["type"] = rfc5280.id_at_commonName
        attr_and_value["value"] = char.UTF8String("Hans the Tester")

        relative_name.append(attr_and_value)

        distribution_point = prepare_distribution_point(
            relative_name=relative_name,
            reason_flags="all",
        )
        self.assertEqual("nameRelativeToCRLIssuer", distribution_point["distributionPoint"].getName())

    def test_prepare_distribution_point_with_crl_issuer_as_str(self):
        """
        GIVEN a CRL URL and a CRL issuer as a string.
        WHEN prepare_distribution_point is called with the URL and CRL issuer.
        THEN it should return a correct DistributionPoint object with the CRL issuer set.
        """
        distribution_point = prepare_distribution_point(
            full_name=self.crl_url,
            reason_flags="all",
            crl_issuers=self.relative_name,
        )
        self.assertTrue(distribution_point["cRLIssuer"].isValue)
        self.assertEqual(1, len(distribution_point["cRLIssuer"]))
        self.assertEqual("directoryName", distribution_point["cRLIssuer"][0].getName())

        dec_dp, rest = _decode_distribution_point(distribution_point)
        self.assertEqual(rest, b"")

        self.assertTrue(dec_dp["cRLIssuer"].isValue)
        crl_issuer_name = get_asn1_value(dec_dp, "cRLIssuer/0.directoryName") # type: ignore
        crl_issuer_name: rfc5280.Name

        name_should_be = prepare_name(self.relative_name)
        result = compare_pyasn1_names(
            name_should_be,
            crl_issuer_name,
            mode="without_tag",
        )
        self.assertTrue(result)

    def test_prepare_distribution_point_with_crl_issuer_as_name(self):
        """
        GIVEN a CRL URL and a CRL issuer as a Name object.
        WHEN prepare_distribution_point is called with the URL and CRL issuer.
        THEN it should return a correct DistributionPoint object with the CRL issuer set.
        """
        distribution_point = prepare_distribution_point(
            full_name=self.crl_url,
            reason_flags="all",
            crl_issuers=self.crl_issuer,
        )
        self.assertTrue(distribution_point["cRLIssuer"].isValue)
        self.assertEqual(1, len(distribution_point["cRLIssuer"]))
        self.assertEqual("directoryName", distribution_point["cRLIssuer"][0].getName())

        dec_dp, rest = _decode_distribution_point(distribution_point)
        self.assertEqual(rest, b"")
        self.assertTrue(dec_dp["cRLIssuer"].isValue)
        crl_issuer_name = get_asn1_value(dec_dp, "cRLIssuer/0.directoryName") # type: ignore
        crl_issuer_name: rfc5280.Name
        result = compare_pyasn1_names(
            self.crl_issuer,
            crl_issuer_name,
            mode="without_tag",
        )
        self.assertTrue(result)
