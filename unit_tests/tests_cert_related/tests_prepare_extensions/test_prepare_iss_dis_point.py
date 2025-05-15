# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple

from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_distribution_point_name, prepare_issuing_distribution_point
from resources.asn1utils import get_asn1_value_as_string, get_asn1_value, try_decode_pyasn1, \
    get_all_asn1_named_value_names, is_bit_set
from resources.prepareutils import prepare_name
from unit_tests.utils_for_test import try_encode_pyasn1


def _decode_issuing_distribution_point(issuing_dp: rfc5280.IssuingDistributionPoint) \
        -> Tuple[rfc5280.IssuingDistributionPoint, bytes]:
    """Decode the issuing distribution point.

    :param issuing_dp: The issuing distribution point to decode.
    :return: The decoded issuing distribution point and the remaining data.
    """
    der_data = try_encode_pyasn1(issuing_dp)
    decoded_dp, rest = try_decode_pyasn1(der_data, rfc5280.IssuingDistributionPoint()) # type: ignore
    decoded_dp: rfc5280.IssuingDistributionPoint
    return decoded_dp, rest


class TestPrepareIssDisPoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crl_url = "https://example.com/crl"
        cls.relative_name = "CN=Hans the Tester"

    def test_prepare_iss_dis_point(self):
        """
        GIVEN a CRL URL.
        WHEN the DistributionPoint is prepared with the URL.
        THEN it should return a correct DistributionPoint structure.
        """

        dp_name = prepare_distribution_point_name(
            full_name=self.crl_url,
        )

        issuing_dp = prepare_issuing_distribution_point(
            dis_point_name=dp_name,
            only_contains_user_certs=True,
            only_contains_ca_certs=False,
            only_contains_attribute_certs=False,
            indirect_crl=True,
        )

        parsed_crl_url = get_asn1_value_as_string(
            issuing_dp, "distributionPoint.fullName/0.uniformResourceIdentifier", decode=False,
        )
        self.assertEqual(
            self.crl_url,
            parsed_crl_url,
            "The CRL URL in the DistributionPoint structure does not match the expected value.",
        )

        dec_issuing_dp, rest = _decode_issuing_distribution_point(issuing_dp)
        self.assertEqual(rest, b"")

        self.assertTrue(
            issuing_dp["onlyContainsUserCerts"],
        )
        self.assertFalse(
            issuing_dp["onlyContainsCACerts"],
        )
        self.assertFalse(
            issuing_dp["onlyContainsAttributeCerts"],
        )
        self.assertTrue(
            issuing_dp["indirectCRL"],
        )

    def test_prepare_iss_dis_point_with_relative_name(self):
        """
        GIVEN a relative name.
        WHEN the DistributionPoint is prepared with the relative name.
        THEN it should return a correct DistributionPoint structure.
        """
        name_obj = prepare_name(self.relative_name)
        relative_name = name_obj["rdnSequence"][0]

        dp_name = prepare_distribution_point_name(
            relative_name=relative_name,
        )

        issuing_dp = prepare_issuing_distribution_point(
            dis_point_name=dp_name,
            only_contains_user_certs=False,
            only_contains_ca_certs=True,
            only_contains_attribute_certs=False,
            indirect_crl=False,
        )
        parsed_relative_name = get_asn1_value_as_string(
            issuing_dp, "distributionPoint.nameRelativeToCRLIssuer/0.value", decode=True,
        )
        self.assertEqual(
            self.relative_name,
            "CN=" + parsed_relative_name,
            "The relative name in the DistributionPoint structure does not match the expected value.",
            )

        dec_issuing_dp, rest = _decode_issuing_distribution_point(issuing_dp)
        self.assertEqual(rest, b"")

        parsed_relative_name = get_asn1_value_as_string(
            dec_issuing_dp, "distributionPoint.nameRelativeToCRLIssuer/0.value", decode=True,
        )

        self.assertEqual(
            self.relative_name,
            "CN=" + parsed_relative_name,
            "The relative name in the DistributionPoint structure does not match the expected value.",
        )
        self.assertFalse(
            dec_issuing_dp["onlyContainsUserCerts"],
        )
        self.assertTrue(
            dec_issuing_dp["onlyContainsCACerts"],
        )
        self.assertFalse(
            dec_issuing_dp["onlyContainsAttributeCerts"],
        )
        self.assertFalse(
            dec_issuing_dp["indirectCRL"],
        )
    def test_prepare_iss_dis_point_with_reason_flag(self):
        """
        GIVEN the reason flag argument "all".
        WHEN the DistributionPoint is prepared with the reason flag.
        THEN it should return a correct DistributionPoint structure.
        """
        dp_name = prepare_distribution_point_name(
            full_name=self.crl_url,
        )

        issuing_dp = prepare_issuing_distribution_point(
            dis_point_name=dp_name,
            only_some_reasons="all"
        )

        dec_issuing_dp, rest = _decode_issuing_distribution_point(issuing_dp)
        self.assertEqual(rest, b"")
        self.assertTrue(issuing_dp["onlySomeReasons"].isValue)
        options = get_all_asn1_named_value_names(rfc5280.ReasonFlags, get_keys=True) # type: ignore
        result = is_bit_set(dec_issuing_dp["onlySomeReasons"], ",".join(options), exclusive=False)
        self.assertTrue(
            result,
            "The reason flag in the DistributionPoint structure does not match the expected value.",
        )