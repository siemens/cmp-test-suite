# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5280, rfc9480
from resources.asn1utils import get_asn1_value_as_string
from resources.general_msg_utils import prepare_distribution_point_name_gen_name


class TestPrepareDistributionPointName(unittest.TestCase):

    def test_prepare_dpn_with_ca_crl_url(self):
        """
        GIVEN a CA CRL URL is provided
        WHEN `prepare_distribution_point_name` is called with the `ca_crl_url` parameter
        THEN it should return a `DistributionPointName` object with the URL set in `uniformResourceIdentifier`
        """
        dist_point_name = prepare_distribution_point_name_gen_name(ca_crl_url="http://crl.testcompany.com/testcompany.crl")
        self.assertIsInstance(dist_point_name, rfc5280.DistributionPointName)
        self.assertEqual(dist_point_name["fullName"][0]["uniformResourceIdentifier"], "http://crl.testcompany.com/testcompany.crl")
        der_data = encoder.encode(dist_point_name)
        decoded_obj, rest = decoder.decode(der_data, rfc9480.DistributionPointName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")
        # is decoded as IA5String, so decoding is not needed, like for the `Name` structure.
        value = get_asn1_value_as_string(decoded_obj, "fullName/0.uniformResourceIdentifier",
                                         decode=False)
        self.assertEqual(value, "http://crl.testcompany.com/testcompany.crl")

    def test_prepare_dpn_with_ca_name(self):
        """
        GIVEN a CA name is provided
        WHEN `prepare_distribution_point_name` is called with the `ca_name` parameter
        THEN it should return a `DistributionPointName` object with the name set in `rfc822Name`
        """
        dist_point_name = prepare_distribution_point_name_gen_name(ca_name="CN=testcompany.crl")
        self.assertIsInstance(dist_point_name, rfc9480.DistributionPointName)
        self.assertEqual(dist_point_name["fullName"][0]["rfc822Name"], "CN=testcompany.crl")
        der_data = encoder.encode(dist_point_name)
        decoded_obj, rest = decoder.decode(der_data, rfc9480.DistributionPointName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")
        value = get_asn1_value_as_string(dist_point_name, "fullName/0.rfc822Name", decode=False)
        self.assertEqual(value, "CN=testcompany.crl")

    def test_prepare_dpn_with_ca_name_blank(self):
        """
        GIVEN a blank CA name is provided
        WHEN `prepare_distribution_point_name` is called with the `ca_name` parameter as an empty string
        THEN it should return a `DistributionPointName` object with an empty string in `rfc822Name`
        """
        dist_point_name = prepare_distribution_point_name_gen_name(ca_name="")
        self.assertIsInstance(dist_point_name,rfc9480.DistributionPointName)
        self.assertEqual(dist_point_name["fullName"][0]["rfc822Name"], "")
        der_data = encoder.encode(dist_point_name)
        decoded_obj, rest = decoder.decode(der_data, rfc5280.DistributionPointName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                                tag.tagFormatConstructed, 0)))
        self.assertEqual(rest, b"")
        value = get_asn1_value_as_string(dist_point_name, "fullName/0.rfc822Name", decode=False)
        self.assertEqual(value, "")
