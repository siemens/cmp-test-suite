# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280
from resources.certutils import parse_certificate
from resources.general_msg_utils import prepare_dpn_from_cert
from resources.utils import load_and_decode_pem_file


class TestPrepareDpnFromCert(unittest.TestCase):

    def test_prepare_dpn_from_idp_ext(self):
        """
        GIVEN a certificate containing an Issuing Distribution Point (IDP) extension
        WHEN `prepare_dpn_from_cert` is called with this certificate
        THEN it should return a valid `DistributionPointName` object extracted from the IDP extension
        """
        der_data = load_and_decode_pem_file("data/unittest/cert_issuing_dp.pem")
        cert_issuing_dp = parse_certificate(der_data)
        dist_point_name = prepare_dpn_from_cert(cert_issuing_dp)
        self.assertIsInstance(dist_point_name, rfc5280.DistributionPointName)
        self.assertTrue(dist_point_name.isValue)

    def test_prepare_dpn_from_crl_dp_ext(self):
        """
        GIVEN a certificate containing a CRL Distribution Points (CRL DP) extension
        WHEN `prepare_dpn_from_cert` is called with this certificate
        THEN it should return a valid `DistributionPointName` object extracted from the CRL DP extension
        """
        der_data = load_and_decode_pem_file("data/unittest/cert_crl_dp.pem")
        cert_crl_dp = parse_certificate(der_data)
        dist_point_name = prepare_dpn_from_cert(cert_crl_dp)
        self.assertIsInstance(dist_point_name, rfc5280.DistributionPointName)
        self.assertTrue(dist_point_name.isValue)
        self.assertEqual(
            dist_point_name["fullName"][0]["uniformResourceIdentifier"],
            "http://crl.testcompany.com/testcompany.crl"
        )

    def test_prepare_dpn_without_relevant_extensions(self):
        """
        GIVEN a certificate that does not contain IDP or CRL DP extensions
        WHEN `prepare_dpn_from_cert` is called with this certificate
        THEN it should return `None`
        """
        der_data = load_and_decode_pem_file("data/unittest/bare_certificate.pem")
        base_cert = parse_certificate(der_data)
        dist_point_name = prepare_dpn_from_cert(base_cert)
        self.assertTrue(dist_point_name is None, dist_point_name)


if __name__ == '__main__':
    unittest.main()
