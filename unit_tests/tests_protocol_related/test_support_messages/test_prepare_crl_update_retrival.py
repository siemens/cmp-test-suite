# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.general_msg_utils import prepare_crl_update_retrieval


class TestPrepareDistributionPointName(unittest.TestCase):

    def test_prepare_crl_update_retrival_with_url(self):
        """
        GIVEN a CA CRL URL is provided
        WHEN `prepare_crl_update_retrival` is called with the `ca_crl_url` parameter
        THEN it should return an `InfoTypeAndValue` object correctly constructed with the CRL source
        """
        info_val = prepare_crl_update_retrieval(
            ca_crl_url="http://crl.testcompany.com/testcompany.crl"
        )
        self.assertIsInstance(info_val, rfc9480.InfoTypeAndValue)
        der_data = encoder.encode(info_val)
        dec_info_val, rest = decoder.decode(
            der_data, asn1Spec=rfc9480.InfoTypeAndValue()
        )
        self.assertEqual(rest, b"")

    def test_prepare_crl_update_retrival_neg(self):
        """
        GIVEN a CA CRL URL is provided and negative testing is enabled
        WHEN `prepare_crl_update_retrival` is called with `negative=True`
        THEN it should return an `InfoTypeAndValue` object with the `thisUpdate` field adjusted for negative testing
        """
        info_val = prepare_crl_update_retrieval(
            ca_crl_url="http://crl.testcompany.com/testcompany.crl", bad_this_update=True
        )
        self.assertIsInstance(info_val, rfc9480.InfoTypeAndValue)
        der_data = encoder.encode(info_val)
        dec_info_val, rest = decoder.decode(
            der_data, asn1Spec=rfc9480.InfoTypeAndValue()
        )
        self.assertEqual(rest, b"")
        crl_status_list_val, rest = decoder.decode(
            dec_info_val["infoValue"], asn1Spec=rfc9480.CRLStatusListValue()
        )
        self.assertEqual(rest, b"")
        self.assertEqual(len(crl_status_list_val), 1)
        self.assertTrue(crl_status_list_val[0]["thisUpdate"].isValue)


if __name__ == "__main__":
    unittest.main()
