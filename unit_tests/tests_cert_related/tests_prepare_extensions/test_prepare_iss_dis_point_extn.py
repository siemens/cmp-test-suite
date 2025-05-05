import unittest
from typing import Tuple

from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_issuing_distribution_point, prepare_issuing_distribution_point_extension
from resources.asn1utils import try_decode_pyasn1
from unit_tests.utils_for_test import try_encode_pyasn1


def _decode_issuing_distribution_point(der_data: bytes) \
        -> Tuple[rfc5280.IssuingDistributionPoint, bytes]:
    """Decode the issuing distribution point."""
    decoded_iss_dp, rest = try_decode_pyasn1(der_data, rfc5280.IssuingDistributionPoint()) # type: ignore
    decoded_iss_dp: rfc5280.IssuingDistributionPoint
    return decoded_iss_dp, rest

class TestPrepareIssDisPointExtn(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crl_url = "https://example.com/crl"


    def test_prepare_iss_dis_point_extn_simple(self):
        """
        GIVEN a IssuingDistributionPoint structure
        WHEN the IssuingDistributionPoint extension is prepared,
        THEN is the extension correctly prepared.
        """
        iss_dp = prepare_issuing_distribution_point(
            full_name=self.crl_url,
            only_some_reasons="all",
        )

        iss_dp_extn = prepare_issuing_distribution_point_extension(
            iss_dis_point=iss_dp,
            critical=True,
        )
        self.assertIsInstance(iss_dp_extn, rfc5280.Extension)
        self.assertEqual(iss_dp_extn["extnID"], rfc5280.id_ce_issuingDistributionPoint)
        self.assertEqual(iss_dp_extn["critical"], True)

        der_data = iss_dp_extn["extnValue"].asOctets()
        decoded_iss_dp, rest = _decode_issuing_distribution_point(der_data)
        self.assertEqual(rest, b"")

    def test_prepare_iss_dis_point_extn_simple2(self):
        """
        GIVEN a IssuingDistributionPoint structure
        WHEN the IssuingDistributionPoint extension is prepared,
        THEN is the extension correctly prepared.
        """
        iss_dp = prepare_issuing_distribution_point(
            full_name=self.crl_url,
            only_some_reasons="all",
        )

        iss_dp_extn = prepare_issuing_distribution_point_extension(
            iss_dis_point=iss_dp,
            add_rand_val=True,
            critical=False,
        )
        self.assertIsInstance(iss_dp_extn, rfc5280.Extension)
        self.assertEqual(iss_dp_extn["extnID"], rfc5280.id_ce_issuingDistributionPoint)
        self.assertEqual(iss_dp_extn["critical"], False)

        der_data = iss_dp_extn["extnValue"].asOctets()
        decoded_iss_dp, rest = _decode_issuing_distribution_point(der_data)
        self.assertNotEqual(rest, b"")



