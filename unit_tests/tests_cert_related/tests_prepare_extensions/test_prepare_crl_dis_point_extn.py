import unittest

from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_distribution_point, prepare_crl_distribution_point_extension
from resources.asn1utils import try_decode_pyasn1
from resources.prepareutils import prepare_name


class TestPrepareCRLDistributionPointExtn(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crl_url = "https://example.com/crl"
        cls.relative_name = "CN=Hans the Tester"
        cls.crl_issuer = "CN=CRL Issuer"

    def test_crl_distribution_point_extn_simple(self):
        """
        GIVEN a CRL URL and a relative name.
        WHEN the CRL Distribution Point extension is prepared.
        THEN it should return a correct CRL Distribution Point structure.
        """
        crl_distribution_point_extn = prepare_crl_distribution_point_extension(
            full_name=self.crl_url,
            crl_issuers=self.crl_issuer,
            critical=True,
        )
        self.assertEqual(crl_distribution_point_extn["extnID"], rfc5280.id_ce_cRLDistributionPoints)
        self.assertTrue(crl_distribution_point_extn["critical"])
        self.assertTrue(crl_distribution_point_extn["extnValue"].isValue)

    def test_crl_distribution_point_extn_simple2(self):
        """
        GIVEN a CRL URL and a relative name.
        WHEN the CRL Distribution Point extension is prepared.
        THEN it should return a correct CRL Distribution Point structure.
        """
        crl_distribution_point_extn = prepare_crl_distribution_point_extension(
            full_name=self.crl_url,
            crl_issuers=self.crl_issuer,
            critical=False,
            add_rand_val=True,
        )
        self.assertEqual(crl_distribution_point_extn["extnID"], rfc5280.id_ce_cRLDistributionPoints)
        self.assertFalse(crl_distribution_point_extn["critical"])
        self.assertTrue(crl_distribution_point_extn["extnValue"].isValue)

        der_data = crl_distribution_point_extn["extnValue"].asOctets()
        crl_dp, rest = try_decode_pyasn1(der_data, rfc5280.CRLDistributionPoints())  # type: ignore
        self.assertIsInstance(crl_dp, rfc5280.CRLDistributionPoints)
        self.assertNotEqual(rest, b"")

    def test_crl_distribution_point_extn_with_relative_name(self):
        """
        GIVEN a relative name.
        WHEN the CRL Distribution Point extension is prepared with the relative name.
        THEN it should return a correct CRL Distribution Point structure.
        """
        dp1 = prepare_distribution_point(
            full_name=self.crl_url,
        )
        self.assertTrue(dp1.isValue)
        name_obj = prepare_name(self.relative_name)
        relative_name = name_obj["rdnSequence"][0]
        dp2 = prepare_distribution_point(
            relative_name=relative_name,
        )
        self.assertTrue(dp2.isValue)
        self.assertEqual(0, len(rfc5280.CRLDistributionPoints()))

        crl_distribution_point_extn = prepare_crl_distribution_point_extension(
            distribution_points=[dp1, dp2],
            critical=True,
        )

        self.assertEqual(crl_distribution_point_extn["extnID"], rfc5280.id_ce_cRLDistributionPoints)
        self.assertTrue(crl_distribution_point_extn["critical"])
        self.assertTrue(crl_distribution_point_extn["extnValue"].isValue)

        der_data = crl_distribution_point_extn["extnValue"].asOctets()
        crl_dp, rest = try_decode_pyasn1(der_data, rfc5280.CRLDistributionPoints())
        self.assertIsInstance(crl_dp, rfc5280.CRLDistributionPoints)
        self.assertEqual(rest, b"")
        self.assertEqual(len(crl_dp), 2)
