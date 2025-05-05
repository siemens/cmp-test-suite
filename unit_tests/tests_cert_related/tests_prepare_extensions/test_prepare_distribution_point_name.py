import unittest

from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import prepare_distribution_point_name
from resources.asn1utils import try_decode_pyasn1, get_asn1_value_as_string
from resources.prepareutils import prepare_name
from resources.utils import get_openssl_name_notation
from unit_tests.utils_for_test import try_encode_pyasn1


def _decode_distribution_point(distribution_point: rfc5280.DistributionPointName) \
        -> tuple[rfc5280.DistributionPointName, bytes]:
    """Decode the DER data into a DistributionPoint object.

    :param distribution_point: The DistributionPoint object to decode.
    :return: The decoded DistributionPoint object and any remaining data.
    """
    der_data = try_encode_pyasn1(distribution_point)
    distribution_point, rest = try_decode_pyasn1(der_data, rfc5280.DistributionPointName())  # type: ignore
    distribution_point: rfc5280.DistributionPointName
    return distribution_point, rest

class TestPrepareDistributionPoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.crl_url = "https://example.com/crl"
        cls.relative_name = "CN=Hans the Tester"

    def test_prepare_distribution_point(self):
        """
        GIVEN a CRL URL.
        WHEN the DistributionPoint is prepared with the URL.
        THEN it should return a correct DistributionPoint structure.
        """
        distribution_point_name = prepare_distribution_point_name(
            full_name=self.crl_url,
        )
        self.assertEqual("fullName", distribution_point_name.getName())

        dec_dp, rest = _decode_distribution_point(distribution_point_name)
        self.assertEqual(rest, b"")
        self.assertEqual("fullName", dec_dp.getName())
        self.assertTrue(dec_dp["fullName"][0]["uniformResourceIdentifier"].isValue)
        dec_crl_url = get_asn1_value_as_string(dec_dp, "fullName/0.uniformResourceIdentifier", decode=False)
        self.assertEqual(self.crl_url, dec_crl_url)


    def test_prepare_distribution_point_with_relative_name(self):
        """
        GIVEN a relative name.
        WHEN the DistributionPoint is prepared with the relative name.
        THEN it should return a correct DistributionPoint structure.
        """
        name_obj = prepare_name(self.relative_name)
        relative_name = name_obj["rdnSequence"][0]

        self.assertIsInstance(relative_name, rfc5280.RelativeDistinguishedName)

        distribution_point_name = prepare_distribution_point_name(
            relative_name=relative_name,
        )
        self.assertEqual("nameRelativeToCRLIssuer", distribution_point_name.getName())

        dec_dp, rest = _decode_distribution_point(distribution_point_name)
        self.assertEqual(rest, b"")

        self.assertEqual("nameRelativeToCRLIssuer", dec_dp.getName())
        self.assertTrue(dec_dp["nameRelativeToCRLIssuer"][0].isValue)
        dec_relative_name = get_asn1_value_as_string(dec_dp, "nameRelativeToCRLIssuer/0.value", decode=True)

        new_name = rfc5280.Name()
        new_rel_name = rfc5280.RelativeDistinguishedName()
        new_rel_name.extend(dec_dp["nameRelativeToCRLIssuer"])
        new_name["rdnSequence"].append(new_rel_name)
        dec_name = get_openssl_name_notation(new_name)
        self.assertEqual(self.relative_name, dec_name)
        self.assertEqual(self.relative_name, "CN=" + dec_relative_name)
