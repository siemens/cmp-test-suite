# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480
from resources.cmputils import build_cmp_error_message
from resources.protectionutils import mac_protection_algorithms_must_match, protect_pkimessage

from unit_tests import utils_for_test
from unit_tests.utils_for_test import build_pkimessage


class TestMACProtectionAlgorithmsMustMatch(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.pki_message = build_cmp_error_message()
        cls.pki_message2 = build_cmp_error_message()
        cls.password = "test_password"
        cls.protection = "password_based_mac"

    def test_same_protection_must_be_different_salt(self):
        """
        GIVEN three PKIMessages protected with the same protection method but different salt values.
        WHEN `protection_algorithms_must_match` is called with lwcmp=True and strict=True,
        THEN no error should be risen, because valid protection algorithm is used and only lwcmp one.
        """
        request = protect_pkimessage(self.pki_message, password=self.password, protection=self.protection)
        response = protect_pkimessage(self.pki_message2, password=self.password, protection=self.protection)
        pkiconf = protect_pkimessage(build_pkimessage(), password=self.password, protection=self.protection)

        response = utils_for_test.de_and_encode_pkimessage(response)
        pkiconf = utils_for_test.de_and_encode_pkimessage(pkiconf)
        mac_protection_algorithms_must_match(
            request=request, response=response, pkiconf=pkiconf, same_salt=False, strict=True, enforce_lwcmp=True
        )

    def test_same_protection_method_but_different_salt(self):
        """
        GIVEN two PKIMessages protected with the same protection method but different salt values.
        WHEN `protection_algorithms_must_match` is called with same_salt=True and strict=True,
        THEN a `ValueError` is raised, indicating a mismatch in the `parameters` values used.
        """
        request = protect_pkimessage(self.pki_message, password=self.password, protection=self.protection)
        response = protect_pkimessage(self.pki_message2, password=self.password, protection=self.protection)

        response = utils_for_test.de_and_encode_pkimessage(response)
        with self.assertRaises(ValueError):
            mac_protection_algorithms_must_match(request, response, same_salt=True, strict=True)

    def test_not_both_are_lwcmp_protection_methods(self):
        """
        GIVEN two PKIMessages protected with the `hmac` and `pbmac1` protection method.
        WHEN `protection_algorithms_must_match` is called with same_salt=True and strict=True,
        THEN a `ValueError` is raised, indicating that hmac is not allowed inside the Lwcmp version.
        """
        # note: for negative testing reasons only the server is checked.
        # so basically both could use hmac.
        request = protect_pkimessage(self.pki_message, password=self.password, protection="pbmac1")
        response = protect_pkimessage(self.pki_message2, password=self.password, protection="hmac")
        response = utils_for_test.de_and_encode_pkimessage(response)
        with self.assertRaises(ValueError):
            mac_protection_algorithms_must_match(request, response, same_salt=True, strict=True)

    def test_same_protection_method_and_parameters(self):
        """
        GIVEN two `PKIMessages` protected with the same protection method and identical parameters, including the salt.
        WHEN `protection_algorithms_must_match` is called with same_salt=True.
        THEN no exception is raised, confirming that the protection methods and parameters are consistent.
        """
        request = protect_pkimessage(
            self.pki_message,
            password=self.password,
            protection=self.protection,
            salt="0x1234567890",
        )
        response = protect_pkimessage(
            self.pki_message2, password=self.password, protection=self.protection, salt="0x1234567890"
        )
        response = utils_for_test.de_and_encode_pkimessage(response)
        mac_protection_algorithms_must_match(request, response, same_salt=True)

    def test_different_protection_method(self):
        """
        GIVEN two PKIMessages protected with different MAC-protection methods.
        WHEN `protection_algorithms_must_match` is called.
        THEN a `ValueError` is raised, highlighting the inconsistency in the protection methods.
        """
        request = protect_pkimessage(self.pki_message, password=self.password, protection="password_based_mac")
        response = protect_pkimessage(self.pki_message2, password=self.password, protection="pbmac1")
        response = utils_for_test.de_and_encode_pkimessage(response)
        with self.assertRaises(ValueError):
            mac_protection_algorithms_must_match(request, response)

    def _protect_with_absent_owf_params(self, pki_message):
        """Protect a message with password-based MAC and remove the NULL `owf` parameters of its `PBMParameter`."""
        protected = protect_pkimessage(
            pki_message, password=self.password, protection=self.protection, salt="0x1234567890"
        )
        protected = utils_for_test.de_and_encode_pkimessage(protected)
        prot_alg = protected["header"]["protectionAlg"]
        pbm_params, _ = decoder.decode(prot_alg["parameters"].asOctets(), asn1Spec=rfc9480.PBMParameter())
        self.assertEqual(encoder.encode(pbm_params["owf"]["parameters"]), encoder.encode(univ.Null("")))
        owf = rfc9480.AlgorithmIdentifier()
        owf["algorithm"] = pbm_params["owf"]["algorithm"]
        pbm_params["owf"] = owf
        prot_alg["parameters"] = univ.Any(encoder.encode(pbm_params))
        return utils_for_test.de_and_encode_pkimessage(protected)

    def test_absent_owf_parameters_allowed(self):
        """
        GIVEN a request with NULL `owf` parameters and a response with absent `owf` parameters.
        WHEN `protection_algorithms_must_match` is called with allow_null=True,
        THEN no exception is raised, because NULL and absent parameters are equivalent (RFC 4055 Section 2.1).
        """
        request = protect_pkimessage(
            self.pki_message, password=self.password, protection=self.protection, salt="0x1234567890"
        )
        response = self._protect_with_absent_owf_params(self.pki_message2)
        mac_protection_algorithms_must_match(request, response, same_salt=True, allow_null=True)

    def test_absent_owf_parameters_not_allowed(self):
        """
        GIVEN a request with NULL `owf` parameters and a response with absent `owf` parameters.
        WHEN `protection_algorithms_must_match` is called with allow_null=False,
        THEN a `ValueError` is raised.
        """
        request = protect_pkimessage(
            self.pki_message, password=self.password, protection=self.protection, salt="0x1234567890"
        )
        response = self._protect_with_absent_owf_params(self.pki_message2)
        with self.assertRaises(ValueError):
            mac_protection_algorithms_must_match(request, response, same_salt=True, allow_null=False)


if __name__ == "__main__":
    unittest.main()
