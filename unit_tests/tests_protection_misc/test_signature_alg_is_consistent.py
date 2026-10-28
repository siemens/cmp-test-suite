# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ
from resources.certbuildutils import build_certificate
from resources.protectionutils import check_signature_alg_is_consistent, protect_pkimessage

from unit_tests import utils_for_test
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestCheckSignatureAlgIsConsistent(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.pki_response = utils_for_test.build_pkimessage(body_type="error")
        cls.pki_conf = utils_for_test.build_pkimessage(body_type="error")
        cls.pki_polling = utils_for_test.build_pkimessage(body_type="error")

    def test_matching_signature_algorithms(self):
        """
        GIVEN PKIMessages signed with the same certificate and key.
        WHEN signature_protection_must_match is called.
        THEN no exception is raised.
        """
        cert, key = build_certificate()
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert, private_key=key, protection="signature")

        try:
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot, pki_polling_prot)
        except ValueError:
            self.fail("check_signature_alg_is_consistent raised ValueError unexpectedly!")

    def test_matching_signature_algorithms_without_polling(self):
        """
        GIVEN a `pki_conf` message signed with a different signature algorithm from `pki_response`
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, indicating the inconsistency of signature algorithms between the PKIMessages.
        """
        cert, key = build_certificate()
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")

        try:
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot)
        except ValueError:
            self.fail("check_signature_alg_is_consistent raised ValueError unexpectedly!")

    def test_matching_signature_algorithms_without_pki_conf(self):
        """
        GIVEN a `pki_conf` message signed with a different signature algorithm from `pki_response` and `pki_polling`.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, indicating the inconsistency of signature algorithms between the PKIMessages.
        """
        cert, key = build_certificate()
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")

        try:
            check_signature_alg_is_consistent(pki_response_prot, pki_polling=pki_polling_prot)
        except ValueError:
            self.fail("check_signature_alg_is_consistent raised ValueError unexpectedly!")

    def test_different_signature_algorithms_in_conf(self):
        """
        GIVEN a `pki_conf` message signed with a different signature algorithm from `pki_response` and `pki_polling`.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, indicating the inconsistency of signature algorithms between the PKIMessages.
        """
        cert, key = build_certificate(private_key="rsa")
        cert2, key2 = build_certificate(private_key="ecc")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert2, private_key=key2, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert, private_key=key, protection="signature")
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def test_different_signature_algorithms_in_polling(self):
        """
        GIVEN a `pki_polling` message signed with a different signature algorithm from
        `pki_response` and `pki_conf`.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, indicating the inconsistency of signature algorithms between the PKIMessages.
        """
        cert, key = build_certificate(private_key="rsa", hash_alg="sha256")
        cert2, key2 = build_certificate(private_key="ecc", hash_alg="sha256")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert2, private_key=key2, protection="signature")
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def test_different_signature_hash_algorithms_in_pki_conf(self):
        """
        GIVEN a `pki_conf` message signed with a different signature hash algorithm from
        `pki_response` and `pki_polling`.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, indicating the inconsistency of signature algorithms between the PKIMessages.
        """
        cert, key = build_certificate(private_key="rsa", hash_alg="sha256")
        cert2, key2 = build_certificate(private_key="rsa", hash_alg="sha256")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(
            self.pki_polling, cert=cert2, private_key=key2, protection="signature", hash_alg="sha512"
        )
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def _protect_with_params(self, private_key: str, params, protection: str = "signature"):
        """Protect `pki_response` and `pki_conf` and set the `protectionAlg` parameters of both to `params`."""
        cert, key = build_certificate(private_key=private_key)
        messages = []
        for pki_message in [self.pki_response, self.pki_conf]:
            protected = protect_pkimessage(pki_message, cert=cert, private_key=key, protection=protection)
            if params is not None:
                protected["header"]["protectionAlg"]["parameters"] = params
            messages.append(de_and_encode_pkimessage(protected))
        return messages

    def test_rsa_with_null_parameters(self):
        """
        GIVEN RSA PKCS #1 v1.5 signed `pki_response` and `pki_conf` messages with NULL `protectionAlg` parameters.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN no exception is raised, because RFC 4055 Section 5 requires NULL parameters.
        """
        pki_response_prot, pki_conf_prot = self._protect_with_params("rsa", univ.Null(""))
        check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot)

    def test_rsa_with_other_parameters(self):
        """
        GIVEN RSA PKCS #1 v1.5 signed messages whose `protectionAlg` parameters are not NULL.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised.
        """
        pki_response_prot, pki_conf_prot = self._protect_with_params("rsa", univ.Integer(1))
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot)

    def test_ecdsa_with_null_parameters(self):
        """
        GIVEN ECDSA signed messages with NULL `protectionAlg` parameters.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN a `ValueError` is raised, because ECDSA parameters must be absent.
        """
        pki_response_prot, pki_conf_prot = self._protect_with_params("ecc", univ.Null(""))
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot)

    def test_rsassa_pss_with_parameters(self):
        """
        GIVEN RSASSA-PSS signed messages, whose `protectionAlg` carries `RSASSA-PSS-params`.
        WHEN `check_signature_alg_is_consistent` is called.
        THEN no exception is raised, because RFC 4056 Section 2 requires the parameters.
        """
        pki_response_prot, pki_conf_prot = self._protect_with_params("rsa", None, protection="rsassa-pss")
        self.assertTrue(pki_response_prot["header"]["protectionAlg"]["parameters"].isValue)
        check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot)


if __name__ == "__main__":
    unittest.main()
