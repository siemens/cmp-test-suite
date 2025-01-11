# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.protectionutils import check_signature_alg_is_consistent, protect_pkimessage

from unit_tests import utils_for_test


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
        cert, key = build_certificate(key_alg="rsa")
        cert2, key2 = build_certificate(key_alg="ec")
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
        cert, key = build_certificate(key_alg="rsa", hash_alg="sha256")
        cert2, key2 = build_certificate(key_alg="ec", hash_alg="sha256")
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
        cert, key = build_certificate(key_alg="rsa", hash_alg="sha256")
        cert2, key2 = build_certificate(key_alg="rsa", hash_alg="sha256")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(
            self.pki_polling, cert=cert2, private_key=key2, protection="signature", hash_alg="sha512"
        )
        with self.assertRaises(ValueError):
            check_signature_alg_is_consistent(pki_response_prot, pki_conf_prot, pki_polling_prot)


if __name__ == "__main__":
    unittest.main()
