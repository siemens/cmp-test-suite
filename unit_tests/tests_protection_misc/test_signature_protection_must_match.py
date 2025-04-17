# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.cmputils import prepare_extra_certs
from resources.protectionutils import protect_pkimessage, signature_protection_must_match

from unit_tests import utils_for_test


class TestSignatureProtectionMustMatch(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.pki_response = utils_for_test.build_pkimessage(body_type="error")
        cls.pki_conf = utils_for_test.build_pkimessage(body_type="error")
        cls.pki_polling = utils_for_test.build_pkimessage(body_type="error")

    def test_signature_protection_valid(self):
        """
        GIVEN PKIMessages signed with the same certificate and key
        WHEN signature_protection_must_match is called
        THEN no exception is raised, and the signature protections are valid.
        """
        cert, key = build_certificate()
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert, private_key=key, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert, private_key=key, protection="signature")
        signature_protection_must_match(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def test_different_key_sign_pkiconf(self):
        """
        GIVEN a `pkiConf` message signed with a different key from `pki_response` and
        `pki_polling`
        WHEN signature_protection_must_match is called
        THEN a ValueError is raised, indicating a different signing_key for the PKIMessage.
        """
        cert, key = build_certificate(key_alg="ec")
        cert2, key2 = build_certificate(key_alg="ec")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(
            self.pki_conf, cert=cert2, private_key=key2, protection="signature", exclude_certs=True
        )
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert, private_key=key, protection="signature")
        extra_certs = prepare_extra_certs([cert])
        pki_conf_prot["extraCerts"] = extra_certs
        with self.assertRaises(ValueError):
            signature_protection_must_match(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def test_different_key_sign_pki_polling(self):
        """
        GIVEN a `pki_polling` message signed with a different key from `pki_response`
        and `pki_conf`
        WHEN signature_protection_must_match is called
        THEN a ValueError is raised, indicating a different signing_key for the PKIMessage.
        """
        cert, key = build_certificate(key_alg="ec")
        cert2, key2 = build_certificate(key_alg="ec")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(
            self.pki_conf, cert=cert, private_key=key, protection="signature", exclude_certs=True
        )
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert2, private_key=key2, protection="signature")
        extra_certs = prepare_extra_certs([cert])
        pki_conf_prot["extraCerts"] = extra_certs
        with self.assertRaises(ValueError):
            signature_protection_must_match(pki_response_prot, pki_conf_prot, pki_polling_prot)

    def test_different_cert_pkiconf(self):
        """
        GIVEN a `pki_conf` message signed with a different certificate from `pki_response`
        and `pki_polling`
        WHEN signature_protection_must_match is called
        THEN a ValueError is raised, indicating a certificate mismatch.
        """
        cert, key = build_certificate(key_alg="ec")
        cert2, key2 = build_certificate(key_alg="ec")
        pki_response_prot = protect_pkimessage(self.pki_response, cert=cert, private_key=key, protection="signature")
        pki_conf_prot = protect_pkimessage(self.pki_conf, cert=cert2, private_key=key2, protection="signature")
        pki_polling_prot = protect_pkimessage(self.pki_polling, cert=cert, private_key=key, protection="signature")
        with self.assertRaises(ValueError):
            signature_protection_must_match(pki_response_prot, pki_conf_prot, pki_polling_prot)
