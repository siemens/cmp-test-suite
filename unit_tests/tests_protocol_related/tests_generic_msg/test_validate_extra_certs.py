# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.checkutils import validate_extra_certs
from resources.cmputils import patch_extra_certs, prepare_extra_certs
from resources.protectionutils import protect_pkimessage

from unit_tests.prepare_ca_response import build_ca_pki_message
from unit_tests.utils_for_test import build_pkimessage, load_or_generate_cert_chain


class TestValidateExtraCerts(unittest.TestCase):
    def setUp(self):
        cert_chain, private_keys = load_or_generate_cert_chain()
        self.root_cert = cert_chain[0]
        self.intermediate_cert = cert_chain[1]
        self.ee_cert = cert_chain[2]
        self.root_key = private_keys[0]
        self.intermediate_key = private_keys[1]
        self.ee_key = private_keys[2]

        self.chain = [
            self.ee_cert,
            self.intermediate_cert,
            self.root_cert,
        ]

    def test_correctly_protected_pkimessage_without_cert(self):
        """
        GIVEN a PKI message protected by a self-signed certificate without including it in `extraCerts`
        WHEN `validate_extra_certs` is called with `allow_self_signed=True`.
        THEN the validation should pass without raising any errors.
        """
        pki_message = build_pkimessage()
        protected_pki_message = protect_pkimessage(
            pki_message, protection="signature", private_key=self.ee_key, exclude_cert=True
        )
        validate_extra_certs(protected_pki_message, allow_self_signed=True)

    def test_correctly_protected_pkimessage_without_cert_but_not_allowed(self):
        """
        GIVEN a PKI message protected by a self-signed certificate without including it in `extraCerts`
        WHEN `validate_extra_certs` is called with `allow_self_signed=False`.
        THEN a `ValueError` should be raised indicating that the CMP protection certificate is missing
        """
        pki_message = build_pkimessage()
        protected_pki_message = protect_pkimessage(
            pki_message, protection="signature", private_key=self.ee_key, exclude_cert=True
        )
        with self.assertRaises(ValueError):
            validate_extra_certs(protected_pki_message, allow_self_signed=False)

    def test_correctly_checking_pkimessage_protection(self):
        """
        GIVEN a PKI message protected by a certificate chain included in `extraCerts`
        WHEN `validate_extra_certs` is called.
        THEN the validation should pass without raising any errors
        """
        pki_message = build_pkimessage()
        protected_pki_message = protect_pkimessage(
            pki_message, protection="signature", private_key=self.ee_key, exclude_cert=True
        )
        extra_certs = prepare_extra_certs(self.chain)
        protected_pki_message["extraCerts"] = extra_certs
        validate_extra_certs(protected_pki_message)

    def test_check_validation_not_able_to_build_chain(self):
        """
        GIVEN a PKI message with `extraCerts` containing only the end-entity certificate
        WHEN `validate_extra_certs` is called.
        THEN a `ValueError` should be raised indicating that the certificate chain cannot be built
        """
        ca_message = build_ca_pki_message(body_type="ip", cert=self.ee_cert)
        protected_ca_message = protect_pkimessage(
            ca_message, protection="signature", private_key=self.ee_key, cert=self.ee_cert
        )
        protected_ca_message = patch_extra_certs(protected_ca_message, [self.ee_cert])
        with self.assertRaises(ValueError):
            validate_extra_certs(protected_ca_message)


if __name__ == '__main__':
    unittest.main()
