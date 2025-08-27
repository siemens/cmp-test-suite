# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import validate_cert_template_public_key
from resources.certbuildutils import prepare_cert_template
from resources.exceptions import BadAsn1Data, BadCertTemplate
from resources.keyutils import load_private_key_from_file, prepare_subject_public_key_info


class TestPrepareSPKIInvalidKeySize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

    @staticmethod
    def _prepare_cert_template(key):
        """Prepare a certificate template."""
        spki = prepare_subject_public_key_info(key, add_params_rand_bytes=True)
        cert_template = prepare_cert_template(key, subject="CN=Hans the Tester", spki=spki)
        return cert_template

    def test_prepare_spki_invalid_parameters_rsa(self):
        """
        GIVEN a `SubjectPublicKeyInfo` with random bytes for the `parameters` field.
        WHEN preparing the SPKI and validating the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.rsa_key)
        with self.assertRaises(BadCertTemplate):
            validate_cert_template_public_key(cert_template)

    def test_prepare_spki_invalid_parameters_ml_dsa(self):
        """
        GIVEN a `SubjectPublicKeyInfo` with random bytes for the `parameters` field.
        WHEN preparing the SPKI and validating the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.mldsa_key)
        with self.assertRaises(BadCertTemplate):
            validate_cert_template_public_key(cert_template)

    def test_prepare_spki_invalid_parameters_composite(self):
        """
        GIVEN a `SubjectPublicKeyInfo` with random bytes for the `parameters` field.
        WHEN preparing the SPKI and validating the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.comp_key)
        with self.assertRaises(BadCertTemplate):
            validate_cert_template_public_key(cert_template)
