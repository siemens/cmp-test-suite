# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyasn1_alt_modules import rfc9480
from resources.ca_ra_utils import prepare_new_ca_certificate, prepare_new_root_ca_certificate, prepare_old_with_new_cert
from resources.certbuildutils import build_certificate, prepare_extensions
from resources.certutils import load_public_key_from_cert, verify_cert_signature
from resources.general_msg_utils import process_root_ca_update
from resources.keyutils import load_private_key_from_file
from resources.oidutils import PQ_SIG_OID_2_NAME


class TestRootCAKeyUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.new_key = load_private_key_from_file(
            "data/keys/private-key-ml-dsa-44-seed.pem",
        )

    def _build_old_cert(self) -> rfc9480.CMPCertificate:
        """Prepare an old certificate."""
        extn_old = prepare_extensions(
            key=self.old_key,
            ca_key=self.old_key.public_key(),
            critical=False,
        )
        old_cert, _ = build_certificate(
            self.old_key,
            common_name="CN=Root CA OLD",
            extensions=extn_old,
        )
        return old_cert

    def test_prepare_new_with_old(self):
        """
        GIVEN a new key and an old certificate.
        WHEN preparing a new certificate with the old certificate,
        THEN the new certificate is correctly built.
        """
        old_cert = self._build_old_cert()
        new_cert = prepare_new_ca_certificate(
            old_cert=old_cert,
            new_priv_key=self.new_key,
            hash_alg=None,
            use_rsa_pss=True,
            use_pre_hash=False,
            bad_sig=False,
        )

        sig_alg = new_cert["signatureAlgorithm"]["algorithm"]
        _name = PQ_SIG_OID_2_NAME[sig_alg]
        self.assertEqual(self.new_key.name, _name)
        sig_alg = new_cert["tbsCertificate"]["signature"]["algorithm"]
        _name = PQ_SIG_OID_2_NAME[sig_alg]
        self.assertEqual(self.new_key.name, _name)

        pub_key = load_public_key_from_cert(new_cert)
        self.assertEqual(self.new_key.public_key(), pub_key)

        verify_cert_signature(
            cert=new_cert,
        )

    def test_prepare_old_with_new(self):
        """
        GIVEN an old certificate and a new key and certificate.
        WHEN preparing old certificate with the new key and certificate,
        THEN the new certificate is correctly built.
        """
        old_cert = self._build_old_cert()
        pub_key = load_public_key_from_cert(old_cert)
        self.assertEqual(self.old_key.public_key(), pub_key)
        self.assertIsInstance(pub_key, RSAPublicKey)

        new_cert = prepare_new_ca_certificate(
            old_cert=old_cert,
            new_priv_key=self.new_key,
            hash_alg=None,
            use_rsa_pss=True,
            use_pre_hash=False,
            bad_sig=False,
        )

        old_with_new = prepare_old_with_new_cert(
            old_cert=old_cert,
            new_cert=new_cert,
            hash_alg=None,
            new_priv_key=self.new_key,
            bad_sig=False,
        )

        sig_alg = old_with_new["signatureAlgorithm"]["algorithm"]
        _name = PQ_SIG_OID_2_NAME[sig_alg]
        self.assertEqual(self.new_key.name, _name)
        sig_alg = old_with_new["tbsCertificate"]["signature"]["algorithm"]
        _name = PQ_SIG_OID_2_NAME[sig_alg]
        self.assertEqual(self.new_key.name, _name)

        pub_key = load_public_key_from_cert(old_with_new)
        self.assertEqual(self.old_key.public_key(), pub_key)

        verify_cert_signature(
            cert=old_with_new,
            issuer_pub_key=self.new_key.public_key(),
        )

    def test_prepare_root_ca_key_update(self):
        """
        GIVEN a new and an old key and a new certificate.
        WHEN preparing a root CA key update value structure,
        THEN the structure is correctly built.
        """
        old_cert = self._build_old_cert()

        extn_new = prepare_extensions(
            key=self.new_key,
            ca_key=self.new_key.public_key(),
            critical=False,
        )

        new_cert, _ = build_certificate(self.new_key, common_name="CN=Root CA NEW", extensions=extn_new)
        root_ca = prepare_new_root_ca_certificate(
            old_cert=old_cert,
            old_priv_key=self.old_key,
            new_priv_key=self.new_key,
            new_cert=new_cert,
        )
        self.assertIsInstance(root_ca, rfc9480.RootCaKeyUpdateValue)

        process_root_ca_update(
            root_ca_update=root_ca,
            old_ca_cert=old_cert,
        )

    def test_prepare_root_ca_key_update_value_structure_with_key(self):
        """
        GIVEN a new and an old key,
        WHEN preparing a root CA key update value structure,
        THEN the structure is correctly built.
        """
        old_cert = self._build_old_cert()
        root_ca = prepare_new_root_ca_certificate(
            old_cert=old_cert,
            old_priv_key=self.old_key,
            new_priv_key=self.new_key,
        )
        self.assertIsInstance(root_ca, rfc9480.RootCaKeyUpdateValue)
        process_root_ca_update(
            root_ca_update=root_ca,
            old_ca_cert=old_cert,
        )
