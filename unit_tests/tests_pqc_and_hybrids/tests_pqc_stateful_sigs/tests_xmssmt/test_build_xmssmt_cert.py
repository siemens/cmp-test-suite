# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.stateful_sig_keys import XMSSMTPrivateKey
from resources.certbuildutils import build_certificate
from resources.certutils import verify_cert_signature
from resources.keyutils import generate_key, load_public_key_from_spki


class TestBuildXMSSMTCert(unittest.TestCase):
    def test_build_xmssmt_cert(self):
        """
        GIVEN a valid XMSSMT key.
        WHEN building a certificate for the XMSSMT key,
        THEN the certificate should be built successfully and the signature should be correctly verified.
        """
        key = generate_key("xmssmt-sha2_20/2_256")
        self.assertIsInstance(key, XMSSMTPrivateKey, "Key should be an instance of XMSSMTPrivateKey")
        cert, _ = build_certificate(key, "CN=Test XMSSMT Certificate")
        verify_cert_signature(cert, key.public_key())

    def test_build_xmssmt_cert_and_load_key(self):
        """
        GIVEN a valid XMSSMT key.
        WHEN building a certificate for the XMSSMT key,
        THEN the certificate should be built successfully and the public key should be correctly loaded.
        """
        key = generate_key("xmssmt-sha2_20/2_256")
        self.assertIsInstance(key, XMSSMTPrivateKey, "Key should be an instance of XMSSMTPrivateKey")
        cert, _ = build_certificate(key, "CN=Test XMSSMT Certificate")
        public_key = key.public_key()
        loaded_pub_key = load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
        self.assertEqual(public_key, loaded_pub_key, "Public key should not be None after building certificate")
        verify_cert_signature(cert, loaded_pub_key)


if __name__ == "__main__":
    unittest.main()
