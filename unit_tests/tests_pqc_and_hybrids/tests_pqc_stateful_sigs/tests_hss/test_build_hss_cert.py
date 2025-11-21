# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.certutils import verify_cert_signature
from resources.keyutils import generate_key, load_public_key_from_spki


class TestBuildHSSCert(unittest.TestCase):
    def test_build_hss_cert(self):
        """
        GIVEN a valid HSS key.
        WHEN building a certificate for the HSS key,
        THEN the certificate should be built successfully and the signature should be correctly verified.
        """
        key = generate_key("hss")
        cert, _ = build_certificate(key, "CN=Test HSS Certificate")
        verify_cert_signature(cert, key.public_key())

    def test_build_hss_cert_and_load_key(self):
        """
        GIVEN a valid HSS key.
        WHEN building a certificate for the HSS key,
        THEN the certificate should be built successfully and the public key should be correctly loaded.
        """
        key = generate_key("hss")
        cert, _ = build_certificate(key, "CN=Test HSS Certificate")
        public_key = key.public_key()
        loaded_pub_key = load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
        self.assertEqual(public_key, loaded_pub_key, "Public key should not be None after building certificate")
        verify_cert_signature(cert, loaded_pub_key)


if __name__ == "__main__":
    unittest.main()
