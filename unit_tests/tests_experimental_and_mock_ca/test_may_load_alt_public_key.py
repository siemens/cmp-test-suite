# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from pq_logic.hybrid_sig.cert_binding_for_multi_auth import prepare_related_cert_extension
from pq_logic.hybrid_sig.certdiscovery import prepare_subject_info_access_syntax_extension
from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr, build_chameleon_cert_from_paired_csr
from pq_logic.pq_verify_logic import may_extract_alt_key_from_cert
from resources.certbuildutils import generate_certificate
from resources.keyutils import load_private_key_from_file


class TestMayLoadAltPublicKey(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ca_cert = generate_certificate(private_key=cls.ca_key, hash_alg="sha256")

    def test_load_key_from_related_cert(self):
        """
        GIVEN a related certificate and the certificate.
        WHEN loading the public key,
        THEN the public key is loaded correctly.
        """
        cert_a = generate_certificate(private_key=self.mldsa_key, hash_alg="sha512")
        extn = prepare_related_cert_extension(cert_a=cert_a,
                                              hash_alg="sha256", critical=False)

        cert_b = generate_certificate(private_key=self.rsa_key,
                                      extensions=[extn],
                                      hash_alg="sha256")

        public_key = may_extract_alt_key_from_cert(cert_b, other_certs=[cert_a])
        self.assertEqual(public_key, self.mldsa_key.public_key())

    def test_load_key_from_chameleon(self):
        """
        GIVEN a chameleon certificate.
        WHEN loading the public key,
        THEN the public key is loaded correctly.
        """
        csrs = build_paired_csr(
            base_private_key=self.comp_key.trad_key,
            delta_private_key=self.comp_key.pq_key,
        )

        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=csrs,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )

        public_key = may_extract_alt_key_from_cert(cert=paired_cert, other_certs=None)
        self.assertEqual(public_key, self.comp_key.pq_key.public_key())

    @patch("resources.utils.load_certificate_from_uri")
    def test_load_key_from_cert_discovery(self, mock_get_cert):
        """
        GIVEN a certificate with a subject info access extension.
        WHEN loading the public key,
        THEN the public key is loaded correctly.
        :param mock_get_cert: Return the certificate.
        """
        discovery_cert = generate_certificate(private_key=self.mldsa_key, hash_alg="sha256")

        mock_get_cert.side_effect = [
            [discovery_cert],
        ]

        sig_alg_id = discovery_cert["tbsCertificate"]["signature"]
        pub_key_alg_id = discovery_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
        extension = prepare_subject_info_access_syntax_extension(
            url="https://example.com/cert-discovery",
            critical=False,
            signature_algorithm=sig_alg_id,
            public_key_algorithm=pub_key_alg_id
        )
        cert = generate_certificate(private_key=self.rsa_key,
                                    extensions=[extension],
                                    hash_alg="sha256")

        public_key = may_extract_alt_key_from_cert(cert, other_certs=None)
        self.assertEqual(public_key, self.mldsa_key.public_key())