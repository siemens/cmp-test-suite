# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import get_sun_hybrid_alt_pub_key, sun_cert_template_to_cert
from pq_logic.pq_verify_logic import may_extract_alt_key_from_cert
from resources.certbuildutils import build_certificate, prepare_cert_template
from resources.keyutils import generate_key


class TestSunCertTemplateToCert(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = generate_key("composite-sig")
        cls.ca_cert, _ = build_certificate(cls.ca_key, "CN=Test CA")

    def test_cert_template_composite_sig(self):
        """
        GIVEN a composite signature certificate template.
        WHEN the certificate is built.
        THEN the public key is extracted correctly.
        """
        comp_sig = generate_key("composite-sig")
        cert_template = prepare_cert_template(comp_sig, "CN=Hans the Tester")
        cert_form4, cert_form1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key.trad_key,
            alt_private_key=self.ca_key.pq_key,
            pub_key_loc="https://example.com/pubkey/1",
            sig_loc="https://example.com/sig/1",
            serial_number=1,
        )

        public_key = may_extract_alt_key_from_cert(cert_form1)
        self.assertEqual(public_key, comp_sig.public_key().pq_key)

    def test_cert_template_composite_kem(self):
        """
        GIVEN a composite KEM certificate template.
        WHEN the certificate is built.
        THEN the public key is extracted correctly.
        """
        comp_kem = generate_key("composite-kem")
        cert_template = prepare_cert_template(comp_kem, "CN=Hans the Tester")
        cert_form4, cert_form1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key.trad_key,
            alt_private_key=self.ca_key.pq_key,
            pub_key_loc="https://example.com/pubkey/1",
            sig_loc="https://example.com/sig/1",
            serial_number=1,
        )

        public_key = get_sun_hybrid_alt_pub_key(cert_form1["tbsCertificate"]["extensions"])
        self.assertEqual(public_key, comp_kem.public_key().pq_key)
