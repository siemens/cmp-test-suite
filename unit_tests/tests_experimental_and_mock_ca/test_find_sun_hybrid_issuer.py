# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import sun_cert_template_to_cert
from pq_logic.py_verify_logic import find_sun_hybrid_issuer_cert
from resources.certbuildutils import build_certificate, prepare_cert_template
from resources.keyutils import generate_key


class TestFindSunHybridIssuer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = generate_key("composite-sig")
        cls.ca_cert, _ = build_certificate(cls.ca_key, "CN=Test CA")

    def test_find_sun_hybrid_issuer(self):
        """
        GIVEN a composite signature certificate.
        WHEN the issuer is extracted.
        THEN the issuer is correct.
        """
        comp_key = generate_key("composite-sig", trad_name="ed25519")
        cert_template = prepare_cert_template(comp_key, "CN=Hans the Tester")
        ca_cert, _ = build_certificate(comp_key, "CN=Hans the Tester", use_rsa_pss=False)
        cert4, cert1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=ca_cert,
            ca_key=comp_key.trad_key,
            alt_private_key=comp_key.pq_key,
            pub_key_loc="https://example.com/pubkey/1",
            sig_loc="https://example.com/sig/1",
        )

        _ = find_sun_hybrid_issuer_cert(cert1, [cert1])
        _ = find_sun_hybrid_issuer_cert(cert4, [cert1])
