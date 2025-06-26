# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.keyutils import generate_key
from resources.certutils import verify_csr_signature, verify_cert_signature
from resources.certbuildutils import generate_certificate, build_csr


class TestCompositeSignature(unittest.TestCase):

    def test_cert_comp_sig_pure_rsa_with_pk(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        cert = generate_certificate(key) # type: ignore
        verify_cert_signature(cert, key.public_key())


    def test_cert_comp_sig_pure_rsa(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        cert = generate_certificate(key) # type: ignore
        verify_cert_signature(cert)


    def test_sign_csr(self):
        """
        GIVEN a composite signature key.
        WHEN signing a CSR,
        THEN the signature is valid.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        csr = build_csr(key)
        verify_csr_signature(csr)
