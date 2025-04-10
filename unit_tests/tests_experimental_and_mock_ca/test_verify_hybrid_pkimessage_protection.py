# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig.cert_binding_for_multi_auth import prepare_related_cert_extension
from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr, build_chameleon_cert_from_paired_csr
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import sun_csr_to_cert
from resources.protectionutils import protect_hybrid_pkimessage
from pq_logic.py_verify_logic import verify_hybrid_pkimessage_protection
from resources.certbuildutils import generate_certificate
from resources.cmputils import parse_csr, build_p10cr_from_csr
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import build_sun_hybrid_composite_csr


class TestVerifyHybridPkimessageProtection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

    def test_verify_composite_sig_with_public_key(self):
        """
        GIVEN a Composite signature protected PKIMessage
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(p10cr, private_key=self.comp_key)
        verify_hybrid_pkimessage_protection(protected_p10cr, public_key=self.comp_key.public_key())


    def test_verify_hybrid_composite_with_cert(self):
        """
        GIVEN a hybrid PKIMessage
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="composite",
            private_key=self.comp_key,
        )

        cert = generate_certificate(private_key=self.comp_key)
        protected_p10cr["extraCerts"].append(cert)

        verify_hybrid_pkimessage_protection(protected_p10cr)

    def test_verify_hybrid_composite_with_cert_and_public_key(self):
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="composite",
            private_key=self.comp_key.trad_key,
            alt_signing_key=self.comp_key.pq_key,
        )

        cert = generate_certificate(private_key=self.comp_key)
        protected_p10cr["extraCerts"].append(cert)

        verify_hybrid_pkimessage_protection(protected_p10cr)

    def test_verify_composite_with_related_cert(self):
        """
        GIVEN a related certificate and a Composite signed PKIMessage.
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        cert_a = generate_certificate(private_key=self.mldsa_key, hash_alg="sha512")
        extn = prepare_related_cert_extension(cert_a=cert_a,
                                              hash_alg="sha256", critical=False)

        cert_b = generate_certificate(private_key=self.rsa_key,
                                      extensions=[extn],
                                      hash_alg="sha256")

        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="composite",
            private_key=self.mldsa_key,
            alt_signing_key=self.rsa_key,
        )
        protected_p10cr["extraCerts"].append(cert_b)
        protected_p10cr["extraCerts"].append(cert_a)

    def test_verify_composite_with_chameleon_cert(self):
        """
        GIVEN a chameleon certificate and a Composite signed PKIMessage.
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        csrs = build_paired_csr(
            base_private_key=self.comp_key.trad_key,
            delta_private_key=self.comp_key.pq_key,
        )
        self.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        self.ca_cert = generate_certificate(private_key=self.ca_key, hash_alg="sha256")

        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=csrs,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="composite",
            private_key=self.comp_key.trad_key,
            alt_signing_key=self.comp_key.pq_key,
        )
        protected_p10cr["extraCerts"].append(paired_cert)

        verify_hybrid_pkimessage_protection(protected_p10cr)

    def verify_composite_with_sun_hybrid_cert_form1(self):
        """
        GIVEN a hybrid SUN certificate in form 1 and a Composite signed PKIMessage.
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.comp_key,
            common_name="CN=Hans the Tester",
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha384",
            sig_value_location="https://example.com/sig"
        )

        cert4, cert1 = sun_csr_to_cert(
            csr=csr,
            issuer_private_key=self.comp_key.trad_key,
            alt_private_key=self.comp_key.pq_key,
        )
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="composite",
            private_key=self.comp_key.trad_key,
            alt_signing_key=self.comp_key.pq_key,
        )
        protected_p10cr["extraCerts"].append(cert1)

        verify_hybrid_pkimessage_protection(protected_p10cr)

    def test_verify_hybrid_catalyst_with_public(self):
        """
        GIVEN a hybrid PKIMessage
        WHEN verifying the protection,
        THEN it should pass if the protection is valid.
        """
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        p10cr = build_p10cr_from_csr(csr)
        protected_p10cr = protect_hybrid_pkimessage(
            pki_message=p10cr,
            protection="catalyst",
            private_key=self.comp_key.trad_key,
            alt_signing_key=self.comp_key.pq_key,
            include_alt_pub_key=True,
            use_rsa_pss=False,
            hash_alg="sha256"
        )

        protected_p10cr["extraCerts"].append(generate_certificate(private_key=self.comp_key.trad_key))

        verify_hybrid_pkimessage_protection(protected_p10cr)
