# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.tmp_oids import id_compSig07_mldsa44_rsa2048_pkcs15, id_compSig07_mldsa44_rsa2048_pss
from resources.certbuildutils import build_certificate
from resources.checkutils import check_protection_alg_conform_to_spki
from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.prepare_alg_ids import prepare_sig_alg_id


class TestCompositeSignatureConformToSigAlg(unittest.TestCase):

    def test_composite_signature_rsa_conform_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PKCS#15
        and a Signature Algorithm Identifier with Composite Signature RSA key with PKCS#15.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=False)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_compSig07_mldsa44_rsa2048_pkcs15)
        sig_alg_id = prepare_sig_alg_id(key, use_rsa_pss=False)
        self.assertEqual(sig_alg_id["algorithm"], id_compSig07_mldsa44_rsa2048_pkcs15)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_rsa_pss_conform_to_sig_alg_pss(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PSS
        and a Signature Algorithm Identifier with Composite Signature RSA key with PSS.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=True)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_compSig07_mldsa44_rsa2048_pss)
        sig_alg_id = prepare_sig_alg_id(key, use_rsa_pss=True)
        self.assertEqual(sig_alg_id["algorithm"], id_compSig07_mldsa44_rsa2048_pss)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_rsa_pss_conform_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PSS
        and a Signature Algorithm Identifier with Composite Signature RSA key with PKCS#15.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=True)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_compSig07_mldsa44_rsa2048_pss)
        sig_alg_id = prepare_sig_alg_id(key, use_rsa_pss=False)
        self.assertEqual(sig_alg_id["algorithm"], id_compSig07_mldsa44_rsa2048_pkcs15)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_rsa_conform_to_sig_alg_rsa_pss(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PKCS#15
        and a Signature Algorithm Identifier with Composite Signature RSA key with PSS.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=False)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_compSig07_mldsa44_rsa2048_pkcs15)
        sig_alg_id = prepare_sig_alg_id(key, use_rsa_pss=True)
        self.assertEqual(sig_alg_id["algorithm"], id_compSig07_mldsa44_rsa2048_pss)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_ecdsa_conform_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature ECDSA key
        and a Signature Algorithm Identifier with Composite Signature ECDSA key.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="ecdsa")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(key)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_ed25519_conform_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature Ed25519 key
        and a Signature Algorithm Identifier with Composite Signature Ed25519 key.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="ed25519")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(key)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_ed448_conform_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature Ed448 key
        and a Signature Algorithm Identifier with Composite Signature Ed448 key.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("composite-sig", trad_name="ed448")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(key)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_different_algorithms(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PKCS#15
        and a Signature Algorithm Identifier with Composite Signature ECDSA key.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=False)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(generate_key("composite-sig", trad_name="ecdsa"))
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_different_ed_algorithms(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature Ed25519 key
        and a Signature Algorithm Identifier with Composite Signature Ed448 key.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("composite-sig", trad_name="ed25519")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(generate_key("composite-sig", trad_name="ed448"))
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_different_trad_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PKCS#15
        and a Signature Algorithm Identifier with RSA-SHA256.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=False)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(generate_key("rsa"), hash_alg="sha256")
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_composite_signature_different_pq_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Composite Signature RSA key with PKCS#15
        and a Signature Algorithm Identifier with MLDSA-44 key.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("composite-sig", trad_name="rsa")
        spki = prepare_subject_public_key_info(key, use_rsa_pss=False)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(generate_key("ml-dsa-44"))
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

if __name__ == "__main__":
    unittest.main()