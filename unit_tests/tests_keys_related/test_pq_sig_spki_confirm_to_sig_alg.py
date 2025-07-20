import unittest

from pkilint.nist.asn1.csor import id_ml_dsa_44, id_ml_dsa_87

from pq_logic.tmp_oids import id_falcon_512, id_falcon_1024
from resources.certbuildutils import build_certificate
from resources.checkutils import check_protection_alg_conform_to_spki
from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.oidutils import id_ml_dsa_44_with_sha512, SLH_DSA_NAME_2_OID, PQ_NAME_2_OID
from resources.prepare_alg_ids import prepare_sig_alg_id


class TestPQSigSpkiConfirmToSigAlg(unittest.TestCase):
    def test_mldsa_spki_confirm_to_sig_alg_with_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with MLDSA signature algorithm with hash
        and a signature AlgorithmIdentifier with the same algorithm and hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("ml-dsa-44")
        spki = prepare_subject_public_key_info(key, hash_alg="sha512")
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44_with_sha512)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha512")
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_mldsa_spki_confirm_to_sig_alg_without_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with MLDSA signature algorithm without hash
        and a signature AlgorithmIdentifier with the same algorithm and hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("ml-dsa-44")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg=None)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_mldsa_spki_confirm_to_sig_alg_with_spki_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with MLDSA signature algorithm with hash
        and a signature AlgorithmIdentifier with the same algorithm but without hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("ml-dsa-44")
        spki = prepare_subject_public_key_info(key, hash_alg="sha512")
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44_with_sha512)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg=None)
        self.assertEqual(sig_alg_id["algorithm"], id_ml_dsa_44)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_mldsa_spki_confirm_to_sig_alg_with_sig_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with MLDSA signature algorithm without hash
        and a signature AlgorithmIdentifier with the same algorithm but with hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("ml-dsa-44")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha512")
        self.assertEqual(sig_alg_id["algorithm"], id_ml_dsa_44_with_sha512)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_mldsa_spki_confirm_to_sig_alg_with_different_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with MLDSA signature algorithm without hash
        and a signature AlgorithmIdentifier with a different algorithm.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("ml-dsa-44")
        diff_key = generate_key("ml-dsa-87")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44)
        sig_alg_id = prepare_sig_alg_id(diff_key, hash_alg=None)
        self.assertEqual(sig_alg_id["algorithm"], id_ml_dsa_87)
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_falcon_spki_confirm_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Falcon signature algorithm
        and a signature AlgorithmIdentifier with the same algorithm.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("falcon-512")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_falcon_512)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg=None)
        self.assertEqual(sig_alg_id["algorithm"], id_falcon_512)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_falcon_spki_confirm_to_sig_alg_with_different_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with Falcon signature algorithm
        and a signature AlgorithmIdentifier with a different algorithm.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("falcon-512")
        diff_key = generate_key("falcon-1024")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)

        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_falcon_512)
        sig_alg_id = prepare_sig_alg_id(diff_key, hash_alg=None)
        self.assertEqual(sig_alg_id["algorithm"], id_falcon_1024)
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_slh_dsa_spki_confirm_to_sig_alg_with_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with SLH-DSA signature algorithm with hash
        and a signature AlgorithmIdentifier with the same algorithm and hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("slh-dsa-sha2-256s")
        spki = prepare_subject_public_key_info(key, hash_alg="sha512")
        cert, _ = build_certificate(key)
        cert["tbsCertificate"]["subjectPublicKeyInfo"] = spki
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, PQ_NAME_2_OID["slh-dsa-sha2-256s-sha512"])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha512")
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_slh_dsa_spki_confirm_to_sig_alg_without_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with SLH-DSA signature algorithm without hash
        and a signature AlgorithmIdentifier with the same algorithm and no hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("slh-dsa-sha2-256s")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key)
        cert["tbsCertificate"]["subjectPublicKeyInfo"] = spki
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, SLH_DSA_NAME_2_OID["slh-dsa-sha2-256s"])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg=None)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_slh_dsa_spki_confirm_to_sig_alg_with_spki_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with SLH-DSA signature algorithm with hash
        and a signature AlgorithmIdentifier with the same algorithm but without hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("slh-dsa-sha2-256s")
        spki = prepare_subject_public_key_info(key, hash_alg="sha512")
        cert, _ = build_certificate(key)
        cert["tbsCertificate"]["subjectPublicKeyInfo"] = spki
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, PQ_NAME_2_OID["slh-dsa-sha2-256s-sha512"])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg=None)
        self.assertEqual(sig_alg_id["algorithm"], SLH_DSA_NAME_2_OID["slh-dsa-sha2-256s"])
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_slh_dsa_spki_confirm_to_sig_alg_with_sig_hash(self):
        """
        GIVEN a SubjectPublicKeyInfo with SLH-DSA signature algorithm without hash
        and a signature AlgorithmIdentifier with the same algorithm but with hash.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("slh-dsa-sha2-256s")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key)
        cert["tbsCertificate"]["subjectPublicKeyInfo"] = spki
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, SLH_DSA_NAME_2_OID["slh-dsa-sha2-256s"])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha512")
        self.assertEqual(sig_alg_id["algorithm"], PQ_NAME_2_OID["slh-dsa-sha2-256s-sha512"])
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_pq_alg_with_trad_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with a PQ algorithm
        and a signature AlgorithmIdentifier with the RSA-SHA-256 traditional algorithm.
        WHEN both are compared,
        THEN should return False indicating they conform to each other.
        """
        key = generate_key("ml-dsa-44")
        spki = prepare_subject_public_key_info(key, hash_alg=None)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual(cert_oid, id_ml_dsa_44)
        diff_key = generate_key("rsa")
        sig_alg_id = prepare_sig_alg_id(diff_key, hash_alg="sha256")
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

if __name__ == "__main__":
    unittest.main()