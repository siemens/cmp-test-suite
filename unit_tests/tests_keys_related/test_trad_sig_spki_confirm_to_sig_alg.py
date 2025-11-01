# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280

from resources.asn1utils import encode_to_der, try_decode_pyasn1
from resources.certbuildutils import build_certificate
from resources.checkutils import check_protection_alg_conform_to_spki
from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import RSASSA_PSS_OID_2_NAME
from resources.prepare_alg_ids import prepare_sig_alg_id


class TestTradSigSPKIConfirmToSigAlg(unittest.TestCase):

    def test_rsa_spki_confirm_to_sig_alg(self):
        """
        GIVEN a SubjectPublicKeyInfo with RSA key
        and a Signature Algorithm Identifier with RSA key.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("rsa")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual("rsa", may_return_oid_to_name(cert_oid))
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha256")
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_rsa_pss_confirm_to_sig_alg_rsa_pss(self):
        """
        GIVEN a SubjectPublicKeyInfo with RSA key with PSS
        and a Signature Algorithm Identifier with RSA key with PSS.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("rsa")
        spki = prepare_subject_public_key_info(key, hash_alg="sha256", use_rsa_pss=True)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual("rsassa_pss-sha256", RSASSA_PSS_OID_2_NAME[cert_oid])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha256", use_rsa_pss=True)
        der_data = encode_to_der(sig_alg_id)
        dec_sig_alg_id, _ = try_decode_pyasn1(der_data, rfc5280.AlgorithmIdentifier())
        self.assertTrue(check_protection_alg_conform_to_spki(dec_sig_alg_id, cert))

    def test_rsa_pss_confirm_to_sig_alg_rsa(self):
        """
        GIVEN a SubjectPublicKeyInfo with RSA key with PSS
        and a Signature Algorithm Identifier with RSA key with PKCS#15.
        WHEN both are compared,
        THEN should return False indicating they do not conform to each other.
        """
        key = generate_key("rsa")
        spki = prepare_subject_public_key_info(key, hash_alg="sha256", use_rsa_pss=True)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual("rsassa_pss-sha256", RSASSA_PSS_OID_2_NAME[cert_oid])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="sha256", use_rsa_pss=False)
        # TODO change if this is allowed.
        self.assertFalse(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_rsa_confirm_to_sig_alg_rsa_pss_shake(self):
        """
        GIVEN a SubjectPublicKeyInfo with RSA key
        and a Signature Algorithm Identifier with RSA key with PSS.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("rsa")
        spki = prepare_subject_public_key_info(key)
        cert, _ = build_certificate(key, spki=spki)
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="shake256", use_rsa_pss=True)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))

    def test_rsa_pss_confirm_to_sig_alg_rsa_pss_sha(self):
        """
        GIVEN a SubjectPublicKeyInfo with RSA key with PSS
        and a Signature Algorithm Identifier with RSA key with PSS.
        WHEN both are compared,
        THEN should return True indicating they conform to each other.
        """
        key = generate_key("rsa")
        spki = prepare_subject_public_key_info(key, hash_alg="shake256", use_rsa_pss=True)
        cert, _ = build_certificate(key, spki=spki)
        cert_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
        self.assertEqual("rsassa_pss-shake256", RSASSA_PSS_OID_2_NAME[cert_oid])
        sig_alg_id = prepare_sig_alg_id(key, hash_alg="shake256", use_rsa_pss=True)
        self.assertTrue(check_protection_alg_conform_to_spki(sig_alg_id, cert))


if __name__ == "__main__":
    unittest.main()
