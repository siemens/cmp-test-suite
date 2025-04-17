# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.tmp_oids import (
    id_compSig04_mldsa44_rsa2048_pkcs15, id_compSig04_mldsa44_rsa2048_pss, composite_sig04_hash_ml_dsa_44_rsa2048_pss,
    composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15)
from resources.certbuildutils import build_csr
from resources.keyutils import generate_key


class TestSigOidForCompositeSig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.common_name = "CN=Hans the Tester"
        cls.comp_key = generate_key("composite-sig", pq_name="ml-dsa-44", trad_name="rsa", length=2048)


    def test_csr_with_composite_sig(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA-44 components.
        WHEN building a CSR with RSA-PSS and not pre-hashing.
        THEN the CSR is built correctly.
        """
        csr = build_csr(common_name=self.common_name,
                        signing_key=self.comp_key,
                        use_rsa_pss=False,
                        use_pre_hash=False,
                        )

        self.assertEqual(str(csr["signatureAlgorithm"]["algorithm"]), str(id_compSig04_mldsa44_rsa2048_pkcs15))
        self.assertEqual(str(csr["certificationRequestInfo"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]),
                         str(id_compSig04_mldsa44_rsa2048_pkcs15))


    def test_csr_with_composite_sig_rsa_pss(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA-44 components.
        WHEN building a CSR with RSA-PSS and not pre-hashing.
        THEN the CSR is built correctly.
        """
        csr = build_csr(common_name=self.common_name,
                        signing_key=self.comp_key,
                        use_rsa_pss=True,
                        use_pre_hash=False
                        )


        self.assertEqual(str(csr["signatureAlgorithm"]["algorithm"]), str(id_compSig04_mldsa44_rsa2048_pss))
        self.assertEqual(str(csr["certificationRequestInfo"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]),
                         str(id_compSig04_mldsa44_rsa2048_pss))

    def test_csr_with_composite_sig_rsa_prehash(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA-44 components.
        WHEN building a CSR with RSA and pre-hashing.
        THEN the CSR is built correctly.
        """
        csr = build_csr(common_name=self.common_name,
                        signing_key=self.comp_key,
                        use_rsa_pss=False,
                        use_pre_hash=True
                        )


        self.assertEqual(str(csr["signatureAlgorithm"]["algorithm"]), str(composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15))
        self.assertEqual(str(csr["certificationRequestInfo"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
                             ), str(composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15))

    def test_csr_with_composite_sig_rsa_pss_prehash(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA-44 components.
        WHEN building a CSR with RSA-PSS and pre-hashing.
        THEN the CSR is built correctly.
        """
        csr = build_csr(common_name=self.common_name,
                        signing_key=self.comp_key,
                        use_rsa_pss=False,
                        use_pre_hash=True,
                        use_pre_hash_pub_key=None)


        self.assertEqual(str(csr["signatureAlgorithm"]["algorithm"]),
                         str(composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15))
        self.assertEqual(str(csr["certificationRequestInfo"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]),
                         str(composite_sig04_hash_ml_dsa_44_rsa2048_pkcs15))



    def test_csr_with_composite_sig_rsa_pss_and_pub_prehash(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA-44 components.
        WHEN building a CSR without RSA-PSS-pre-hashing, but with pre-hashing for
        the public key.
        THEN the CSR is built correctly.
        """
        comp_key = generate_key("composite-sig", pq_name="ml-dsa-44", trad_name="rsa", length=2048)
        csr = build_csr(common_name=self.common_name,
                        signing_key=comp_key,
                        use_rsa_pss=True,
                        use_pre_hash=False,
                        use_pre_hash_pub_key=True
                        )
        self.assertEqual(str(csr["signatureAlgorithm"]["algorithm"]),
                         str(id_compSig04_mldsa44_rsa2048_pss))
        self.assertEqual(str(csr["certificationRequestInfo"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]),
                         str(composite_sig04_hash_ml_dsa_44_rsa2048_pss))
