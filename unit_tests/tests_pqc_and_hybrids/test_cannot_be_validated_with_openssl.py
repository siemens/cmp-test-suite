import unittest
from typing import List

from pyasn1_alt_modules import rfc9480

from resources.certutils import pqc_algs_cannot_be_validated_with_openssl
from resources.keyutils import generate_key
from unit_tests.utils_for_test import build_certificate_chain


class TestCannotPQCertChainOpenSSL(unittest.TestCase):

    @staticmethod
    def _build_chain(algs: List[str]) -> List[rfc9480.CMPCertificate]:
        """Generate a certificate chain for the provided algorithms.

        :param algs: A list containing three algorithm names for the root, intermediate
                     and end-entity certificates respectively.
        :return: The certificate chain ordered from end-entity to root.
        """
        keys = [generate_key(alg) for alg in algs]
        certs, _ = build_certificate_chain(length=3, keys=keys)
        return certs[::-1]

    def test_verify_ml_dsa_chain(self) -> None:
        """
        GIVEN a certificate chain with ML-DSA keys.
        WHEN the algorithms are checked for OpenSSL compatibility,
        THEN the chain should be validatable with OpenSSL.
        """
        chain = self._build_chain(["ml-dsa-87", "ml-dsa-65", "ml-dsa-44"])
        self.assertFalse(pqc_algs_cannot_be_validated_with_openssl(chain), "ML-DSA chain should be validated with OpenSSL")

    def test_verify_slh_dsa_chain(self) -> None:
        """
        GIVEN a certificate chain with SLH-DSA keys and an ML-DSA key.
        WHEN the algorithms are checked for OpenSSL compatibility,
        THEN the chain should be validatable with OpenSSL.
        """
        chain = self._build_chain(["slh-dsa-sha2-256f", "slh-dsa-sha2-256f", "ml-dsa-44"])
        self.assertFalse(pqc_algs_cannot_be_validated_with_openssl(chain), "SLH-DSA chain should be validated with OpenSSL")

    def test_verify_ml_kem_chain(self) -> None:
        """
        GIVEN a certificate chain for an ML-KEM key.
        WHEN the algorithms are checked for OpenSSL compatibility,
        THEN the chain should be validatable with OpenSSL.
        """
        chain = self._build_chain(["ml-dsa-44", "ml-dsa-44", "ml-kem-768"])
        self.assertFalse(pqc_algs_cannot_be_validated_with_openssl(chain), "ML-KEM chain should be validated with OpenSSL")

    def test_verify_non_nist_alg(self):
        """
        GIVEN a certificate chain with a non-NIST algorithm.
        WHEN the algorithms are checked for OpenSSL compatibility,
        THEN the chain should not be validatable with OpenSSL.
        """
        chain = self._build_chain(["ml-dsa-44", "ml-dsa-44", "falcon-1024"])
        self.assertTrue(pqc_algs_cannot_be_validated_with_openssl(chain), "Falcon chain should not be validated with OpenSSL")