# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Test OpenSSL certificate chain validation for PQ algorithms."""

import logging
import subprocess
import unittest
from typing import List

from pyasn1_alt_modules import rfc9480

from resources.certutils import verify_cert_chain_openssl, verify_cert_chain_openssl_pqc
from resources.exceptions import SignerNotTrusted
from resources.keyutils import generate_key
from unit_tests.utils_for_test import build_certificate_chain


def _require_openssl_ge_3_5() -> None:
    """Skip tests if the local OpenSSL is older than 3.5.0."""
    try:
        result = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, check=True
        )
        ver_str = result.stdout.strip().split()[1]
        ver_num = ver_str.split("-")[0].split("+")[0]
        version_tuple = tuple(int(part) for part in ver_num.split(".")[:3])
    except Exception as exc:  # pragma: no cover - environment dependent
        logging.warning("Could not determine OpenSSL version: %s", exc)
        raise unittest.SkipTest("OpenSSL >= 3.5.0 required") from exc

    if version_tuple < (3, 5, 0):
        logging.warning(
            "Skipping PQ certificate chain tests: OpenSSL %s < 3.5.0", ver_str
        )
        raise unittest.SkipTest("OpenSSL >= 3.5.0 required")


class TestVerifyPQCertChainOpenSSL(unittest.TestCase):
    """Validate certificate chains of length three for PQ algorithms using OpenSSL."""

    @classmethod
    def setUpClass(cls) -> None:
        """Ensure OpenSSL version is suitable for PQ certificate chain validation.

        - Skip tests if OpenSSL version is less than 3.5.0.
        """
        _require_openssl_ge_3_5()

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

    def _verify_or_skip(self, chain: List[rfc9480.CMPCertificate], name: str) -> None:
        """Verify the chain with OpenSSL or skip if not supported."""
        try:
            verify_cert_chain_openssl_pqc(chain)
        except SignerNotTrusted as exc:
            self.skipTest(f"OpenSSL does not support {name}: {exc}")

    def test_verify_ml_dsa_chain(self) -> None:
        """
        GIVEN a certificate chain with ML-DSA keys.
        WHEN the chain is validated using OpenSSL,
        THEN the validation should succeed or skip if not supported.
        """
        chain = self._build_chain(["ml-dsa-87", "ml-dsa-65", "ml-dsa-44"])
        self._verify_or_skip(chain, "ML-DSA")

    def test_verify_slh_dsa_chain(self) -> None:
        """
        GIVEN a certificate chain with SLH-DSA keys and an ML-DSA key.
        WHEN the chain is validated using OpenSSL,
        THEN the validation should succeed or skip if not supported.
        """
        chain = self._build_chain(["slh-dsa-sha2-256f", "slh-dsa-sha2-256f", "ml-dsa-44"])
        self._verify_or_skip(chain, "SLH-DSA")

    def test_verify_ml_kem_chain(self) -> None:
        """
        GIVEN a certificate chain for an ML-KEM key.
        WHEN the chain is validated using OpenSSL,
        THEN the validation should succeed or skip if not supported.
        """
        chain = self._build_chain(["ml-dsa-44", "ml-dsa-44", "ml-kem-768"])
        self._verify_or_skip(chain, "ML-KEM")

    def test_verify_non_nist_alg(self):
        """
        GIVEN a certificate chain with a non-NIST algorithm.
        WHEN the chain is validated using OpenSSL,
        THEN the validation should raise an `ValueError` exception.
        """
        chain = self._build_chain(["ml-dsa-44", "ml-dsa-44", "falcon-1024"])
        with self.assertRaises(ValueError):
            verify_cert_chain_openssl_pqc(chain)


if __name__ == "__main__":
    unittest.main()