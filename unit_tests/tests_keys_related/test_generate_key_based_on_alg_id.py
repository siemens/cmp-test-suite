# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.keyutils import generate_key_based_on_alg_id
from resources.oidutils import PQ_NAME_2_OID


def _prepare_alg_id_by_name(name: str) -> rfc9480.AlgorithmIdentifier:
    """Prepare a `rfc9480.AlgorithmIdentifier` based on the given name.

    :param name: The name of the algorithm.
    :return: The `rfc9480.AlgorithmIdentifier` object.
    """
    alg_id = rfc9480.AlgorithmIdentifier()
    oid = PQ_NAME_2_OID[name]
    alg_id["algorithm"] = oid
    return alg_id

class TestGenerateKeyBasedOnAlgId(unittest.TestCase):


    def test_generate_ml_dsa_key(self):
        """
        GIVEN an AlgorithmIdentifier for ML-DSA-87.
        WHEN the key is generated based on the AlgorithmIdentifier.
        THEN the key is successfully generated.
        """
        alg_id = _prepare_alg_id_by_name("ml-dsa-87")
        key = generate_key_based_on_alg_id(alg_id=alg_id)
        self.assertEqual(key.name, "ml-dsa-87")

    def test_generate_ml_dsa_87_with_sha512(self):
        """
        GIVEN an AlgorithmIdentifier for ML-DSA-87 with SHA-512.
        WHEN the key is generated based on the AlgorithmIdentifier.
        THEN the key is successfully generated.
        """
        alg_id = _prepare_alg_id_by_name("ml-dsa-87-sha512")
        key = generate_key_based_on_alg_id(alg_id=alg_id)
        self.assertEqual(key.name, "ml-dsa-87")

    def test_generate_slh_dsa_shake_256s(self):
        """
        GIVEN an AlgorithmIdentifier for SLH-DSA-SHAKE-256s.
        WHEN the key is generated based on the AlgorithmIdentifier.
        THEN the key is successfully generated.
        """
        alg_id = _prepare_alg_id_by_name("slh-dsa-shake-256s")
        key = generate_key_based_on_alg_id(alg_id=alg_id)
        self.assertEqual(key.name, "slh-dsa-shake-256s")

    def test_generate_slh_dsa_shake_256s_with_sha512(self):
        """
        GIVEN an AlgorithmIdentifier for SLH-DSA-SHAKE-256s-SHAKE256.
        WHEN the key is generated based on the AlgorithmIdentifier.
        THEN the key is successfully generated.
        """
        alg_id = _prepare_alg_id_by_name("slh-dsa-shake-256s-shake256")
        key = generate_key_based_on_alg_id(alg_id=alg_id)
        self.assertEqual(key.name, "slh-dsa-shake-256s")