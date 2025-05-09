# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.keyutils import generate_key, prepare_subject_public_key_info
from resources.oidutils import id_ml_dsa_44_with_sha512, PQ_NAME_2_OID


class TestPrepareCompositeSigSPKI(unittest.TestCase):


    def test_ml_dsa_key(self):
        """
        GIVEN a ML-DSA key and a hash algorithm.
        WHEN preparing the `SubjectPublicKeyInfo` structure.
        THEN the correct OID is present in the `SubjectPublicKeyInfo` structure.
        """
        key = generate_key("ml-dsa-44")

        spki = prepare_subject_public_key_info(key=key, hash_alg="sha512")
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(id_ml_dsa_44_with_sha512))


    def test_slh_dsa_key(self):
        """
        GIVEN a SLH-DSA key and a hash algorithm.
        WHEN preparing the `SubjectPublicKeyInfo` structure.
        THEN the correct OID is present in the `SubjectPublicKeyInfo` structure.
        """
        key = generate_key("slh-dsa-sha2-256s")
        spki = prepare_subject_public_key_info(key=key, hash_alg="sha512")
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(
            PQ_NAME_2_OID["slh-dsa-sha2-256s-sha512"]))


