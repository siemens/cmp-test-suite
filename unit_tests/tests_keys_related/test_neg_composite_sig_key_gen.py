# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey
from resources.cmputils import build_ir_from_key
from resources.exceptions import InvalidKeyCombination
from resources.keyutils import generate_key, prepare_subject_public_key_info


class TestNegCompositeSigKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bad_rsa_key = generate_key("bad_rsa_key")
        cls.ml_dsa_44_key = generate_key("ml-dsa-44")

    def test_neg_composite_sig_key_gen_rsa(self):
        """
        Generate a composite signature key with RSA traditional key and ML-DSA-44 post-quantum key.
        WHEN the key is generated,
        THEN the key is generated successfully.
        """
        comp_key = generate_key("composite-sig", trad_key=self.bad_rsa_key, pq_key=None)
        self.assertEqual(comp_key.trad_key.public_key(), self.bad_rsa_key.public_key())
        self.assertEqual(comp_key.pq_key.name, "ml-dsa-44")

    def test_neg_composite_sig_key_sign(self):
        """
        GIVEN A composite signature key with an invalid key combination.
        WHEN the key sign's the data, it should be successful, but when verified,
        THEN should an InvalidKeyCombination exception be raised.
        """
        pq_key = generate_key("ml-dsa-44")
        comp = CompositeSig07PrivateKey(trad_key=self.bad_rsa_key, pq_key=pq_key)

        sig = comp.sign(data=b"data")

        with self.assertRaises(InvalidKeyCombination):
            comp.public_key().verify(signature=sig, data=b"data")

    def test_build_neg_ir_comp_sig06(self):
        """
        GIVEN A composite signature key with an invalid key combination.
        WHEN the ir is built,
        THEN should a `InvalidKeyCombination` exception be raised.
        """
        comp = CompositeSig07PrivateKey(trad_key=self.bad_rsa_key, pq_key=self.ml_dsa_44_key)
        with self.assertRaises(InvalidKeyCombination):
            _ = build_ir_from_key(comp)

    def test_build_ir_with_spki(self):
        """
        GIVEN A composite signature key with an invalid key combination.
        WHEN the SPKI is prepared and the ir is built,
        THEN should a valid PKIMessage be returned.
        """
        comp = CompositeSig07PrivateKey(trad_key=self.bad_rsa_key, pq_key=self.ml_dsa_44_key)
        spki = prepare_subject_public_key_info(comp)
        _ = build_ir_from_key(comp, spki=spki)

    def test_neg_composite_sig_key_gen_comp_sig04(self):
        """
        Generate a composite signature key with RSA traditional key and ML-DSA-44 post-quantum key.
        WHEN the key is generated,
        THEN the key is generated successfully.
        """
        comp_key = generate_key("composite-sig", trad_key=self.bad_rsa_key, pq_key=None)
        self.assertEqual(comp_key.trad_key.public_key(), self.bad_rsa_key.public_key())
        self.assertEqual(comp_key.pq_key.name, "ml-dsa-44")
