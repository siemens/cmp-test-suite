# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey
from pq_logic.pq_key_factory import PQKeyFactory


class TestCompositeSignature(unittest.TestCase):

    def test_comp_sig_pure_rsa(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA
        WHEN signing and verifying data with RSA,
        THEN the verification should succeed
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        trad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        message = os.urandom(32)
        sig = comp_key.sign(message, use_pss=False)
        comp_pk.verify(message, sig, use_pss=False)

    def test_comp_sig_pure_rsa_pss(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA
        WHEN signing and verifying data with RSA-PSS,
        THEN the verification should succeed
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        trad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        data = os.urandom(32)
        sig = comp_key.sign(data, use_pss=True)
        comp_pk.verify(data, sig, use_pss=True)


    def test_mismatch_oid(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA
        WHEN signing with the prehash version and verifying data without prehash,
        THEN the verification should fail.
        :return:
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        trad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        data = os.urandom(32)
        sig = comp_key.sign(data, use_pss=False, pre_hash=True)
        with self.assertRaises(InvalidSignature):
             comp_pk.verify(data, sig, use_pss=False, pre_hash=False)


    def test_comp_sig_rsa_prehash(self):
        """
        GIVEN a composite signature key with RSA and ML-DSA
        WHEN signing with the prehash version and verifying data,
        THEN the verification should succeed
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        trad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        data = os.urandom(32)
        sig = comp_key.sign(data, use_pss=False, pre_hash=True)

        comp_pk.verify(data, sig, use_pss=False, pre_hash=True)

    def test_comp_sig_ec_secp256r1(self):
        """
        GIVEN a composite signature key with ECDSA and ML-DSA
        WHEN signing and verifying data,
        THEN the verification should succeed
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        trad_key = ec.generate_private_key(ec.SECP256R1())

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        data = os.urandom(32)
        sig = comp_key.sign(data, use_pss=False, pre_hash=True)

        comp_pk.verify(data, sig, use_pss=False, pre_hash=True)

    def test_comp_sig_ec_brainpoolp256r1(self):
        """
        GIVEN a composite signature key with ECDSA and ML-DSA
        WHEN signing and verifying data,
        THEN the verification should succeed
        """
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-65")
        trad_key = ec.generate_private_key(ec.BrainpoolP256R1())

        comp_key = CompositeSigCMSPrivateKey(pq_key, trad_key)
        comp_pk = comp_key.public_key()

        data = os.urandom(32)
        sig = comp_key.sign(data, use_pss=False, pre_hash=False)
        comp_pk.verify(data, sig, use_pss=False, pre_hash=False)
