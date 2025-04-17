# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from cryptography.exceptions import InvalidSignature
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from resources.oid_mapping import compute_hash
from resources.utils import manipulate_first_byte


class TestMLDSASigVerify(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        cls.mldsa_version = "ml-dsa-44"
        cls.mldsa_key: MLDSAPrivateKey = PQKeyFactory.generate_pq_key(cls.mldsa_version)
        cls.ctx = b"CMP-TEST-SUITE"
        cls.data = os.urandom(1024)

    def test_mldsa_invalid_sig_verify(self):
        """
        GIVEN a MLDSA private key
        WHEN signing with context and the signature is manipulated,
        THEN the verification should fail
        """
        signature = self.mldsa_key.sign(ctx=self.ctx, data=self.data)
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            self.mldsa_key.public_key().verify(signature=signature, data=self.data, ctx=self.ctx)

    def test_mldsa_invalid_sig_verify_with_hash(self):
        """
        GIVEN a MLDSA private key
        WHEN signing data with context and a hash algorithm and the signature is manipulated,
        THEN the verification should fail
        """
        signature = self.mldsa_key.sign(ctx=self.ctx, data=self.data, hash_alg="sha512")
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            self.mldsa_key.public_key().verify(signature=signature, data=self.data, ctx=self.ctx, hash_alg="sha512")


    def test_mldsa_44_sig_verify_ctx(self):
        """
        GIVEN a MLDSA private key
        WHEN signing and verifying data with a context,
        THEN the verification should succeed
        """
        signature = self.mldsa_key.sign(ctx=self.ctx, data=self.data)
        self.mldsa_key.public_key().verify(signature=signature, data=self.data, ctx=self.ctx)

    def test_mldsa_44_sig_pre_hash_verify_ctx(self):
        """
        GIVEN a MLDSA private key
        WHEN signing and verifying data with a context with prehashed algorithm,
        THEN the verification should succeed
        """
        signature = self.mldsa_key.sign(ctx=self.ctx, data=self.data, hash_alg="sha512")
        self.mldsa_key.public_key().verify(signature=signature,hash_alg="sha512", data=self.data, ctx=self.ctx)


    def test_mldsa_44_sig_verify_prehash_verify_ctx(self):
        """
        GIVEN a MLDSA private key
        WHEN signing with a context and prehashed data,
        THEN the verification should succeed
        """
        signature = self.mldsa_key.sign(ctx=self.ctx, data=self.data, hash_alg="sha512")
        prehashed_data = compute_hash("sha512", self.data)
        self.mldsa_key.public_key().verify(signature=signature,
                                           hash_alg="sha512",
                                           data=prehashed_data,
                                           ctx=self.ctx,
                                           is_prehashed=True)


