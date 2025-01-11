# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pq_logic.pq_key_factory import PQKeyFactory
from resources.cryptoutils import sign_data, verify_signature


class TestSLHDSASignAndVerify(unittest.TestCase):

    def setUp(self):
        self.slh_dsa_key = PQKeyFactory.generate_pq_key("slh-dsa")
        self.data = os.urandom(1024)


    def test_slh_dsa_sign_without_alg(self):
        """
        GIVEN a SLH-DSA key.
        WHEN data is signed without specifying a hash algorithm.
        THEN the signature should be successfully verified.
        """
        signature = sign_data(self.data, self.slh_dsa_key)
        verify_signature(signature=signature, data=self.data,
                         public_key=self.slh_dsa_key.public_key())


    def test_slh_dsa_sign_with_sha256(self):
        """
        GIVEN a SLH-DSA key.
        WHEN data is signed with SHA256.
        THEN the signature should be successfully verified.
        """
        signature = sign_data(self.data, self.slh_dsa_key, hash_alg="sha256")
        verify_signature(signature=signature,
                         data=self.data,
                         public_key=self.slh_dsa_key.public_key(),
                         hash_alg="sha256")

    def test_slh_dsa_sign_with_shake128(self):
        """
        GIVEN a SLH-DSA key.
        WHEN data is signed with SHAKE128.
        THEN the signature should be successfully verified.
        """
        signature = sign_data(self.data, self.slh_dsa_key, hash_alg="shake128")
        verify_signature(signature=signature,
                         data=self.data,
                         public_key=self.slh_dsa_key.public_key(),
                         hash_alg="shake128")



    def test_slh_dsa_sign_with_shake256(self):
        """
        GIVEN a SLH-DSA key.
        WHEN data is signed with SHAKE256.
        THEN the signature should be successfully verified.
        """
        signature = sign_data(self.data, self.slh_dsa_key, hash_alg="shake256")
        verify_signature(signature=signature,
                         data=self.data,
                         public_key=self.slh_dsa_key.public_key(),
                         hash_alg="shake256")
