# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig import CompositeSigPrivateKey
from resources.keyutils import load_private_key_from_file, generate_key


class TestCompositeSig13(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ecc_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.ed_key = generate_key("ed448")
        cls.mldsa87_key = load_private_key_from_file("data/keys/private-key-ml-dsa-87-seed.pem")
        cls.data = b"Hello, world!"

    def test_composite_sig_rsa(self):
        """
        GIVEN a Composite-Sig RSA key.
        WHEN signing data with the key.
        THEN verify the signature with the public key.
        """
        comp_key = CompositeSigPrivateKey(self.mldsa_key, self.rsa)
        sig = comp_key.sign(self.data, use_pss=False, )
        public_key = comp_key.public_key()
        public_key.verify(signature=sig, data=self.data, use_pss=False)

    def test_composite_sig_rsa_pss(self):
        """
        GIVEN a Composite-Sig RSA key.
        WHEN signing data with the key and using PSS.
        THEN verify the signature with the public key.
        """
        comp_key = CompositeSigPrivateKey(self.mldsa_key, self.rsa)
        self.assertEqual(comp_key.get_oid(), comp_key.public_key().get_oid())
        self.assertEqual(comp_key.get_oid(use_pss=True), comp_key.public_key().get_oid(use_pss=True))
        self.assertEqual(comp_key.get_oid(use_pss=True),
                         comp_key.public_key().get_oid(use_pss=True))
        sig = comp_key.sign(data=self.data, use_pss=True)
        public_key = comp_key.public_key()
        public_key.verify(signature=sig, data=self.data, use_pss=True)

    def test_composite_sig_ecdsa(self):
        """
        GIVEN a Composite-Sig ECDSA key.
        WHEN signing data with the key.
        THEN verify the signature with the public key.
        """
        comp_key = CompositeSigPrivateKey(self.mldsa_key, self.ecc_key)
        self.assertEqual(comp_key.get_oid(), comp_key.public_key().get_oid())
        self.assertEqual(comp_key.get_oid(), comp_key.public_key().get_oid())
        sig = comp_key.sign(self.data, )
        public_key = comp_key.public_key()
        public_key.verify(signature=sig, data=self.data, )


    def test_composite_sig_ed448(self):
        """
        GIVEN a Composite-Sig ED448 key.
        WHEN signing data with the key.
        THEN verify the signature with the public key.
        """
        comp_key = CompositeSigPrivateKey(self.mldsa87_key, self.ed_key)
        sig = comp_key.sign(self.data, )
        public_key = comp_key.public_key()
        public_key.verify(signature=sig, data=self.data)
