# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives._serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from resources import keyutils
from resources.utils import manipulate_first_byte


class TestLoadCompSig04(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rsa_key = keyutils.generate_key("rsa", length=2048)
        mldsa_key = keyutils.generate_key("ml-dsa-44")
        cls.comp_rsa_key = CompositeSig04PrivateKey(mldsa_key, rsa_key)
        ed_key = keyutils.generate_key("ed448")
        mldsa_key = keyutils.generate_key("ml-dsa-87")
        cls.comp_ed_key = CompositeSig04PrivateKey(mldsa_key, ed_key)

        ecc_key = keyutils.generate_key("ecdsa")
        mldsa_key = keyutils.generate_key("ml-dsa-65")
        cls.comp_ecc_key = CompositeSig04PrivateKey(mldsa_key, ecc_key)

    def test_export_and_load_pub_key_rsa(self):
        """
        GIVEN a composite signature RSA-key in version 4.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        der_data = self.comp_rsa_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )
        private_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
        self.assertEqual(private_key.public_key(), self.comp_rsa_key.public_key())


    def test_export_and_load_pub_key_ed(self):
        """
        GIVEN a composite signature Ed-key in version 4.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        der_data = self.comp_ed_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )
        private_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
        self.assertEqual(private_key.public_key(), self.comp_ed_key.public_key())

    def test_export_and_load_pub_key_ecc(self):
        """
        GIVEN a composite signature ECC-key in version 4.
        WHEN exporting the public key and loading it back.
        THEN the loaded key is the same as the exported key.
        """
        der_data = self.comp_ecc_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )
        private_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
        self.assertEqual(private_key.public_key(), self.comp_ecc_key.public_key())


    def test_export_and_load_priv_key_bad_seed(self):
        """
        GIVEN a composite signature key in version 4.
        WHEN exporting the private key and loading it back with a bad ML-DSA seed.
        THEN is the loaded key different from the exported key.
        """
        _seed = manipulate_first_byte(self.comp_rsa_key.pq_key._seed)
        pq_key = MLDSAPrivateKey(seed=self.comp_rsa_key.pq_key._seed,
                                 alg_name=self.comp_rsa_key.pq_key.name)
        other_key = CompositeSig04PrivateKey(pq_key, trad_key=self.comp_rsa_key.trad_key)

        other_key.pq_key._seed = _seed

        der_data = other_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )

        out_key = CombinedKeyFactory.load_private_key_from_one_asym_key(der_data)
        self.assertNotEqual(out_key.public_key(), other_key.public_key())