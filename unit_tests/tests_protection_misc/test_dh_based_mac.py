# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from Crypto.Hash import KMAC256
from resources.cmputils import build_ir_from_key
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import (
    compute_dh_based_mac_from_alg_id,
    prepare_dh_based_mac_alg_id,
    protect_pkimessage,
    verify_pkimessage_protection,
)


class TestDHBasedMAC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dhmac_ss = b"A" * 12
        cls.data = b"Hello, World!"


    def test_compute_dh_based_mac_hmac(self):
        """
        GIVEN a shared secret and data.
        WHEN the DHBasedMAC is computed using HMAC,
        THEN the DHBasedMAC is computed correctly.
        """
        # does not need extract logic.
        # to increase the key size.
        alg_id = prepare_dh_based_mac_alg_id(hash_alg="sha1", mac_alg="hmac")
        compute_dh_based_mac_from_alg_id(data=self.data, shared_secret=self.dhmac_ss, alg_id=alg_id)

    def test_compute_dh_based_mac_kmac(self):
        """
        GIVEN a shared secret and data, with a short base key.
        WHEN the DHBasedMAC is computed using KMAC,
        THEN the basekey is extended and the DHBasedMAC is computed correctly.
        """
        with self.assertRaises(ValueError):
            # to prove that the key needs to be extended.
            too_short_key = b"key"
            KMAC256.new(key=too_short_key, data=self.data, mac_len=32, custom=b"")

        alg_id = prepare_dh_based_mac_alg_id(hash_alg="sha1", mac_alg="kmac")
        compute_dh_based_mac_from_alg_id(data=self.data, shared_secret=self.dhmac_ss, alg_id=alg_id)

    def test_compute_dh_based_mac_gmac(self):
        """
        GIVEN a shared secret and data.
        WHEN the DHBasedMAC is computed using AES-GMAC,
        THEN the basekey is extended and the DHBasedMAC is computed correctly.
        """
        alg_id = prepare_dh_based_mac_alg_id(hash_alg="sha1", mac_alg="aes256_gmac")
        compute_dh_based_mac_from_alg_id(data=self.data, shared_secret=self.dhmac_ss, alg_id=alg_id)


    def test_verify_pkimessage_dh_based_mac(self):
        """
        GIVEN a PKIMessage with a DHBasedMAC protection.
        WHEN the PKIMessage is verified,
        THEN the protection is verified correctly.
        """
        key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        ir = build_ir_from_key(key)
        protected_ir = protect_pkimessage(pki_message=ir,
                                          protection="dh",
                                          shared_secret=self.dhmac_ss,
                                          hash_alg="sha1",
                                          mac_alg="aes256_gmac")

        verify_pkimessage_protection(protected_ir, shared_secret=self.dhmac_ss)
