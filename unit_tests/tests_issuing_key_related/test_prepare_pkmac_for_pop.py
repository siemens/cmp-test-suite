# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211
from resources.cmputils import prepare_cert_request
from resources.extra_issuing_logic import prepare_pkmac_popo
from resources.keyutils import load_private_key_from_file


class TestPreparePkmacForPop(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", None)
        cls.shared_secret = b"A" * 32
        cls.common_name = "CN=Hans the Tester"


    def test_prepare_pkmac_for_pop(self):
        """
        GIVEN a shared secret and a common name.
        WHEN prepare_pkmac_popo is called,
        THEN an en- and decodeable `ProofOfPossession` object is returned
        """
        cert_request = prepare_cert_request(common_name=self.common_name, key=self.key)
        prepared_pkmac = prepare_pkmac_popo(shared_secret=self.shared_secret,
                                            cert_request=cert_request)

        der_data = encoder.encode(prepared_pkmac)
        data, rest = decoder.decode(der_data, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")
