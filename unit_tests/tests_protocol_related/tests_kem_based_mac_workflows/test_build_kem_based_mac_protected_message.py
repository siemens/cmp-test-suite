# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pyasn1.codec.der import decoder, encoder

from resources.asn1_structures import KemCiphertextInfoAsn1, InfoTypeAndValue
from resources.certutils import parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import verify_pkimessage_protection, prepare_kem_ciphertextinfo
from resources.utils import load_and_decode_pem_file
from resources.cmputils import build_kem_based_mac_protected_message, build_ir_from_key


class TestBuildKemBasedMacProtectedMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.common_name = "CN=Hans the Tester"
        cls.xwing = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
        cls.xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))

    def test_build_kem_based_mac_protected_message_with_cert(self):
        """
        GIVEN an X-Wing key and an X-Wing certificate
        WHEN building a KEM based MAC protected message.
        THEN the message is correctly protected.
        """
        ir = build_ir_from_key(
            signing_key=self.xwing,
        )
        ss, pki_message = build_kem_based_mac_protected_message(
            request=ir,
            ca_cert=self.xwing_cert,
        )
        verify_pkimessage_protection(
            shared_secret=ss,
            pki_message=pki_message,
        )

    def test_build_kbm_with_client_key_and_kem_ct_info(self):
        """
        GIVEN a client key and a KEMCiphertextInfo structure
        WHEN building a KEM based MAC protected message.
        THEN the message is correctly protected.
        """
        key = load_private_key_from_file("data/keys/client-key-x25519.pem")
        ss, ct = self.xwing.public_key().encaps(key.public_key())
        kem_ct_info = prepare_kem_ciphertextinfo(
            key=self.xwing,
            ct=ct,
        )

        der_data = encoder.encode(kem_ct_info)
        decoded_kem_ct_info, _ = decoder.decode(der_data, InfoTypeAndValue())

        _, pki_message = build_kem_based_mac_protected_message(
            request=build_ir_from_key(key),
            kem_ct_info=decoded_kem_ct_info,
            client_key=self.xwing,
        )
        verify_pkimessage_protection(
            shared_secret=ss,
            pki_message=pki_message,
        )

    def test_build_kbm_with_ss(self):
        """
        GIVEN a shared secret.
        WHEN building a KEM based MAC protected message.
        THEN the message is correctly protected.
        """
        ss = os.urandom(32)
        _, pki_message = build_kem_based_mac_protected_message(
            request=build_ir_from_key(self.xwing),
            ca_cert=self.xwing_cert,
            shared_secret=ss,
        )
        verify_pkimessage_protection(
            shared_secret=ss,
            pki_message=pki_message,
        )



