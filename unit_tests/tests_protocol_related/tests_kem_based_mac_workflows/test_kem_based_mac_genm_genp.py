# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.certutils import parse_certificate
from resources.general_msg_utils import build_cmp_general_message, validate_genp_kem_ct_info, \
    build_genp_kem_ct_info_from_genm
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import prepare_kem_ciphertextinfo
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestKEMBasedMacGenmGenp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.common_name = "CN=Hans the Tester"
        cls.xwing = load_private_key_from_file("./data/keys/private-key-xwing.pem")
        cls.xwing_cert = parse_certificate(load_and_decode_pem_file("./data/unittest/hybrid_cert_xwing.pem"))

    def test_build_general_message_for_kembasedmac(self):
        """
        GIVEN a KEM key,
        WHEN building a general message,
        THEN the message is correctly built.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_cmp_general_message(
            add_messages=None,
            info_values=info_val,
        )
        self.assertEqual(len(genm["body"]["genm"]), 1)
        der_data = try_encode_pyasn1(genm)
        decoded_genm, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")


    def test_build_genp_from_genm(self):
        """
        GIVEN a general message,
        WHEN building a genp message,
        THEN the message is correctly built.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_cmp_general_message(
            add_messages=None,
            info_values=info_val,
        )
        genm["extraCerts"].append(self.xwing_cert)

        der_data = try_encode_pyasn1(genm)
        decoded_genm, rest = try_decode_pyasn1(der_data, PKIMessageTMP())

        ss, genp = build_genp_kem_ct_info_from_genm(
            genm=decoded_genm,
        )
        self.assertEqual(len(genp["body"]["genp"]), 1)
        der_data = try_encode_pyasn1(genp)
        decoded_genp, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")


    def test_message_exchange(self):
        """
        GIVEN a complete message exchange,
        WHEN all necessary messages are built,
        THEN the genp message is correctly built
        and the shared secret is correctly decapsulated.
        """
        info_val = prepare_kem_ciphertextinfo(
            key=self.xwing,
        )
        genm = build_cmp_general_message(
            add_messages=None,
            info_values=info_val,
        )
        genm["extraCerts"].append(self.xwing_cert)
        der_data = try_encode_pyasn1(genm)
        decoded_genm, rest = try_decode_pyasn1(der_data, PKIMessageTMP())

        ss, genp = build_genp_kem_ct_info_from_genm(
            genm=decoded_genm,
        )
        ss_out = validate_genp_kem_ct_info(
            genp=genp,
            client_private_key=self.xwing,
        )
        self.assertEqual(ss, ss_out)
