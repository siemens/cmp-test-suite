# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import build_cp_cmp_message
from resources.certutils import parse_certificate
from resources.cmputils import build_cr_from_key, prepare_cert_req_msg
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildCpCmpMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.mldsa_key2 = load_private_key_from_file("data/keys/private-key-ml-dsa-65-seed.pem")
        cls.mldsa_key3 = load_private_key_from_file("data/keys/private-key-ml-dsa-87-seed.pem")

    def test_build_cp_cmp_message(self):
        """
        GIVEN a Composite Signature Private Key, build a `cr` message.
        WHEN the `cp` response message is built.
        THEN the CMP message is built correctly.
        """
        pki_message = build_cr_from_key(
            signing_key=self.comp_key
        )

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            cert_index=0,
        )

        self.assertEqual(len(certs), 1)

        _ = de_and_encode_pkimessage(pki_message)


    def test_build_cp_cmp_message_2(self):
        """
        GIVEN Certificate Request Messages and `cr` Message.
        WHEN the `cp` response message is built.
        THEN the CMP message is built correctly.
        """
        cert_req_msg1 = prepare_cert_req_msg(
            private_key=self.mldsa_key,
            common_name="CN=Test ML DSA 44",
        )
        cert_req_msg2 = prepare_cert_req_msg(
            private_key=self.mldsa_key2,
            common_name="CN=Test ML DSA 65",
        )
        cert_req_msg3 = prepare_cert_req_msg(
            private_key=self.mldsa_key3,
            common_name="CN=Test ML DSA 87",
        )

        cert_req_msgs = [cert_req_msg1, cert_req_msg2, cert_req_msg3]
        pki_message = build_cr_from_key(
            signing_key=None,
            cert_req_msg=cert_req_msgs,
        )

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )

        self.assertEqual(len(certs), 3)

        _ = de_and_encode_pkimessage(pki_message)
