# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import build_ip_cmp_message
from resources.cmputils import build_ir_from_key, prepare_cert_request, prepare_signature_popo
from resources.exceptions import BadPOP
from resources.keyutils import generate_key
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestInvalidSigAlgId(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.recipient = "CN=MockCA"
        cls.cm = "CN=Hans the Tester"
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()


    def test_invalid_popo_signature_flow(self):
        """
        GIVEN a valid IR with a mismatching alg id.
        WHEN the IR is processed,
        THEN should a badPOP exception be raised.
        """

        key1 = generate_key('rsa')
        key2 = generate_key('ecc')

        cert_req = prepare_cert_request(key2, self.cm)

        popo = prepare_signature_popo(key1, cert_req, hash_alg='sha256')


        ir = build_ir_from_key(
            key2,
            popo=popo,
            cert_request=cert_req,
            recipient=self.recipient,
        )
        with self.assertRaises(BadPOP) as e:
            build_ip_cmp_message(
                request=ir,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
            )
        self.assertEqual(e.exception.message, "The `signature` POP alg id and the public key are of different types.")
