# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_kup_from_kur
from resources.certutils import parse_certificate
from resources.cmputils import build_key_update_request, prepare_popo, \
    prepare_cert_req_msg
from resources.exceptions import BadPOP
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestBuildKupFromKur(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem"))

    def test_build_kup_from_kur(self):
        """
        GIVEN a valid kur PKIMessage.
        WHEN the PKIMessage is processed, and a response is built,
        THEN must a PKIMessage with a status of 'accepted' be returned.
        """
        kur = build_key_update_request(
            self.new_key,
            cert=self.cert,
            use_controls=True,
            exclude_fields=None,

        )
        kur["extraCerts"].extend([self.cert, self.ca_cert])
        der_data = try_encode_pyasn1(kur)
        kur, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
        kur: PKIMessageTMP

        kup, certs = build_kup_from_kur(
            request=kur,
            ca_key=self.private_key,
            ca_cert=self.ca_cert,

        )
        obj, rest = try_decode_pyasn1(try_encode_pyasn1(kup), PKIMessageTMP())
        self.assertEqual(rest, b"")

    def test_ra_verified_kup(self):
        """
        GIVEN a valid kur PKIMessage.
        WHEN the PKIMessage is processed, and a response is built,
        THEN must a PKIMessage with a status of 'accepted' be returned.
        """

        popo = prepare_popo(
            ra_verified=True,
        )

        kur = build_key_update_request(
            self.new_key,
            cert=self.cert,
            use_controls=True,
            exclude_fields=None,
            popo=popo,
        )
        kur["extraCerts"].extend([self.cert, self.ca_cert])
        der_data = try_encode_pyasn1(kur)
        kur, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
        kur: PKIMessageTMP

        with self.assertRaises(BadPOP):
            build_kup_from_kur(
                request=kur,
                ca_key=self.private_key,
                ca_cert=self.ca_cert,
                ra_verified=False,
            )

    def test_invalid_pop_kur(self):
            """
            GIVEN a valid kur PKIMessage with an invalid signature pop.
            WHEN the PKIMessage is processed, and a response is built,

            """

            cert_req_msg = prepare_cert_req_msg(
                self.new_key,
                bad_pop=True,
                common_name="CN=Hans the Tester",
            )

            kur = build_key_update_request(
                self.new_key,
                cert=self.cert,
                cert_req_msg=cert_req_msg,
                exclude_fields=None,
            )
            kur["extraCerts"].extend([self.cert, self.ca_cert])
            der_data = try_encode_pyasn1(kur)
            kur, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
            self.assertEqual(rest, b"")
            kur: PKIMessageTMP

            with self.assertRaises(BadPOP):
                build_kup_from_kur(
                    request=kur,
                    ca_key=self.private_key,
                    ca_cert=self.ca_cert,
                    ra_verified=False,
                )



