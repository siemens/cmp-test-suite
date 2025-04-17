# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder

from resources.asn1_structures import PKIMessageTMP, ChallengeASN1
from resources.ca_ra_utils import build_popdecc_from_request
from resources.cmputils import build_ir_from_key, prepare_popo_challenge_for_non_signing_key
from resources.keyutils import generate_key, load_private_key_from_file
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildPoPDeccFromRequest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


    def test_challenge_en_decode_able(self):
        """
        GIVEN a request for a PoPDecc.
        WHEN building a challenge.
        THEN the challenge should be correctly built.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=2,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, ca_key=self.rsa_key)
        der_data = encoder.encode(popdecc["body"]["popdecc"][0])
        decoded_challenge, rest = decoder.decode(der_data, asn1Spec=ChallengeASN1())
        self.assertEqual(rest, b"")

    def test_build_challenge_is_en_and_decode_able(self):
        """
        GIVEN a request for a PoPDecc.
        WHEN building a challenge.
        THEN the challenge should be correctly built.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                                 pvno=2,
                               popo_structure=popo)
        popdecc, num = build_popdecc_from_request(request=ir, ca_key=self.rsa_key)
        decoded_popdecc = de_and_encode_pkimessage(popdecc)

    def test_build_encrypted_rand_en_and_decode_able(self):
        """
        GIVEN a request.
        WHEN building an encrypted random.
        THEN the encrypted random should be correctly built.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=3,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, ca_key=self.rsa_key)
        decoded_popdecc = de_and_encode_pkimessage(popdecc)

    def test_build_encr_rand_v3_but_req_v2(self):
        """
        GIVEN a request.
        WHEN building an encrypted random with request version 2.
        THEN the encrypted random should be correctly built for version 3.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=2,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, for_pvno=3, ca_key=self.rsa_key)

        challenge = popdecc["body"]["popdecc"][0]
        self.assertEqual(challenge["challenge"], b"")
        self.assertTrue(challenge["encryptedRand"].isValue)

    def test_build_challenge_v3_with_val(self):
        """
        GIVEN a request.
        WHEN building a challenge with a value.
        THEN the challenge should be correctly built.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=3,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, ca_key=self.rsa_key, challenge=b"1234")

        challenge = popdecc["body"]["popdecc"][0]
        self.assertTrue(challenge["challenge"].isValue)
        self.assertTrue(challenge["encryptedRand"].isValue)
