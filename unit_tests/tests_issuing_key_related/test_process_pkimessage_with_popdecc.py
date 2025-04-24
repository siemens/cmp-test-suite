# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder

from resources.ca_ra_utils import build_popdecc_from_request
from resources.cmputils import prepare_popo_challenge_for_non_signing_key, build_ir_from_key
from resources.exceptions import BadRequest
from resources.extra_issuing_logic import process_pkimessage_with_popdecc
from resources.keyutils import load_private_key_from_file


class TestProcessPKIMessageWithPopDecc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)


    def test_process_pki_message_with_popdecc(self):
        """
        GIVEN a PKIMessage with a PopDecc.
        WHEN processing the PKIMessage.
        THEN the PopDecC should be successfully verified.
        """
        rand_num = 9
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=2,
                               popo_structure=popo)
        popdecc, num = build_popdecc_from_request(request=ir,
                                                  rand_sender="CN=CMP-TEST-SUITE",
                                                  rand_int=rand_num,
                                                  ca_key=self.rsa_key)

        encoded_popdecc = encoder.encode(popdecc)

        out = process_pkimessage_with_popdecc(
            pki_message=encoded_popdecc,
            ee_key=self.rsa_key,
            expected_size=1,
            expected_sender="CN=CMP-TEST-SUITE"
        )

        self.assertEqual(int(out["body"]["popdecr"][0]), rand_num)

    def test_valid_encrypted_rand(self):
        """
        GIVEN a PKIMessage with a PopDecc.
        WHEN processing the PKIMessage with a valid encrypted random.
        THEN the PopDecC should be successfully verified.
        """
        rand_num = 9
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=3,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir,
                                                  rand_sender="CN=CMP-TEST-SUITE",
                                                  rand_int=rand_num,
                                                  pvno=3,

                                                  ca_key=self.rsa_key)

        encoded_popdecc = encoder.encode(popdecc)
        out = process_pkimessage_with_popdecc(
            pki_message=encoded_popdecc,
            ee_key=self.rsa_key,
            expected_size=1,
            expected_sender="CN=CMP-TEST-SUITE"
        )
        self.assertEqual(int(out["body"]["popdecr"][0]), rand_num)



    def test_invalid_size_popdecc(self):
        """
        GIVEN a PKIMessage with a PopDecc.
        WHEN processing the PKIMessage with an invalid size.
        THEN a BadRequest exception should be raised.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=2,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, for_pvno=3, ca_key=self.rsa_key)
        encoded_popdecc = encoder.encode(popdecc)

        with self.assertRaises(BadRequest):
            process_pkimessage_with_popdecc(
                pki_message=encoded_popdecc,
                ee_key=self.rsa_key,
                expected_size=2,
                expected_sender="CN=CMP-TEST-SUITE"
            )


    def test_invalid_version_popdecc(self):
        """
        GIVEN a PKIMessage with a PopDecc.
        WHEN processing the PKIMessage with an invalid version.
        (uses envelopedData but version 2.)
        THEN a BadRequest exception should be raised.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=True)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=2,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, for_pvno=3, ca_key=self.rsa_key)
        encoded_popdecc = encoder.encode(popdecc)

        with self.assertRaises(BadRequest):
            process_pkimessage_with_popdecc(
                pki_message=encoded_popdecc,
                ee_key=self.rsa_key,
                expected_size=1,
                expected_version=2,
                expected_sender="CN=CMP-Test-Suite",
            )

    def test_encr_rand_and_challenge_present(self):
        """
        GIVEN a PKIMessage with a PopDecc.
        WHEN processing the PKIMessage with the challenge and encrypted random present.
        THEN a BadRequest exception should be raised.
        """
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)
        ir = build_ir_from_key(signing_key=self.rsa_key,
                               pvno=3,
                               popo_structure=popo)

        popdecc, num = build_popdecc_from_request(request=ir, ca_key=self.rsa_key, challenge=b"1234")

        encoded_popdecc = encoder.encode(popdecc)
        with self.assertRaises(BadRequest):
            process_pkimessage_with_popdecc(
                pki_message=encoded_popdecc,
                ee_key=self.rsa_key,
                expected_size=1,
                expected_sender="CN=CMP-Test-Suite"
            )



