# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc4211

from resources.cmputils import prepare_popo_challenge_for_non_signing_key, prepare_cert_req_msg
from resources.keyutils import generate_key


class TestPOPONonSigningKey(unittest.TestCase):


    def test_prepare_with_challenge_with_enc_key(self):
        """
        GIVEN a challenge for a non-signing key.
        WHEN the challenge is prepared with an encryption key.
        THEN the challenge should be successfully prepared.
        """
        result = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)
        self.assertIsInstance(result, rfc4211.ProofOfPossession)
        self.assertTrue(result["keyEncipherment"].isValue)

        encoded = encoder.encode(result)
        decoded, rest = decoder.decode(encoded, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_with_challenge_with_key_agree(self):
        """
        GIVEN a challenge for a non-signing key.
        WHEN the challenge is prepared without an encryption key.
        THEN the challenge should be successfully prepared.
        """
        result = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)
        self.assertIsInstance(result, rfc4211.ProofOfPossession)
        self.assertTrue(result["keyAgreement"].isValue)

        encoded = encoder.encode(result)
        decoded, rest = decoder.decode(encoded, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_with_enc_cert_with_enc_key(self):
        """
        GIVEN a challenge for a non-signing key.
        WHEN the challenge is prepared with an encryption certificate and an encryption key.
        THEN the challenge should be successfully prepared.
        """
        result = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=True)
        self.assertIsInstance(result, rfc4211.ProofOfPossession)
        self.assertTrue(result["keyEncipherment"].isValue)

        encoded = encoder.encode(result)
        decoded, rest = decoder.decode(encoded, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_with_enc_cert_with_key_agree(self):
        """
        GIVEN a challenge for a non-signing key.
        WHEN the challenge is prepared with an encryption certificate and without an encryption key.
        THEN the challenge should be successfully prepared.
        """
        result = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=False)
        self.assertIsInstance(result, rfc4211.ProofOfPossession)
        self.assertTrue(result["keyAgreement"].isValue)

        encoded = encoder.encode(result)
        decoded, rest = decoder.decode(encoded, asn1Spec=rfc4211.ProofOfPossession())
        self.assertEqual(rest, b"")

    def test_prepare_cert_req_msg(self):
        """
        GIVEN a non-signing key and a common name.
        WHEN a certificate request message is prepared.
        THEN the CertReqMsg should be successfully prepared
        and can be en- and decoded.
        """

        cert_req_msg = prepare_cert_req_msg(private_key=generate_key("ml-kem-768"),
                                            common_name="CN=Hans the Tester",
                                            use_encr_cert=True)


        decoded, rest = decoder.decode(encoder.encode(cert_req_msg), asn1Spec=rfc4211.CertReqMsg())
        self.assertEqual(rest, b"")