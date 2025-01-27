import unittest

from resources.ca_ra_utils import prepare_challenge
from resources.extra_issuing_logic import process_simple_challenge
from resources.keyutils import generate_key, load_private_key_from_file
from resources.asn1_structures import ChallengeASN1, KemCiphertextInfoAsn1


class TestPrepareChallenge(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.rand_int = 15
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_challenge_rsa(self):
        """
        GIVEN an RSA public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        ee_key = generate_key("rsa")
        pub_key = ee_key.public_key()

        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            rand_int=self.rand_int,
            iv="A"*16,
        )

        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNone(info_val)

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            iv="A"*16,

        )
        self.assertEqual(int(rand["int"]), self.rand_int)

    def test_challenge_ecc(self):
        """
        GIVEN an EC public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        ee_key = generate_key("ec")
        pub_key = ee_key.public_key()

        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            ca_key=self.ca_key,
            rand_int=self.rand_int,
            iv="A"*16,
        )

        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNone(info_val)

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            ca_pub_key=self.ca_key.public_key(),
            iv="A"*16,

        )
        self.assertEqual(int(rand["int"]), 15)

    def test_challenge_kem(self):
        """
        GIVEN an KEM public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        rand_int = 15

        ee_key = generate_key("ml-kem-768")
        pub_key = ee_key.public_key()

        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            rand_int=rand_int,
            ca_key=self.ca_key,
            iv="A"*16,
        )
        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNotNone(info_val)

        kemct_info: KemCiphertextInfoAsn1 = info_val["infoValue"]
        kemct = kemct_info["ct"].asOctets()

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            ca_pub_key=None,
            iv="A"*16,
            kemct=kemct

        )
        self.assertEqual(int(rand["int"]), rand_int)

    def test_challenge_xwing(self):
        """
        GIVEN an XWing public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        rand_int = 15

        ee_key = generate_key("xwing")
        pub_key = ee_key.public_key()
        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            rand_int=rand_int,
            ca_key=generate_key("x25519"),
            iv="A"*16,
        )
        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNotNone(info_val)

        kemct_info: KemCiphertextInfoAsn1 = info_val["infoValue"]
        kemct = kemct_info["ct"].asOctets()

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            ca_pub_key=None,
            iv="A"*16,
            kemct=kemct

        )
        self.assertEqual(int(rand["int"]), rand_int)

    def test_challenge_chempat(self):
        """
        GIVEN an CHEMPAT public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        rand_int = 15
        ee_key = generate_key("chempat", trad_name="x25519",
                              pq_name="ml-kem-768")

        pub_key = ee_key.public_key()
        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            rand_int=rand_int,
            ca_key=generate_key("x25519"),
            iv="A"*16,
        )
        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNotNone(info_val)

        kemct_info: KemCiphertextInfoAsn1 = info_val["infoValue"]
        kemct = kemct_info["ct"].asOctets()

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            ca_pub_key=None,
            iv="A"*16,
            kemct=kemct

        )
        self.assertEqual(int(rand["int"]), rand_int)

    def test_challenge_composite_kem(self):
        """
        GIVEN a Composite KEM public key.
        WHEN preparing a challenge object,
        THEN should the challenge object be correctly prepared.
        """
        ee_key = generate_key("composite-kem", trad_name="rsa",
                              length=2048, pq_name="ml-kem-768")
        pub_key = ee_key.public_key()

        challenge_obj, shared_secret, info_val = prepare_challenge(
            public_key=pub_key,
            rand_int=self.rand_int,
            iv="A"*16,
        )
        self.assertIsInstance(challenge_obj, ChallengeASN1)
        self.assertIsNotNone(info_val)

        kemct_info: KemCiphertextInfoAsn1 = info_val["infoValue"]
        kemct = kemct_info["ct"].asOctets()

        rand = process_simple_challenge(
            challenge=challenge_obj,
            ee_key=ee_key,
            ca_pub_key=None,
            iv="A"*16,
            kemct=kemct

        )
        self.assertEqual(int(rand["int"]), self.rand_int)



if __name__ == '__main__':
    unittest.main()