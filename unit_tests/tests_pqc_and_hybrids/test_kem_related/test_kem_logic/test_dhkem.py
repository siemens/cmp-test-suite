# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


import binascii
import unittest
from binascii import unhexlify

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pq_logic.kem_mechanism import DHKEMRFC9180


class TestDHKEMRFC9180(unittest.TestCase):

    def setUp(self):
        self.dh_kem = DHKEMRFC9180(context="HPKE-v1")


    def test_rfc9180_vectors(self):
        """
        GIVEN the test vectors for P256 from RFC 9180.
        WHEN the encapsulation and decacapsulation is performed.
        THEN the shared secret should be equal to the expected shared secret.
        """
        skEm = ec.derive_private_key(
            int(
                "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb", 16
            ),
            ec.SECP256R1()
        )

        skRm = ec.derive_private_key(
            int(
                "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2", 16
            ),
            ec.SECP256R1()
        )

        pkRm = skRm.public_key()

        enc = binascii.unhexlify(
            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
        )

        expected_shared_secret = (
            "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8"
        )

        dhkem = DHKEMRFC9180(private_key=skEm, context="HPKE-v1")
        dhkem2 = DHKEMRFC9180(private_key=skRm, context="HPKE-v1")

        shared_secret, generated_enc = dhkem.encaps(pkRm)

        self.assertEqual(generated_enc.hex(), enc.hex())
        self.assertEqual(shared_secret.hex(), expected_shared_secret)

        decapsulated_secret = dhkem2.decaps(enc)

        self.assertEqual(decapsulated_secret.hex(), expected_shared_secret)

    def test_x25519_key_exchange(self):
        """
        GIVEN the test vectors for x25519 from RFC 9180.
        WHEN the encapsulation and decacapsulation is performed.
        THEN the shared secret should be equal to the expected shared secret.
        """
        skEm = unhexlify("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
        pkRm = unhexlify("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
        skRm = unhexlify("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
        expected_enc = unhexlify("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
        expected_shared_secret = unhexlify("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7")

        sender_sk = X25519PrivateKey.from_private_bytes(skEm)
        recipient_sk = X25519PrivateKey.from_private_bytes(skRm)
        recipient_pk = X25519PublicKey.from_public_bytes(pkRm)

        self.dh_kem.private_key = sender_sk
        shared_secret, enc = self.dh_kem.encaps(recipient_pk)

        self.assertEqual(enc, expected_enc)
        self.assertEqual(shared_secret, expected_shared_secret)

        self.dh_kem.private_key = recipient_sk
        decapped_shared_secret = self.dh_kem.decaps(enc)

        self.assertEqual(decapped_shared_secret, expected_shared_secret)

    def test_p521_key_exchange(self):
        """
        GIVEN the test vectors for P521 from RFC 9180.
        WHEN the encapsulation and decacapsulation is performed.
        THEN the shared secret should be equal to the expected shared secret.
        """
        # currently not considered, by Chempat.
        skEm_hex = (
            "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354"
            "15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e37"
            "4b"
        )

        skRm_hex = (
            "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c2"
            "7196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b24628"
            "47"
        )

        expected_shared_secret = (
            "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1"
            "d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46"
            "d30e818"
        )

        skRm = ec.derive_private_key(
            int(
                skRm_hex, 16
            ),
            ec.SECP521R1()
        )

        skEm = ec.derive_private_key(
            int(
                skEm_hex, 16
            ),
            ec.SECP521R1()
        )

        self.dh_kem.private_key = skEm
        shared_secret, enc = self.dh_kem.encaps(skRm.public_key())
        self.assertEqual(shared_secret.hex(), expected_shared_secret)

        self.dh_kem.private_key = skRm

        decapped_shared_secret = self.dh_kem.decaps(enc)
        self.assertEqual(decapped_shared_secret.hex(), expected_shared_secret)


if __name__ == "__main__":
    unittest.main()
