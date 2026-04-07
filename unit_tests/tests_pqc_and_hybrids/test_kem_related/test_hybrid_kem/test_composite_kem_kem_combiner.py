# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey

from resources.keyutils import generate_key


class CompositeKEMKEMCombinerTest(unittest.TestCase):
    """Test the Composite KEM KEM combiner (draft-ietf-lamps-pq-composite-kem-14)."""

    def test_kem_combiner_example1(self):
        """Example of id-MLKEM768-ECDH-P256-SHA3-256 Combiner function output."""
        # Inputs
        mlkemSS = "ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43"
        tradSS = "ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0"
        tradCT = (
            "041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d19171270cdef"
            "cd4abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5e7610"
        )
        tradPK = (
            "04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159ff73d3"
            "8d29aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e80396a3e"
        )
        Label = "4d4c4b454d3736382d50323536"  # ASCII: "MLKEM768-P256"

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Label
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Label

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee"

        pq_key = generate_key("ml-kem-768")
        trad_key = generate_key("ecdh", curve="secp256r1")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-768-ecdh-secp256r1", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.59", str(comp_key.get_oid()))

        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-768-ecdh-secp256r1", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.59", str(comp_private_key.get_oid()))

        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected,
            ss.hex(),
            "id-MLKEM768-ECDH-P256-SHA3-256 Combiner function output does not match expected value.",
        )

        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected,
            ss2.hex(),
            "id-MLKEM768-ECDH-P256-SHA3-256 Combiner function output does not match expected value from private key.",
        )

    def test_kem_combiner_example2(self):
        """Example of id-MLKEM768-X25519-SHA3-256 Combiner function output."""
        # Inputs
        mlkemSS = "461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1"
        tradSS = "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843"
        tradCT = "0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f"
        tradPK = "1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b"
        Label = "5c2e2f2f5e5c"  # ASCII: \.//^\

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Label
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Label

        trad_key = generate_key("x25519")
        pq_key = generate_key("ml-kem-768")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-768-x25519", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.58", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-768-x25519", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.58", str(comp_private_key.get_oid()))

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98"
        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected, ss.hex(), "id-MLKEM768-X25519-SHA3-256 Combiner function output does not match expected value."
        )
        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected,
            ss2.hex(),
            "id-MLKEM768-X25519-SHA3-256 Combiner function output does not match expected value from private key.",
        )

    def test_kem_combiner_example3(self):
        """Example of id-MLKEM1024-ECDH-P384-SHA3-256 Combiner function output."""
        # Inputs
        mlkemSS = "c0f87f0c53fa8e2ba192a494694d37d1e3cf99c65e0dc5f69b2cc044b3fb205d"
        tradSS = "4d52b7ef430382f479603207c0b8f7aa5bc35d8758835007e39a2642ad65e635d674db7a5513889657fb24e4e228a098"
        tradCT = (
            "0401a5b81dcb51290a0eb142b9032d5a37503164b7a20ac0e3b52dc54f9b0b7"
            "c9fdd2699a59563a0b9ad0e54478846faeab72b92275e1fbb8b963bcc6e80e3"
            "0c089fbe4ed8d47ec76951db94aede46e679d5692eeb1d1b150d5b2e6660dc67c469"
        )
        tradPK = (
            "0468cc4acc5dd85edbcbf25bae7ee7dcacec2968ea7ee57fc91311cb9c47d4a"
            "24c3854e5ce3e5d0b309fda493224520f2870496eb16571108b3deafd72c1df"
            "17edc302fbb8b60bae44d93177e6df5278e4667a090a2d59a2076f41d693975e8d19"
        )
        Label = "4d4c4b454d313032342d50333834"  # ASCII: "MLKEM1024-P384"

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Label
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Label

        trad_key = generate_key("ecdh", curve="secp384r1")
        pq_key = generate_key("ml-kem-1024")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-1024-ecdh-secp384r1", comp_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.63", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-1024-ecdh-secp384r1", comp_private_key.name)
        self.assertEqual("1.3.6.1.5.5.7.6.63", str(comp_private_key.get_oid()))

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "eb60f6c80a309ad4158d7b02f2cf8c947faead96ebbd85c3f62a94868ffddca4"
        ss = comp_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected,
            ss.hex(),
            "id-MLKEM1024-ECDH-P384-SHA3-256 Combiner function output does not match expected value.",
        )

        ss2 = comp_private_key.kem_combiner(
            mlkem_ss=bytes.fromhex(mlkemSS),
            trad_ss=bytes.fromhex(tradSS),
            trad_ct=bytes.fromhex(tradCT),
            trad_pk=bytes.fromhex(tradPK),
            use_in_cms=False,
        )
        self.assertEqual(
            ss_expected,
            ss2.hex(),
            "id-MLKEM1024-ECDH-P384-SHA3-256 Combiner function output does not match expected value from private key.",
        )


if __name__ == "__main__":
    unittest.main()
