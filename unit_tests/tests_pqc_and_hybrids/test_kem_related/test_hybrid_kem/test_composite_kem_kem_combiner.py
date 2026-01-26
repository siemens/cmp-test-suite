# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey

from resources.keyutils import generate_key


class CompositeKEMKEMCombinerTest(unittest.TestCase):
    """Test the Composite KEM KEM combiner."""

    def test_kem_combiner_example1(self):
        """Example of id-MLKEM768-ECDH-P256-HMAC-SHA256 Combiner function output."""
        # Inputs
        mlkemSS = "13f3e2c8d43aaa1045f0e3ba5c53a495a03553965d78fb8c62f1de14a83f0d4e"

        tradSS = "90b5bd5efb23a8084a53da8fabc5e919c9f3e7d6e9e62d1019959dff41e6669b"
        tradCT = "040c9c634ff4e0a309e1a285b9b79cc09c9b06f7558dd948f46b880b4acbe22061149a210e8c2d00f6c00837d52657d6c6b7ad94babb1cdfe0de85d869ec362a84"
        tradPK = "0436d5a0636fd2448488e5914d4820b9420c78f7ae14841c83d3b13f9550a76e96344e509845b1c4d451d6d865d45c69f62659ca77ecd1d69668d22c6c24643704"
        Domain = "060b6086480186fa6b50050236"

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Domain
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Domain

        # Outputs
        # ss = HMAC-SHA256(Combined KDF Input)
        ss_expected = "8e9333dbfbd5057855fee30049790e9e835f24373334bd257e76ec19725e8f89"

        pq_key = generate_key("ml-kem-768")
        trad_key = generate_key("ecdh", curve="secp256r1")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-768-ecdh-secp256r1", comp_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.54", str(comp_key.get_oid()))

        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-768-ecdh-secp256r1", comp_private_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.54", str(comp_private_key.get_oid()))

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
            "id-MLKEM768-ECDH-P256-HMAC-SHA256 Combiner function output does not match expected value.",
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
            "id-MLKEM768-ECDH-P256-HMAC-SHA256 Combiner "
            "function output does not match expected value from private key.",
        )

    def test_kem_combiner_example2(self):
        """Example of id-MLKEM768-X25519-SHA3-256 Combiner function output."""
        # Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.
        # Inputs
        mlkemSS = "542aba637e129ef540743b8420edb78b26e492af2a496f31d33138a5402239c3"
        tradSS = "8af825f1d07ad0b3bff6856a6f7aaa706eb1db11b6a7d2c44dfb06d041e7e261"
        tradCT = "1c5e3c085e7180ffe732c67b94f0d408e524af9dc2954e5ceea1fdfc03a76247"
        tradPK = "0cf7344981ef158017db99cce88de79194f0bf8ebc128d462b1f6a89b34fce7c"
        Domain = "060b6086480186fa6b50050235"

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Domain
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Domain
        trad_key = generate_key("x25519")
        pq_key = generate_key("ml-kem-768")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-768-x25519", comp_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.53", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-768-x25519", comp_private_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.53", str(comp_private_key.get_oid()))

        # Outputs
        # ss = SHA3-256(Combined KDF Input)
        ss_expected = "1fa931e383cd072d5df88a42865f1e2c14acac1c2820cfcf76fbbcd2444aadbd"
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
        """Example of id-MLKEM1024-ECDH-P384-HMAC-SHA512 Combiner function output."""
        # Inputs
        mlkemSS = "99308f288ab1c346bc501eca3f8c1c64315e91686e98920a1b97f60368ead216"
        tradSS = "30604eb9718fc42386217d9d9a71a678fea6b2381f4232624f80a9b176b8f2323fe52cc6d477f024cffbea63c143bdb0"
        tradCT = "04e4f92e7dac57d1fe25c833011947e9ab41445392061b419cc75eaf15e2c99615233a806899a092de01a3bc9cba8acf68f31b3c6b157178a8f890b6f268c6ac361d9f14772c60f34873bbea46c9658462b4e99901c688d6edcfac2859706e6791"
        tradPK = "0408a746f5f561013de88c6f549b846002807d250470e6b101185caec9e3917afbe4c7bd00944f9924aaa95859c1030875d5455daabceca59ee3efd838ac6df1da001a4ca317eb518b931aad0489e8b2bc1955cfdd4b4a62686933491d3ff01d3"
        Domain = "060b6086480186fa6b50050239"

        tradPK = (
            "0408a746f5f561013de88c6f549b846002807d250470e6b101185caec9e3a"
            "917afbe4c7bd00944f9924aaa95859c1030875d5455daabceca59ee3efd838ac6df1da"
            "001a4ca317eb518b931aad0489e8b2bc1955cfdd4b4a62686933491d3ff01d3"
        )

        # Combined KDF Input:
        #  mlkemSS || tradSS || tradCT || tradPK || Domain
        combined_kdf_input = mlkemSS + tradSS + tradCT + tradPK + Domain
        trad_key = generate_key("ecdh", curve="secp384r1")
        pq_key = generate_key("ml-kem-1024")
        comp_key = CompositeKEMPublicKey(pq_key=pq_key.public_key(), trad_key=trad_key.public_key())
        self.assertEqual("composite-kem-ml-kem-1024-ecdh-secp384r1", comp_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.57", str(comp_key.get_oid()))
        comp_private_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        self.assertEqual("composite-kem-ml-kem-1024-ecdh-secp384r1", comp_private_key.name)
        self.assertEqual("2.16.840.1.114027.80.5.2.57", str(comp_private_key.get_oid()))
        # Outputs
        # ss = HMAC-SHA512(Combined KDF Input)
        ss_expected = "466c0ca23953241fddfd50a035b24ecb4e9ea66ce91ca3343b270457ecd63bf2"
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
            "id-MLKEM1024-ECDH-P384-HMAC-SHA512 Combiner function output does not match expected value.",
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
            "id-MLKEM1024-ECDH-P384-HMAC-SHA512 Combiner "
            "function output does not match expected value from private key.",
        )


if __name__ == "__main__":
    unittest.main()
