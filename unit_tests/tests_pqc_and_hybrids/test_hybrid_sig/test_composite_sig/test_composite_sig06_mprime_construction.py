# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.composite_sig06 import CompositeSig06PrivateKey
from resources.keyutils import generate_key

EXPECTED_PHM_HEX = (
    "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
    "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
)


class TestMPrimeConstruction(unittest.TestCase):
    def test_mprime_construction_example1(self):
        """
        GIVEN a composite signature with MLDSA65 and ECDSA-P256-SHA512.
        WHEN the M' is constructed using the provided example values,
        THEN the constructed M' should match the expected value.
        """
        # Input message and context (hex strings provided by the example)
        # id-MLDSA65-ECDSA-P256-SHA512
        M_hex = "00010203040506070809"
        ctx_hex = "0813061205162623"
        r_hex = "9bc35bce21615ae424cd61c1d677104e35e832d0146e3dca41d52fc942d1b713"

        expected_mprime_hex = (
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235"
            "060b6086480186fa6b50090108"
            "08"
            "0813061205162623"
            "9bc35bce21615ae424cd61c1d677104e35e832d0146e3dca41d52fc942d1b713"
            "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
            "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
        )

        # Convert inputs to bytes
        M = bytes.fromhex(M_hex)
        ctx = bytes.fromhex(ctx_hex)
        r = bytes.fromhex(r_hex)

        trad_key = generate_key("ecdsa", curve="secp256r1")
        pq_key = generate_key("ml-dsa-65")

        composite_key = CompositeSig06PrivateKey(
            trad_key=trad_key,
            pq_key=pq_key,
        )

        m_prime = composite_key._prepare_input(
            data=M,
            ctx=ctx,
            rand=r,
            use_pss=False,
        )
        self.assertEqual(m_prime.hex(), expected_mprime_hex)

    def test_mprime_construction_example2(self):
        """
        GIVEN a composite signature with MLDSA65 and ECDSA-P256-SHA512.
        WHEN the M' is constructed using the provided example values,
        THEN the constructed M' should match the expected value.
        """
        # id-MLDSA65-ECDSA-P256-SHA512
        M_hex = "00010203040506070809"
        ctx_hex = "0813061205162623"
        r_hex = "9bc35bce21615ae424cd61c1d677104e35e832d0146e3dca41d52fc942d1b713"
        expected_mprime_hex = (
            "436f6d706f73697465416c676f726974686d5369676e6174757265733230323506"
            "0b6086480186fa6b500901080808130612051626239bc35bce21615ae424cd61c1d677"
            "104e35e832d0146e3dca41d52fc942d1b7130f89ee1fcb7b0a4f7809d1267a02971900"
            "4c5a5e5ec323a7c3523a20974f9a3f202f56fadba4cd9e8d654ab9f2e96dc5c795ea17"
            "6fa20ede8d854c342f903533"
        )
        trad_key = generate_key("ecdsa", curve="secp256r1")
        pq_key = generate_key("ml-dsa-65")
        composite_key = CompositeSig06PrivateKey(
            trad_key=trad_key,
            pq_key=pq_key,
        )
        # Convert inputs to bytes
        M = bytes.fromhex(M_hex)
        ctx = bytes.fromhex(ctx_hex)
        r = bytes.fromhex(r_hex)
        m_prime = composite_key._prepare_input(
            data=M,
            ctx=ctx,
            rand=r,
            use_pss=False,
        )
        self.assertEqual(
            m_prime.hex(),
            expected_mprime_hex,
            "M' construction does not match expected value.",
        )


if __name__ == "__main__":
    unittest.main()
