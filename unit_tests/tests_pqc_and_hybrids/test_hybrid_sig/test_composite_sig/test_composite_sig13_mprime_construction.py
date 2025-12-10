# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ

from pq_logic.keys.composite_sig13 import CompositeSig13PrivateKey, CompositeSig13PublicKey
from resources.keyutils import generate_key

EXPECTED_PHM_HEX = (
    "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
    "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
)


class TestMPrimeConstruction(unittest.TestCase):

    Domain_oid = univ.ObjectIdentifier("1.3.6.1.5.5.7.6.45")

    def test_mprime_construction_example1_empty_context(self):
        """
        GIVEN a composite signature with MLDSA65 and ECDSA-P256-SHA512.
        WHEN the M' is constructed with empty context,
        THEN the constructed M' should match the expected value.

        Example of id-MLDSA65-ECDSA-P256-SHA512 construction of M'.
        Inputs:
            M: 00010203040506070809
            ctx: <empty>
        Components of M':
            Prefix: 436f6d706f73697465416c676f726974686d5369676e61747572657332303235
            Label: COMPSIG-MLDSA65-ECDSA-P256-SHA512
            len(ctx): 00
            ctx: <empty>
            PH(M): 0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f
                   202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533
        """
        # Input message and context (hex strings provided by the example)
        # id-MLDSA65-ECDSA-P256-SHA512
        M_hex = "00010203040506070809"

        expected_mprime_hex = (
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235"
            "434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132"
            "00"
            "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
            "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
        )

        # Convert inputs to bytes
        M = bytes.fromhex(M_hex)
        ctx = b""

        trad_key = generate_key("ecdsa", curve="secp256r1")
        pq_key = generate_key("ml-dsa-65")

        composite_key = CompositeSig13PrivateKey(
            pq_key=pq_key,
            trad_key=trad_key,
        )

        m_prime, _ = composite_key._prepare_input(
            data=M,
            ctx=ctx,
            use_pss=False,
        )
        self.assertEqual(m_prime.hex(), expected_mprime_hex)
        _prepared_input = CompositeSig13PublicKey.prepare_sig_input(domain_oid=self.Domain_oid, data=M, ctx=ctx)[0]
        self.assertEqual(m_prime.hex(), _prepared_input.hex())

    def test_mprime_construction_example2_with_context(self):
        """
        GIVEN a composite signature with MLDSA65 and ECDSA-P256-SHA512.
        WHEN the M' is constructed with a non-empty context,
        THEN the constructed M' should match the expected value.

        Example of id-MLDSA65-ECDSA-P256-SHA512 construction of M'.
        Inputs:
            M: 00010203040506070809
            ctx: 0813061205162623
        Components of M':
            Prefix: 436f6d706f73697465416c676f726974686d5369676e61747572657332303235
            Label: COMPSIG-MLDSA65-ECDSA-P256-SHA512
            len(ctx): 08
            ctx: 0813061205162623
            PH(M): 0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f
                   202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533
        """
        # id-MLDSA65-ECDSA-P256-SHA512
        M_hex = "00010203040506070809"
        ctx_hex = "0813061205162623"

        expected_mprime_hex = (
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235"
            "434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132"
            "08"
            "0813061205162623"
            "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f"
            "202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
        )

        trad_key = generate_key("ecdsa", curve="secp256r1")
        pq_key = generate_key("ml-dsa-65")
        composite_key = CompositeSig13PrivateKey(
            pq_key=pq_key,
            trad_key=trad_key,
        )
        # Convert inputs to bytes
        M = bytes.fromhex(M_hex)
        ctx = bytes.fromhex(ctx_hex)

        m_prime, _ = composite_key._prepare_input(
            data=M,
            ctx=ctx,
            use_pss=False,
        )
        self.assertEqual(
            m_prime.hex(),
            expected_mprime_hex,
            "M' construction does not match expected value.",
        )
        _prepared_input = CompositeSig13PublicKey.prepare_sig_input(domain_oid=self.Domain_oid, data=M, ctx=ctx)[0]
        self.assertEqual(expected_mprime_hex, _prepared_input.hex())


if __name__ == "__main__":
    unittest.main()
