# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#

"""Contain security-related utility functions, like getting the bit string of a used key."""

from typing import Optional

from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from pq_logic.keys.stateful_sig_keys import HSSPublicKey, XMSSMTPublicKey, XMSSPublicKey

# Security strength values follow NIST SP 800-57 Part 1 Revision 5, Tables 2 and 4.
# Table 2 provides the traditional key equivalence for RSA/DSA and ECC key sizes,
# while Table 4 lists the target security strengths for the NIST PQC levels.
_NIST_LEVEL_TO_STRENGTH = {
    1: 128,
    2: 192,
    3: 192,
    4: 256,
    5: 256,
}

HASH_ALG_TO_STRENGTH = {
    "sha1": 80,
    "sha224": 112,
    "sha256": 128,
    "sha384": 192,
    "sha512": 256,
    "sha3_224": 112,
    "sha3_256": 128,
    "sha3_384": 192,
    "sha3_512": 256,
    "shake128": 128,  # Uses in CMP 32 Byte as output size. According to RFC 9481.
    "shake256": 256,  # Uses in CMP 64 Byte as output size. According to RFC 9481.
}


def _rsa_security_strength(key_size: int) -> int:
    """Return an approximate security strength (in bits) for an RSA key size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.
    """
    if key_size < 1024:
        return 64

    if key_size <= 1024:
        return 80

    if key_size <= 2048:
        return 112

    if key_size <= 3072:
        return 128

    if key_size <= 7680:
        return 192

    if key_size <= 15360:
        return 256

    return 256


def _ecc_security_strength(key_size: int) -> int:
    """Return the security strength (in bits) for an ECC-style curve size.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 2.
    """
    # Table 2 (ECC column: f is the field size in bits):
    # - f = 160–223  -> strength 80
    # - f = 224–255  -> strength 112
    # - f = 256–383  -> strength 128
    # - f = 384–511  -> strength 192
    # - f = 512+     -> strength 256
    if key_size <= 223:
        return 80

    if key_size <= 255:
        return 112

    if key_size <= 383:
        return 128

    if key_size <= 511:
        return 192

    return 256


def _get_pq_stfl_nist_security_strength(key: PQHashStatefulSigPublicKey) -> int:
    """Return the PQ security strength (in bits) for a PQ stateful signature key.

    XMSS and XMSS^MT security strength is determined by the hash function output size.
    According to RFC 8391 Section 5. Parameter Sets.
    The security strength is halved when considering PQ security strength, because of the `Grover` algorithm.

    :param key: The PQ stateful signature public key.
    :return: The security strength in bits.
    :raises NotImplementedError: If the key type is not supported.
    """
    if isinstance(key, XMSSPublicKey):
        return key.key_bit_security
    if isinstance(key, XMSSMTPublicKey):
        return key.key_bit_security
    if isinstance(key, HSSPublicKey):
        return key.key_bit_security

    raise NotImplementedError(
        f"Security strength estimation is only implemented for XMSS and XMSSMT keys. Got: {type(key)}"
    )


def _nist_level_strength(level: Optional[int]) -> int:
    """Translate a claimed NIST level into an approximate security strength.

    Mapping follows NIST SP 800-57 Part 1 Rev. 5 Table 4.
    """
    if level is None:
        return 0

    return _NIST_LEVEL_TO_STRENGTH.get(int(level), 0)
