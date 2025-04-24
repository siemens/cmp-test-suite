# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility to handle extra functionality which is only used for "./pq_logic"."""

from typing import Any, Union

from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey, HybridKEMPublicKey, KEMPrivateKey, KEMPublicKey
from resources.oidutils import KEM_NAME_2_OID


@not_keyword
def get_kem_oid_from_key(
    key: Union[KEMPublicKey, KEMPrivateKey],
) -> univ.ObjectIdentifier:
    """Get the Object Identifier from the corresponding key and for CompositeKEM keys the matching kdf.

    :param key: The key to get the Object Identifier from.
    :return: The Object Identifier.
    """
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return rfc5990.id_kem_rsa

    if isinstance(key, (PQKEMPublicKey, PQKEMPrivateKey)):
        return KEM_NAME_2_OID[key.name]

    if isinstance(key, (HybridKEMPrivateKey, HybridKEMPublicKey)):
        return key.get_oid()

    raise ValueError(f"Invalid KEM key. Got: {type(key).__name__}")


@not_keyword
def is_kem_public_key(key: Any) -> bool:
    """Check whether a parsed key is a KEM public key."""
    return isinstance(key, KEMPublicKey)


@not_keyword
def is_kem_private_key(key: Any) -> bool:
    """Check whether a parsed key is a KEM private key."""
    return isinstance(key, KEMPrivateKey)
