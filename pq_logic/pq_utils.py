# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility to handle extra functionality which is only used for "./pq_logic"."""

from typing import Any, Optional, Union, get_args

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPublicKey
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.migration_typing import KEMPrivateKey, KEMPublicKey
from resources.oidutils import PQ_KEM_NAME_2_OID


@not_keyword
def get_kem_oid_from_key(
    key: Union[KEMPublicKey, KEMPrivateKey],
) -> univ.ObjectIdentifier:
    """Get the Object Identifier from the corresponding key and for CompositeKEM keys the matching kdf.

    :param key: The key to get the Object Identifier from.
    :return: The Object Identifier.
    """
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return rfc5990.id_rsa_kem

    if isinstance(key, (PQKEMPublicKey, PQKEMPrivateKey)):
        return PQ_KEM_NAME_2_OID[key.name]

    if isinstance(key, (AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPublicKey)):
        return key.get_oid()

    if isinstance(key, (AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey)):
        return key.get_oid()

    else:
        raise ValueError(f"Invalid KEM key. Got: {type(key).__name__}")


@not_keyword
def is_kem_public_key(key: Any) -> bool:
    """Check whether a parsed key is a KEM public key."""
    allowed_types = get_args(KEMPublicKey)
    if any(isinstance(key, x) for x in allowed_types):
        return True

    return False


@not_keyword
def is_kem_private_key(key: Any) -> bool:
    """Check whether a parsed key is a KEM private key."""
    allowed_types = get_args(KEMPrivateKey)
    if any(isinstance(key, x) for x in allowed_types):
        return True

    return False

@not_keyword
def fetch_value_from_location(location: str) -> Optional[bytes]:
    """Fetch the actual value from a location (e.g., URL) if provided.

    :param location: The URI or location to fetch the value from.
    :return: The fetched value as bytes:
    :raise: ValueError, if the data can not be fetched.
    """
    if not location:
        return None
    try:
        response = requests.get(location)
        response.raise_for_status()
        return response.content
    except Exception as e:
        raise ValueError(f"Failed to fetch value from {location}: {e}")
