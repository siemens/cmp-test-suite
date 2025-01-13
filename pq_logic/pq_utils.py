# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Union, get_args

from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5990
from resources.oidutils import PQ_KEM_NAME_2_OID
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPublicKey
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, KEMPrivateKey, KEMPublicKey


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
        raise ValueError(f"Invalid key type: {type(key).__name__}")


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
    allowed_types = get_args(HybridKEMPrivateKey)
    if any(isinstance(key, x) for x in allowed_types):
        return True

    return False
