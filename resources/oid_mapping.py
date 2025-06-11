# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utilities for working with cryptographic operations and data structures.

Specifically focusing on OID (Object Identifier) mappings for signature and hash algorithms, symmetric and asymmetric
cryptography, and PKI message protections. It includes functions to retrieve OIDs for specific cryptographic
algorithms, create cryptographic instances, and perform lookups between human-readable algorithm names and their
corresponding OIDs.
"""

import logging
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9481
from pyasn1_alt_modules.rfc5480 import id_dsa_with_sha256
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_pq import PQSignaturePrivateKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey
from pq_logic.tmp_oids import (
    CMS_COMPOSITE03_OID_2_HASH,
)
from resources.oidutils import (
    ALL_KNOWN_NAMES_2_OID,
    ALL_KNOWN_OIDS_2_NAME,
    ALLOWED_HASH_TYPES,
    CURVE_NAMES_TO_INSTANCES,
    OID_HASH_MAP,
    OID_HASH_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    SUPPORTED_MAC_NAME_2_OID,
    TRAD_SIG_NAME_2_OID,
)
from resources.typingutils import PrivateKey

KEY_CLASS_MAPPING = {
    "RSAPrivateKey": "rsa",
    "RSAPublicKey": "rsa",
    "EllipticCurvePrivateKey": "ecdsa",
    "EllipticCurvePublicKey": "ecdsa",
    "ECPrivateKey": "ecdsa",
    "ECPublicKey": "ecdsa",
    "DSAPrivateKey": "dsa",
    "DSAPublicKey": "dsa",
    "Ed25519PrivateKey": "ed25519",
    "Ed25519PublicKey": "ed25519",
    "Ed448PrivateKey": "ed448",
    "Ed448PublicKey": "ed448",
    "X25519PrivateKey": "x25519",
    "X25519PublicKey": "x25519",
    "X448PrivateKey": "x448",
    "X448PublicKey": "x448",
}

extra_data = {
    "rsa-sha256-pss": rfc9481.id_RSASSA_PSS,
    "rsa-shake128-pss": rfc9481.id_RSASSA_PSS_SHAKE128,
    "rsa-shake256-pss": rfc9481.id_RSASSA_PSS_SHAKE256,
}


def get_signing_oid(key, hash_alg: Optional[str], use_pss: bool = False) -> Optional[univ.ObjectIdentifier]:
    """Retrieve the OID for a signature algorithm based on the key and hash algorithm.

    :param key: The private key instance.
    :param hash_alg: The hash algorithm to map to the signature OID.
    :param use_pss: Whether to use RSA-PSS padding. Default is `False`.
    :return: The OID of the signature algorithm or `None` if not found.
    """
    oid = None
    type_name = key.__class__.__name__
    key_type = KEY_CLASS_MAPPING.get(type_name, "")
    if hash_alg is not None:
        name = key_type + "-" + hash_alg
        if use_pss and key_type == "rsa":
            name += "-pss"
        oid = extra_data.get(name)

    else:
        name = key_type

    if oid is not None:
        return oid

    if key_type in TRAD_SIG_NAME_2_OID:
        return TRAD_SIG_NAME_2_OID[key_type]

    return OID_HASH_NAME_2_OID.get(name) or SUPPORTED_MAC_NAME_2_OID.get(key_type)


@not_keyword
def sha_alg_name_to_oid(hash_name: str) -> univ.ObjectIdentifier:
    """Perform a lookup for the provided hash name.

    :param hash_name: A string representing the hash name to look up. Example hash names could be "sha256"
                      or "hmac-sha256"
    :return: The corresponding `pyasn1` OID.
    """
    hash_name = hash_name.lower().strip()

    if hash_name in OID_HASH_MAP.values():
        for key, value in OID_HASH_MAP.items():
            if hash_name == value:
                return key

    raise ValueError(f"Hash name is not supported: {hash_name}")


@not_keyword
def get_curve_instance(curve_name: str) -> ec.EllipticCurve:
    """Retrieve an instance of an elliptic curve based on its name.

    :param curve_name: A string name of the elliptic curve to retrieve.
    :raises ValueError: If the specified curve name is not supported.
    :return: `cryptography.hazmat.primitives.ec` EllipticCurve instance.
    """
    if curve_name not in CURVE_NAMES_TO_INSTANCES:
        raise ValueError(f"The Curve: {curve_name} is not Supported!")

    return CURVE_NAMES_TO_INSTANCES[curve_name]


@not_keyword
def get_hash_from_oid(oid: univ.ObjectIdentifier, only_hash: bool = False) -> Union[str, None]:
    """Determine the name of a hashing function used in a signature algorithm given by its oid.

    Note: If only a hash name is needed, set `only_hash` to `True`, unless only a hash name is contained in the OID.
    Then use `only_hash=False`.

    :param oid: `pyasn1 univ.ObjectIdentifier`, OID of signing algorithm
    :param only_hash: A flag indicating if only the hash name shall be returned if one is contained.
    :return: The name of the hashing algorithm, e.g., 'sha256' or `None`, if the
    signature algorithm does not use one.
    """
    if oid in {rfc9481.id_Ed25519, rfc9481.id_Ed448}:
        return None

    if oid in CMS_COMPOSITE03_OID_2_HASH:
        return CMS_COMPOSITE03_OID_2_HASH[oid]

    try:
        if oid in PQ_SIG_PRE_HASH_OID_2_NAME:
            return PQ_SIG_PRE_HASH_OID_2_NAME[oid].split("-")[-1]

        if oid in PQ_OID_2_NAME:
            return None

        return OID_HASH_MAP[oid] if not only_hash else OID_HASH_MAP[oid].split("-")[1]
    except KeyError as err:
        name = may_return_oid_to_name(oid)
        raise ValueError(
            f"Unknown signature algorithm OID {oid}: {name}, check OID_HASH_MAP in cryptoutils.py"
        ) from err


@not_keyword
def hash_name_to_instance(alg: str) -> hashes.HashAlgorithm:
    """Return an instance of a hash algorithm object based on its name.

    :param alg: The name of hashing algorithm, e.g., 'sha256'
    :return: `cryptography.hazmat.primitives.hashes`
    :raises ValueError: If the specified hash algorithm is not supported.
    """
    try:
        # to also get the hash function with rsa-sha1 and so on.
        if "-" in alg:
            return ALLOWED_HASH_TYPES[alg.split("-")[1]]

        return ALLOWED_HASH_TYPES[alg]
    except KeyError as err:
        raise ValueError(f"Unsupported hash algorithm: {alg}") from err


@not_keyword
def get_alg_oid_from_key_hash(
    key: PrivateKey, hash_alg: Optional[str], use_rsa_pss: bool = False, use_pre_hash: bool = False
) -> univ.ObjectIdentifier:
    """Find the pyasn1 oid given the hazmat key instance and a name of a hashing algorithm.

    Only used for single key algorithms, not for composite keys.

    :param key: The private key instance.
    :param hash_alg: Name of hashing algorithm, e.g., 'sha256'
    :param use_rsa_pss: Flag to use RSA-PSS padding. Default is False.
    :param use_pre_hash: Flag to use prehashed key. Default is False.
    :return: The OID of the signature algorithm.
    """
    if isinstance(key, dsa.DSAPrivateKey):
        logging.info("Remember to only use with Negative Testing!")
        if hash_alg == "sha256":
            return id_dsa_with_sha256
        raise ValueError("DSA is only allowed with sha256!")

    alg_oid = get_signing_oid(key, hash_alg, use_pss=use_rsa_pss)

    if isinstance(key, PQSignaturePrivateKey) and alg_oid is None:
        hash_alg = key.check_hash_alg(hash_alg)

        name = key.name
        if hash_alg is not None:
            name += "-" + hash_alg

        return PQ_NAME_2_OID[name]

    from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey

    if isinstance(key, CompositeSig03PrivateKey):
        alg_oid = key.get_oid(use_pss=use_rsa_pss, pre_hash=use_pre_hash)

    if isinstance(key, PQHashStatefulSigPrivateKey):
        return key.get_oid()

    if alg_oid is not None:
        return alg_oid

    raise ValueError(f"Unsupported signature algorithm for ({type(key).__name__}, {hash_alg})")


@not_keyword
def compute_hash(alg_name: str, data: bytes) -> bytes:
    """Calculate the hash of data using an algorithm given by its name.

    :param alg_name: The Name of algorithm, e.g., 'sha256', see HASH_NAME_OBJ_MAP.
    :param data: The buffer we want to hash.
    :return: The resulting hash.
    :raises ValueError: If the specified hash algorithm is not supported.
    """
    hash_class = hash_name_to_instance(alg_name)
    digest = hashes.Hash(hash_class)
    digest.update(data)
    return digest.finalize()


@not_keyword
def may_return_oid_to_name(oid: univ.ObjectIdentifier) -> str:
    """Check if the oid is Known and then returns a human-readable representation, or the dotted string.

    :param oid: The OID to perform the lookup for.
    :return: Either a human-readable name or the OID as dotted string.
    """
    out = ALL_KNOWN_OIDS_2_NAME.get(oid)
    if out is not None:
        return out
    return ALL_KNOWN_OIDS_2_NAME.get(str(oid), str(oid))


@not_keyword
def may_return_oid_by_name(name: str) -> univ.ObjectIdentifier:
    """Check if the name is Known and then returns the OID, or the dotted string.

    :param name: The name to perform the lookup for or a dotted string.
    :return: The OID.
    :raises KeyError: If the name is not found in the OID mapping.
    """
    if "." in name:
        return univ.ObjectIdentifier(name)
    return ALL_KNOWN_NAMES_2_OID[name]
