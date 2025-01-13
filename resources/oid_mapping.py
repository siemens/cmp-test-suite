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
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, rsa
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey
from pq_logic.tmp_oids import (
    CMS_COMPOSITE_OID_2_HASH,
    id_MLKEM768_ECDH_brainpoolP256r1,
    id_MLKEM768_ECDH_P384,
    id_MLKEM768_RSA2048,
    id_MLKEM768_RSA3072,
    id_MLKEM768_RSA4096,
    id_MLKEM768_X25519,
    id_MLKEM1024_ECDH_brainpoolP384r1,
    id_MLKEM1024_ECDH_P384,
    id_MLKEM1024_X448,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9481
from pyasn1_alt_modules.rfc5480 import id_dsa_with_sha256
from robot.api.deco import not_keyword

from resources.oidutils import (
    ALL_KNOWN_PROTECTION_OIDS,
    ALLOWED_HASH_TYPES,
    CURVE_NAMES_TO_INSTANCES,
    OID_HASH_MAP,
    OID_HASH_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    SUPPORTED_MAC_NAME_2_OID,
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
        if use_pss:
            name += "-pss"
        oid = extra_data.get(name)

    else:
        name = key_type
    return oid or OID_HASH_NAME_2_OID.get(name) or SUPPORTED_MAC_NAME_2_OID.get(key_type)


@not_keyword
def sha_alg_name_to_oid(hash_name: str) -> univ.ObjectIdentifier:
    """Perform a lookup for the provided hash name.

    :param hash_name: A string representing the hash name to look up. Example hash names could be "sha256"
                      or "hmac-sha256"
    :return: The corresponding `pyasn1` OID.
    """
    hash_name = hash_name.lower().replace("_", "-").strip()

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

    :param oid: `pyasn1 univ.ObjectIdentifier`, OID of signing algorithm
    :param only_hash: A flag indicating if only the hash name shall be returned if one is contained.
    :return: name of hashing algorithm, e.g., 'sha256' or `None`, if the
    signature algorithm does not use one.
    """
    if oid in {rfc9481.id_Ed25519, rfc9481.id_Ed448}:
        return None

    if oid in CMS_COMPOSITE_OID_2_HASH:
        return CMS_COMPOSITE_OID_2_HASH[oid]


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
    """
    try:
        # to also get the hash function with rsa-sha1 and so on.
        if "-" in alg:
            return ALLOWED_HASH_TYPES[alg.split("-")[1]]

        return ALLOWED_HASH_TYPES[alg]
    except KeyError as err:
        raise ValueError(f"Unsupported hash algorithm: {alg}") from err


def get_oid_composite(
    ml_kem_name: str, trad_key: Union[ed448.Ed448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
):
    """Get the OID for a composite key based on the ML-KEM name and the traditional key.

    :param ml_kem_name:
    :param trad_key:
    :return:
    """
    oid_mapping = {
        ("MLKEM768", rsa.RSAPrivateKey): {
            2048: id_MLKEM768_RSA2048,
            3072: id_MLKEM768_RSA3072,
            4096: id_MLKEM768_RSA4096,
        },
        ("MLKEM768", ec.EllipticCurvePrivateKey): {
            "secp384r1": id_MLKEM768_ECDH_P384,
            "brainpoolP256r1": id_MLKEM768_ECDH_brainpoolP256r1,
        },
        ("MLKEM768", ed448.Ed448PrivateKey): id_MLKEM768_X25519,
        ("MLKEM1024", ec.EllipticCurvePrivateKey): {
            "secp384r1": id_MLKEM1024_ECDH_P384,
            "brainpoolP384r1": id_MLKEM1024_ECDH_brainpoolP384r1,
        },
        ("MLKEM1024", ed448.Ed448PrivateKey): id_MLKEM1024_X448,
    }

    # Determine the traditional key type and retrieve the corresponding OID
    if isinstance(trad_key, rsa.RSAPrivateKey):
        key_size = trad_key.key_size
        return oid_mapping.get((ml_kem_name, rsa.RSAPrivateKey), {}).get(key_size, None)
    if isinstance(trad_key, ec.EllipticCurvePrivateKey):
        curve_name = trad_key.curve.name
        return oid_mapping.get((ml_kem_name, ec.EllipticCurvePrivateKey), {}).get(curve_name, None)
    if isinstance(trad_key, ed448.Ed448PrivateKey):
        return oid_mapping.get((ml_kem_name, ed448.Ed448PrivateKey), None)

    raise ValueError("Unsupported traditional key type.")


@not_keyword
def get_rsa_pss_oid(hash_alg: str = "sha256") -> univ.ObjectIdentifier:
    """Get the RSA-PSS key hash OID for the given hash algorithm.

    :param hash_alg: The hash algorithm to map to the RSA-PSS signature OID.
    Supported values: "shake128", "shake256". Default is "sha256".
    (`id-RSASSA-PSS`)
    :return: None or the matching ObjectIdentifier.
    """
    if hash_alg == "shake128":
        alg_oid = rfc9481.id_RSASSA_PSS_SHAKE128
    elif hash_alg == "shake256":
        alg_oid = rfc9481.id_RSASSA_PSS_SHAKE256
    else:
        alg_oid = rfc9481.id_RSASSA_PSS

    return alg_oid


@not_keyword
def get_rsa_key_hash_oid(hash_alg: str, use_pss: bool = False) -> Optional[univ.ObjectIdentifier]:
    """Get the RSA key hash OID for the given hash algorithm.

    :param hash_alg: str, the hash algorithm to map to the RSA signature OID.
    Supported values: "sha256", "sha384", "sha512".
    :return: None or the matching ObjectIdentifier.
    """
    if use_pss:
        return get_rsa_pss_oid(hash_alg=hash_alg)

    alg_oid = None
    if hash_alg == "sha256":
        alg_oid = rfc9481.sha256WithRSAEncryption
    elif hash_alg == "sha384":
        alg_oid = rfc9481.sha384WithRSAEncryption
    elif hash_alg == "sha512":
        alg_oid = rfc9481.sha512WithRSAEncryption

    return alg_oid


@not_keyword
def get_ec_key_hash_oid(hash_alg: str):
    """Get the ECDSA key hash OID for the given hash algorithm.

    :param hash_alg: str, the hash algorithm to map to the ECDSA signature OID.
    Supported values: "sha256", "sha384", "sha512".
    :return: None or the matching ObjectIdentifier.
    """
    alg_oid = None
    if hash_alg == "sha256":
        alg_oid = rfc9481.ecdsa_with_SHA256
    elif hash_alg == "sha384":
        alg_oid = rfc9481.ecdsa_with_SHA384
    elif hash_alg == "sha512":
        alg_oid = rfc9481.ecdsa_with_SHA512
    elif hash_alg == "shake128":
        alg_oid = rfc9481.id_ecdsa_with_shake128
    elif hash_alg == "shake256":
        alg_oid = rfc9481.id_ecdsa_with_shake256

    return alg_oid


@not_keyword
def get_alg_oid_from_key_hash(
    key: PrivateKey, hash_alg: str, use_pss: bool = False, use_prehashed: bool = False
) -> univ.ObjectIdentifier:
    """Find the pyasn1 oid given the hazmat key instance and a name of a hashing algorithm.

    Only used for single key algorithms, not for composite keys.

    :param key: The private key instance.
    :param hash_alg: Name of hashing algorithm, e.g., 'sha256'
    :param use_pss: Flag to use RSA-PSS padding. Default is False.
    :param use_prehashed: Flag to use prehashed key. Default is False.
    :return: The OID of the signature algorithm.
    """
    if isinstance(key, dsa.DSAPrivateKey):
        logging.info("Remember to only use with Negative Testing!")
        if hash_alg == "sha256":
            return id_dsa_with_sha256
        raise ValueError("DSA is only allowed with sha256!")

    alg_oid = get_signing_oid(key, hash_alg, use_pss=use_pss)

    if isinstance(key, PQSignaturePrivateKey) and alg_oid is None:

        hash_alg = key.check_hash_alg(hash_alg)

        name = key.name
        if hash_alg is not None:
            name += "-" + hash_alg

        return PQ_NAME_2_OID[name]

    # if isinstance(key, AbstractCompositeSigPrivateKey):
    #    alg_oid = key.get_oid(used_padding=use_pss, prehash=use_prehashed)

    if alg_oid is not None:
        return alg_oid

    raise ValueError(f"Unsupported signature algorithm for ({type(key).__name__}, {hash_alg})")


@not_keyword
def compute_hash(alg_name: str, data: bytes) -> bytes:
    """Calculate the hash of data using an algorithm given by its name.

    :param alg_name: The Name of algorithm, e.g., 'sha256', see HASH_NAME_OBJ_MAP.
    :param data: The buffer we want to hash.
    :return: The resulting hash.
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
    return ALL_KNOWN_PROTECTION_OIDS.get(oid, str(oid))
