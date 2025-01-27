# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Mapping functions for the Object Identifiers."""

from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from pyasn1.type import univ
from resources.exceptions import InvalidKeyCombination

from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.keys.kem_keys import (
    FrodoKEMPrivateKey,
    FrodoKEMPublicKey,
    McEliecePrivateKey,
    McEliecePublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
)
from pq_logic.tmp_oids import CHEMPAT_NAME_2_OID, COMPOSITE_KEM_NAME_2_OID
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey


def get_oid_for_composite_kem(
    pq_name: str,
    trad_key: Union[x25519.X25519PrivateKey, x448.X448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    length: Optional[int] = None,
    curve_name: Optional[str] = None,
    use_dhkemrfc9180: bool = False,
) -> univ.ObjectIdentifier:
    """Return the OID for a composite KEM combination.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key object.
    :param length: The length of the RSA key.
    :param curve_name: The name of the elliptic curve
    (only needed for negative testing)
    :param use_dhkemrfc9180: Whether to use the DHKEMRFC9180 and not ECDH mechanism.
    :return: The Object Identifier.
    """
    if isinstance(trad_key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        trad_name = f"rsa{length or trad_key.key_size}"

    elif isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve_name or trad_key.curve.name
        trad_name = f"ecdh-{curve_name}"

    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        trad_name = "x25519"

    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        trad_name = "x448"
    else:
        raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")

    prefix = "" if not use_dhkemrfc9180 else "dhkemrfc9180-"

    return COMPOSITE_KEM_NAME_2_OID[f"{prefix}{pq_name}-{trad_name}"]


def get_oid_for_chemnpat(
    pq_key: PQKEMPublicKey, trad_key: Union[ECDHPrivateKey, ECDHPublicKey], curve_name: Optional[str] = None
) -> univ.ObjectIdentifier:
    """Return the OID for a Chempat key combination.

    :param pq_key: The post-quantum key object.
    :param trad_key: The traditional key object.
    :param curve_name: The name of the elliptic curve.
    :return: The Object Identifier.
    :raises InvalidKeyCombination: If the traditional key type or the post-quantum key type is not supported,
    or if the Chempat key combination is not supported.

    """
    curve_name_2_context_name = {
        "secp256r1": "P256",
        "brainpoolP256r1": "brainpoolP256",
        "secp384r1": "P384",
        "brainpoolP384r1": "brainpoolP384",
    }

    if pq_key.name == "sntrup761":
        pq_name = "sntrup761"

    elif isinstance(pq_key, (McEliecePrivateKey, McEliecePublicKey)):
        pq_name = pq_key.name.replace("-", "").lower()
    elif isinstance(pq_key, (MLKEMPrivateKey, MLKEMPublicKey)):
        pq_name = pq_key.name.upper()

    elif isinstance(pq_key, (FrodoKEMPublicKey, FrodoKEMPrivateKey)):
        pq_name = pq_key.name

    else:
        raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat.: {pq_key.name}")

    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve_name or trad_key.curve.name
        trad_name = curve_name_2_context_name[curve_name]

    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        trad_name = "X25519"

    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        trad_name = "X448"
    else:
        raise InvalidKeyCombination(f"Unsupported traditional key type.: {type(trad_key).__name__}")

    try:
        return CHEMPAT_NAME_2_OID[f"Chempat-{trad_name}-{pq_name}"]
    except KeyError:
        raise InvalidKeyCombination(f"Unsupported Chempat key combination: Chempat-{trad_name}-{pq_name}")
