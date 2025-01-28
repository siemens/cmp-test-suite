# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains stats information for the hybrid ciphertext length."""
from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519

from pq_logic.trad_typing import ECDHPrivateKey

TRAD_ALG_2_NENC = {"brainpoolP384": 97, "P256": 65, "brainpoolP256": 65, "X448": 56, "X25519": 32, "P384": 97}

CURVE_NAME_2_CONTEXT_NAME = {
    "secp256r1": "P256",
    "brainpoolP256r1": "brainpoolP256",
    "secp384r1": "P384",
    "brainpoolP384r1": "brainpoolP384",
}


def get_ec_trad_name(trad_key: Union[ECDHPrivateKey, ECDHPrivateKey]) -> str:
    """Return the traditional name to generate the context string"""
    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = CURVE_NAME_2_CONTEXT_NAME[trad_key.curve.name]
    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        name = "X448"
    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        name = "X25519"
    else:
        raise ValueError("Unsupported key type.")
    return name


def get_ct_length_for_trad_key(key: Union[ECDHPrivateKey, ECDHPrivateKey]) -> int:
    """Get the ciphertext length for traditional keys.

    :param key: The traditional key for which to get the ciphertext length.
    :return: The ciphertext length for the specified key.
    """
    name = get_ec_trad_name(key)
    return TRAD_ALG_2_NENC[name]


def get_trad_key_length(key: Union[ECDHPrivateKey, ECDHPrivateKey, rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> int:
    """Return the key size of the traditional key.

    :param key: The traditional key for which to get the key size.
    :return: The key size of the specified key.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return key.key_size
    else:
        return TRAD_ALG_2_NENC[get_ec_trad_name(key)]
