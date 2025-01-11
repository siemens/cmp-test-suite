# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from pyasn1.type import univ

from pq_logic.tmp_oids import FALCON_HYBRID_NAME_2_OID, id_CompSig

NUMBER_MAP = {
    "ml-dsa-44-rsa2048-pss": 1,
    "ml-dsa-44-rsa2048": 2,
    "ml-dsa-44-ed25519": 3,
    "ml-dsa-44-ecdsa-secp256r1": 4,
    "ml-dsa-44-ecdsa-brainpoolp256r1-sha256": 5,
    "ml-dsa-65-rsa3072-pss": 6,
    "ml-dsa-65-rsa3072": 7,
    "ml-dsa-65-ecdsa-secp256r1": 8,
    "ml-dsa-65-ecdsa-brainpoolp256r1": 9,
    "ml-dsa-65-ed25519": 10,
    "ml-dsa-87-ecdsa-secp384r1": 11,
    "ml-dsa-87-ecdsa-brainpoolp384r1-sha512": 12,
    "ml-dsa-87-ed448": 13,
}

id_MLDSA44_RSA2048_PSS = univ.ObjectIdentifier(f"{id_CompSig}.21")
id_MLDSA44_RSA2048_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.22")
id_MLDSA44_Ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.23")
id_MLDSA44_ECDSA_P256 = univ.ObjectIdentifier(f"{id_CompSig}.24")
id_MLDSA65_RSA3072_PSS = univ.ObjectIdentifier(f"{id_CompSig}.26")
id_MLDSA65_RSA3072_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.27")
id_MLDSA65_RSA4096_PSS = univ.ObjectIdentifier(f"{id_CompSig}.34")
id_MLDSA65_RSA4096_PKCS15 = univ.ObjectIdentifier(f"{id_CompSig}.35")
id_MLDSA65_ECDSA_P384 = univ.ObjectIdentifier(f"{id_CompSig}.28")
id_MLDSA65_ECDSA_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_CompSig}.29")
id_MLDSA65_Ed25519 = univ.ObjectIdentifier(f"{id_CompSig}.30")
id_MLDSA87_ECDSA_P384 = univ.ObjectIdentifier(f"{id_CompSig}.31")
id_MLDSA87_ECDSA_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_CompSig}.32")
id_MLDSA87_Ed448 = univ.ObjectIdentifier(f"{id_CompSig}.33")

NEW_COMPOSITE_SIG_OID_2_OLD_OID = {
    id_MLDSA44_RSA2048_PSS: univ.ObjectIdentifier(f"{id_CompSig}.1"),
    id_MLDSA44_RSA2048_PKCS15: univ.ObjectIdentifier(f"{id_CompSig}.2"),
    id_MLDSA44_Ed25519: univ.ObjectIdentifier(f"{id_CompSig}.3"),
    id_MLDSA44_ECDSA_P256: univ.ObjectIdentifier(f"{id_CompSig}.4"),
    id_MLDSA65_RSA3072_PSS: univ.ObjectIdentifier(f"{id_CompSig}.6"),
    id_MLDSA65_RSA3072_PKCS15: univ.ObjectIdentifier(f"{id_CompSig}.7"),
    id_MLDSA65_ECDSA_brainpoolP256r1: univ.ObjectIdentifier(f"{id_CompSig}.9"),
    id_MLDSA65_Ed25519: univ.ObjectIdentifier(f"{id_CompSig}.10"),
    id_MLDSA87_ECDSA_P384: univ.ObjectIdentifier(f"{id_CompSig}.11"),
    id_MLDSA87_ECDSA_brainpoolP384r1: univ.ObjectIdentifier(f"{id_CompSig}.12"),
    id_MLDSA87_Ed448: univ.ObjectIdentifier(f"{id_CompSig}.13"),
}


HASH_ALGORITHM_MAP = {
    "ml-dsa-44-rsa2048-pss": "sha256",
    "ml-dsa-44-rsa2048": "sha256",
    "ml-dsa-44-ed25519": "sha512",
    "ml-dsa-44-ecdsa-secp256r1": "sha256",
    "ml-dsa-44-ecdsa-brainpoolp256r1-sha256": "sha256",
    "ml-dsa-65-rsa3072-pss": "sha512",
    "ml-dsa-65-rsa3072": "sha512",
    "ml-dsa-65-ecdsa-secp256r1": "sha512",
    "ml-dsa-65-ecdsa-brainpoolp256r1": "sha512",
    "ml-dsa-65-ed25519": "sha512",
    "ml-dsa-87-ecdsa-secp384r1": "sha512",
    "ml-dsa-87-ecdsa-brainpoolp384r1-sha512": "sha512",
    "ml-dsa-87-ed448": "sha512",
}

ecdsa_curve_map = {
    "ml-dsa-44-ecdsa-secp256r1": "secp256r1",
    "ml-dsa-44-ecdsa-brainpoolp256r1": "brainpoolP256r1",
    "ml-dsa-65-ecdsa-secp256r1": "secp256r1",
    "ml-dsa-65-ecdsa-brainpoolp256r1": "brainpoolP256r1",
    "ml-dsa-87-ecdsa-secp384r1": "secp384r1",
    "ml-dsa-87-ecdsa-brainpoolp384r1": "brainpoolP384r1",
}

composite_alg_info = {}


def prepare_map():
    """Prepare the mapping of composite entries to OIDs and algorithm info."""
    for name, idx in NUMBER_MAP.items():
        hash_name = HASH_ALGORITHM_MAP[name]
        oid_add = univ.ObjectIdentifier(f"{id_CompSig}.{idx}")

        pq_name = next((variant for variant in ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] if variant in name), None)

        parts = name.split("-")
        trad_parts = parts[3:-1]
        trad_name = "-".join(trad_parts) if trad_parts else None

        composite_alg_info[oid_add] = {
            "name": name,
            "hash_alg": hash_name,
            "curve_name": ecdsa_curve_map.get(name),
            "ml_dsa_name": pq_name,
            "trad_alg_name": trad_name,
        }


prepare_map()

composite_name_2_oid = {v["name"]: oid for oid, v in composite_alg_info.items()}

composite_name_to_hash_fun = {
    "ml-dsa-44": {
        "rsa2048-pss": "sha256",
        "rsa2048": "sha256",
        "ed25519": "sha512",
        "ecdsa-secp256r1": "sha256",
        "ecdsa-brainpoolp256r1": "sha256",
    },
    "ml-dsa-65": {
        "rsa3072-pss": "sha512",
        "rsa3072": "sha512",
        "ecdsa-secp256r1": "sha512",
        "ecdsa-brainpoolp256r1": "sha512",
        "ed25519": "sha512",
    },
    "ml-dsa-87": {
        "ecdsa-secp384r1": "sha512",
        "ecdsa-brainpoolp384r1": "sha512",
        "ed448": "sha512",
    },
    "falcon-512": {
        "rsa3072": "sha256",
        "ecdsa-secp256r1": "sha256",
    },
    "falcon-padded-512": {
        "rsa3072": "sha256",
        "ecdsa-secp256r1": "sha256",
    },
    "falcon-1024": {
        "ecdsa-secp512r1": "sha512",
    },
    "falcon-padded-1024": {
        "ecdsa-secp512r1": "sha512",
    },
}


def _get_trad_name(
    trad_key: Union[
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        rsa.RSAPrivateKey,
        rsa.RSAPublicKey,
        ed25519.Ed25519PrivateKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PrivateKey,
        ed448.Ed448PublicKey,
    ],
    use_padding: bool = False,
    curve: Optional[str] = None,
) -> str:
    """Retrieve the traditional algorithm name based on the key type."""
    if isinstance(trad_key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        actual_curve = curve or trad_key.curve.name
        return f"ecdsa-{actual_curve}"
    if isinstance(trad_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        trad_name = f"rsa{trad_key.key_size}"
        return f"{trad_name}-pss" if use_padding else trad_name
    if isinstance(trad_key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ed25519"
    if isinstance(trad_key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "ed448"
    raise ValueError(f"Unsupported key type: {type(trad_key).__name__}.")


def get_hash_name(pq_name: str, trad_key, use_padding: bool = False) -> str:
    """Get the hash name for the given composite key combination."""
    trad_name = _get_trad_name(trad_key, use_padding=use_padding)
    return composite_name_to_hash_fun[pq_name].get(trad_name)


def get_composite_sig_oid(pq_name: str, trad_key, use_padding: bool = False) -> univ.ObjectIdentifier:
    """Retrieve the Object Identifier for a composite signature algorithm using a composite key combination."""
    trad_name = _get_trad_name(trad_key, use_padding=use_padding)
    comp_name = f"{pq_name}-{trad_name}"

    tmp = comp_name + "-pkcs15"
    if tmp in FALCON_HYBRID_NAME_2_OID:
        return FALCON_HYBRID_NAME_2_OID[tmp]

    if comp_name in FALCON_HYBRID_NAME_2_OID:
        return FALCON_HYBRID_NAME_2_OID[comp_name]

    return composite_name_2_oid[comp_name]
