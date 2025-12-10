# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""All stateful hash signature keys.

Currently supported:
- XMSS (eXtended Merkle Signature Scheme)
- XMSSMT (eXtended Merkle Signature Scheme with Multiple Trees)

"""

import importlib.util
import logging
import math
from typing import Dict, List, Optional, Sequence, Tuple, Union

import pyhsslms
from cryptography.exceptions import InvalidSignature
from pyhsslms.pyhsslms import LenI
from pyhsslms.pyhsslms import lmots_params as PYHSSLMS_LMOTS_PARAMS
from pyhsslms.pyhsslms import lms_params as PYHSSLMS_LMS_PARAMS

from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from resources.exceptions import InvalidKeyData

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name


XMSS_ALG_DETAILS = {
    "xmss-sha2_10_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 10},
    "xmss-sha2_16_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 16},
    "xmss-sha2_20_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 20},
    "xmss-sha2_10_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 10},
    "xmss-sha2_16_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 16},
    "xmss-sha2_20_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 20},
    "xmss-shake_10_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 10},
    "xmss-shake_16_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 16},
    "xmss-shake_20_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20},
    "xmss-shake_10_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 10},
    "xmss-shake_16_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 16},
    "xmss-shake_20_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20},
    "xmss-sha2_10_192": {"hash_alg": "sha256", "n": 24, "w": 16, "len": 67, "h": 10},
    "xmss-sha2_16_192": {"hash_alg": "sha256", "n": 24, "w": 16, "len": 67, "h": 16},
    "xmss-sha2_20_192": {"hash_alg": "sha256", "n": 24, "w": 16, "len": 67, "h": 20},
    "xmss-shake_10_192": {"hash_alg": "shake128", "n": 24, "w": 16, "len": 67, "h": 10},
    "xmss-shake_16_192": {"hash_alg": "shake128", "n": 24, "w": 16, "len": 67, "h": 16},
    "xmss-shake_20_192": {"hash_alg": "shake128", "n": 24, "w": 16, "len": 67, "h": 20},
    "xmss-shake256_10_192": {"hash_alg": "shake256", "n": 24, "w": 16, "len": 67, "h": 10},
    "xmss-shake256_16_192": {"hash_alg": "shake256", "n": 24, "w": 16, "len": 67, "h": 16},
    "xmss-shake256_20_192": {"hash_alg": "shake256", "n": 24, "w": 16, "len": 67, "h": 20},
    "xmss-shake256_10_256": {"hash_alg": "shake256", "n": 32, "w": 16, "len": 67, "h": 10},
    "xmss-shake256_16_256": {"hash_alg": "shake256", "n": 32, "w": 16, "len": 67, "h": 16},
    "xmss-shake256_20_256": {"hash_alg": "shake256", "n": 32, "w": 16, "len": 67, "h": 20},
}

XMSSMT_ALG_DETAILS = {
    # XMSS^MT parameter sets
    "xmssmt-sha2_20/2_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 20, "d": 2},
    "xmssmt-sha2_20/4_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 20, "d": 4},
    "xmssmt-sha2_40/2_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 2},
    "xmssmt-sha2_40/4_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 4},
    "xmssmt-sha2_40/8_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 40, "d": 8},
    "xmssmt-sha2_60/3_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 3},
    "xmssmt-sha2_60/6_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 6},
    "xmssmt-sha2_60/12_256": {"hash_alg": "sha256", "n": 32, "w": 16, "len": 67, "h": 60, "d": 12},
    "xmssmt-sha2_20/2_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 20, "d": 2},
    "xmssmt-sha2_20/4_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 20, "d": 4},
    "xmssmt-sha2_40/2_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 2},
    "xmssmt-sha2_40/4_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 4},
    "xmssmt-sha2_40/8_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 40, "d": 8},
    "xmssmt-sha2_60/3_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 3},
    "xmssmt-sha2_60/6_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 6},
    "xmssmt-sha2_60/12_512": {"hash_alg": "sha512", "n": 64, "w": 16, "len": 131, "h": 60, "d": 12},
    "xmssmt-shake_20/2_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20, "d": 2},
    "xmssmt-shake_20/4_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 20, "d": 4},
    "xmssmt-shake_40/2_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 2},
    "xmssmt-shake_40/4_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 4},
    "xmssmt-shake_40/8_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 40, "d": 8},
    "xmssmt-shake_60/3_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 3},
    "xmssmt-shake_60/6_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 6},
    "xmssmt-shake_60/12_256": {"hash_alg": "shake128", "n": 32, "w": 16, "len": 67, "h": 60, "d": 12},
    "xmssmt-shake_20/2_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20, "d": 2},
    "xmssmt-shake_20/4_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 20, "d": 4},
    "xmssmt-shake_40/2_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 2},
    "xmssmt-shake_40/4_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 4},
    "xmssmt-shake_40/8_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 40, "d": 8},
    "xmssmt-shake_60/3_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 3},
    "xmssmt-shake_60/6_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 6},
    "xmssmt-shake_60/12_512": {"hash_alg": "shake256", "n": 64, "w": 16, "len": 131, "h": 60, "d": 12},
}

lmots_algorithm_type_dict = {
    "lmots_sha256_n32_w1": b"\x00\x00\x00\x01",
    "lmots_sha256_n32_w2": b"\x00\x00\x00\x02",
    "lmots_sha256_n32_w4": b"\x00\x00\x00\x03",
    "lmots_sha256_n32_w8": b"\x00\x00\x00\x04",
    "lmots_sha256_n24_w1": b"\x00\x00\x00\x05",
    "lmots_sha256_n24_w2": b"\x00\x00\x00\x06",
    "lmots_sha256_n24_w4": b"\x00\x00\x00\x07",
    "lmots_sha256_n24_w8": b"\x00\x00\x00\x08",
    "lmots_shake_n32_w1": b"\x00\x00\x00\x09",
    "lmots_shake_n32_w2": b"\x00\x00\x00\x0a",
    "lmots_shake_n32_w4": b"\x00\x00\x00\x0b",
    "lmots_shake_n32_w8": b"\x00\x00\x00\x0c",
    "lmots_shake_n24_w1": b"\x00\x00\x00\x0d",
    "lmots_shake_n24_w2": b"\x00\x00\x00\x0e",
    "lmots_shake_n24_w4": b"\x00\x00\x00\x0f",
    "lmots_shake_n24_w8": b"\x00\x00\x00\x10",
}

lms_algorithm_type_dict = {
    "lms_sha256_m32_h5": b"\x00\x00\x00\x05",
    "lms_sha256_m32_h10": b"\x00\x00\x00\x06",
    "lms_sha256_m32_h15": b"\x00\x00\x00\x07",
    "lms_sha256_m32_h20": b"\x00\x00\x00\x08",
    "lms_sha256_m32_h25": b"\x00\x00\x00\x09",
    "lms_sha256_m24_h5": b"\x00\x00\x00\x0a",
    "lms_sha256_m24_h10": b"\x00\x00\x00\x0b",
    "lms_sha256_m24_h15": b"\x00\x00\x00\x0c",
    "lms_sha256_m24_h20": b"\x00\x00\x00\x0d",
    "lms_sha256_m24_h25": b"\x00\x00\x00\x0e",
    "lms_shake_m32_h5": b"\x00\x00\x00\x0f",
    "lms_shake_m32_h10": b"\x00\x00\x00\x10",
    "lms_shake_m32_h15": b"\x00\x00\x00\x11",
    "lms_shake_m32_h20": b"\x00\x00\x00\x12",
    "lms_shake_m32_h25": b"\x00\x00\x00\x13",
    "lms_shake_m24_h5": b"\x00\x00\x00\x14",
    "lms_shake_m24_h10": b"\x00\x00\x00\x15",
    "lms_shake_m24_h15": b"\x00\x00\x00\x16",
    "lms_shake_m24_h20": b"\x00\x00\x00\x17",
    "lms_shake_m24_h25": b"\x00\x00\x00\x18",
}

lms_id_2_algorithm_type_dict = {y: x for x, y in lms_algorithm_type_dict.items()}
lmots_id_2_algorithm_type_dict = {y: x for x, y in lmots_algorithm_type_dict.items()}

# More information at:
# https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml

LMS_NAMES: Sequence[str] = (
    "lms_sha256_m24_h5",
    "lms_sha256_m24_h10",
    "lms_sha256_m24_h15",
    "lms_sha256_m24_h20",
    "lms_sha256_m24_h25",
    "lms_sha256_m32_h5",
    "lms_sha256_m32_h10",
    "lms_sha256_m32_h15",
    "lms_sha256_m32_h20",
    "lms_sha256_m32_h25",
    "lms_shake_m24_h5",
    "lms_shake_m24_h10",
    "lms_shake_m24_h15",
    "lms_shake_m24_h20",
    "lms_shake_m24_h25",
    "lms_shake_m32_h5",
    "lms_shake_m32_h10",
    "lms_shake_m32_h15",
    "lms_shake_m32_h20",
    "lms_shake_m32_h25",
)

LMOTS_NAMES: Sequence[str] = (
    "lmots_sha256_n24_w1",
    "lmots_sha256_n24_w2",
    "lmots_sha256_n24_w4",
    "lmots_sha256_n24_w8",
    "lmots_sha256_n32_w1",
    "lmots_sha256_n32_w2",
    "lmots_sha256_n32_w4",
    "lmots_sha256_n32_w8",
    "lmots_shake_n24_w1",
    "lmots_shake_n24_w2",
    "lmots_shake_n24_w4",
    "lmots_shake_n24_w8",
    "lmots_shake_n32_w1",
    "lmots_shake_n32_w2",
    "lmots_shake_n32_w4",
    "lmots_shake_n32_w8",
)


def _collect_pyhsslms_types(names: Sequence[str]) -> Dict[str, bytes]:
    """Collect type codes from the ``pyhsslms`` module for known constant names."""
    values: Dict[str, bytes] = {}
    for name in names:
        value = getattr(pyhsslms, name)
        if not isinstance(value, (bytes, bytearray)) or len(value) != 4:
            raise ValueError(f"Unexpected pyhsslms constant shape for {name}")
        values[name] = bytes(value)
    return values


PYHSS_LMS_TYPES: Dict[str, bytes] = _collect_pyhsslms_types(LMS_NAMES)
PYHSS_LMOTS_TYPES: Dict[str, bytes] = _collect_pyhsslms_types(LMOTS_NAMES)

PYHSS_LMS_NAME_BY_CODE: Dict[bytes, str] = {value: name for name, value in PYHSS_LMS_TYPES.items()}
PYHSS_LMOTS_NAME_BY_CODE: Dict[bytes, str] = {value: name for name, value in PYHSS_LMOTS_TYPES.items()}


def _build_hss_algorithms() -> Dict[str, Dict[str, int]]:
    """Build metadata for all supported HSS parameter sets."""
    algorithms: Dict[str, Dict[str, int]] = {}
    for lms_name, lms_code in PYHSS_LMS_TYPES.items():
        hash_alg, m, h = PYHSSLMS_LMS_PARAMS[lms_code]
        for lmots_name, lmots_code in PYHSS_LMOTS_TYPES.items():
            lmots_hash, n, p, w, _ = PYHSSLMS_LMOTS_PARAMS[lmots_code]
            if lmots_hash != hash_alg or n != m:
                continue
            name = f"hss_{lms_name}_{lmots_name}"
            lmots_sig_len = 4 + n * (p + 1)
            lms_sig_len = 4 + lmots_sig_len + 4 + h * m
            lms_pub_len = 8 + LenI + m
            algorithms[name] = {
                "hash_alg": hash_alg,
                "lms_type_py": lms_code,
                "lmots_type_py": lmots_code,
                "tree_height": h,
                "word_size": w,
                "n": n,
                "lmots_signature_length": lmots_sig_len,
                "lms_signature_length": lms_sig_len,
                "lms_public_key_length": lms_pub_len,
                "max_per_tree": 2**h,
            }
    return algorithms


HSS_ALGORITHM_DETAILS = _build_hss_algorithms()
DEFAULT_HSS_ALGORITHM = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"


def _convert_to_liboqs_lms_name(details: Dict[str, Union[str, int]]) -> Optional[str]:
    """Return the `liboqs` LMS identifier for the provided parameter set."""
    hash_alg = details.get("hash_alg")
    n = details.get("n")
    height = details.get("tree_height")
    word_size = details.get("word_size")

    if not isinstance(hash_alg, str) or hash_alg.lower() != "sha256":
        return None
    if n != 32 or not isinstance(height, int) or not isinstance(word_size, int):
        return None

    return f"LMS_SHA256_H{height}_W{word_size}"


def _get_hss_name_to_oqs_name() -> Dict[str, str]:
    """Build a mapping from HSS algorithm names to liboqs LMS identifiers."""
    name_map: Dict[str, str] = {}
    if oqs is None:
        return name_map

    for name, details in HSS_ALGORITHM_DETAILS.items():
        oqs_name = _convert_to_liboqs_lms_name(details)
        if oqs_name is not None and oqs_name in oqs.get_enabled_stateful_sig_mechanisms():
            name_map[name] = oqs_name
    return name_map


LIBOQS_LMS_NAME_BY_ALG = _get_hss_name_to_oqs_name()


def _get_and_chck_hss_name(name: str) -> str:
    """Check and normalize the provided HSS algorithm name."""
    if not name:
        return DEFAULT_HSS_ALGORITHM
    normalized = name.lower()
    if normalized == "hss":
        normalized = DEFAULT_HSS_ALGORITHM
    return normalized


def _compute_hss_signature_length(details: Dict[str, int], levels: int) -> int:
    """Compute the serialized signature length for the given details and hierarchy depth."""
    # TODO fix, if needed for different LMS and LMOTS key types.
    per_sig = details["lms_signature_length"]
    per_pub = details["lms_public_key_length"]
    return 4 + max(levels - 1, 0) * (per_sig + per_pub) + per_sig


def compute_hss_signature_index(signature: bytes, key: Union["HSSPrivateKey", "HSSPublicKey"]) -> int:
    """Return the global HSS signature index and the encoded depth."""
    # TODO fix, if needed for different LMS and LMOTS key types.
    details = HSS_ALGORITHM_DETAILS.get(key.name)
    if details is None:
        raise ValueError(f"Unsupported HSS algorithm: {key.name}")

    try:
        hss_sig = pyhsslms.HssSignature.deserialize(signature)
    except ValueError as exc:  # pragma: no cover - library validation
        raise ValueError("Malformed HSS signature") from exc

    max_per_tree = details["max_per_tree"]
    indices = [sig_part.q for sig_part in hss_sig.sig]
    indices.append(hss_sig.lms_sig.q)

    if len(indices) != hss_sig.levels:
        raise InvalidSignature(
            f"HSS signature level mismatch: expected {hss_sig.levels}, found {len(indices)} indices",
        )

    total_index = 0
    for value in indices:
        if value >= max_per_tree:
            raise InvalidSignature(
                f"LMS index {value} exceeds tree capacity {max_per_tree - 1} for {key.name}",
            )
        total_index = total_index * max_per_tree + value

    if key.levels != hss_sig.levels:
        raise InvalidSignature(
            f"Signature encodes {hss_sig.levels} levels but key expects {key.levels}",
        )

    return total_index


def build_hss_name_from_codes(lms_type: bytes, lmots_type: bytes) -> str:
    """Return the canonical algorithm name for the provided LMS/LMOTS type codes."""
    lms_name = PYHSS_LMS_NAME_BY_CODE.get(lms_type)
    lmots_name = PYHSS_LMOTS_NAME_BY_CODE.get(lmots_type)

    # Check LMS identifier
    if lms_name is None:
        lms_id = int.from_bytes(lms_type, "big")
        # Private use range: 0xFF000000 to 0xFFFFFFFF (RFC 8554)
        if 0xFF000000 <= lms_id <= 0xFFFFFFFF:
            raise InvalidKeyData(
                f"The LMS identifier 0x{lms_type.hex()} is not set inside the code as Private use algorithm. "
                f"Either update the code base or fix your id setting."
            )
        # Unassigned identifier
        raise InvalidKeyData(
            f"The LMS identifier 0x{lms_type.hex()} is unassigned or unsupported. "
            f"Check RFC 8554 for valid LMS type codes."
        )

    # Check LMOTS identifier
    if lmots_name is None:
        lmots_id = int.from_bytes(lmots_type, "big")
        # Private use range: 0xFF000000 to 0xFFFFFFFF (RFC 8554)
        if 0xFF000000 <= lmots_id <= 0xFFFFFFFF:
            raise InvalidKeyData(
                f"The LMOTS identifier 0x{lmots_type.hex()} is not set inside the code as Private use algorithm. "
                f"Either update the code base or fix your id setting."
            )
        # Unassigned identifier
        raise InvalidKeyData(
            f"The LMOTS identifier 0x{lmots_type.hex()} is unassigned or unsupported. "
            f"Check RFC 8554 for valid LMOTS type codes."
        )

    name = f"hss_{lms_name}_{lmots_name}"
    if name not in HSS_ALGORITHM_DETAILS:
        raise InvalidKeyData(f"Unsupported HSS parameter combination inside the key data. Got: {name}")
    return name


def _xmss_liboqs_sk_to_pk(sk: bytes, name: str = "XMSS-SHA2_10_256") -> bytes:
    """Extract root||PUB_SEED from a liboqs-exported XMSS or XMSS-MT secret key.

    XMSS Format is: ID(4) || index(4) || SK_SEED(n) || SK_PRF(n) || PUB_SEED(n) || root(n)

    :param sk: secret key bytes from liboqs
    :param name: name of the XMSS or XMSS-MT algorithm, e.g. "XMSS-SHA2_20/2_256" or "XMSSMT-SHA2_20/2_256"
    :return: public key bytes in the format OID(4) || PUB_SEED(n) || root(n)
    """
    hdr = 8  # 4-byte OID + 4-byte index
    oid = sk[0:4]  # OID, unused here

    if not name.upper().startswith("XMSS-") and not name.upper().startswith("XMSSMT-"):
        raise ValueError(f"Variant must start with 'XMSS-' or 'XMSSMT-'. Got: {name}")

    num = name.split("_")[-1]  # e.g. "XMSSMT-SHA2_20/2_256" -> 32
    n = int(num) // 8

    if name.upper().startswith("XMSSMT"):
        root_off, pub_seed_off = hdr + 2 * n, hdr + 3 * n
    else:
        start = 8 + 2 * n
        return oid + sk[start : start + n] + sk[start + n : start + 2 * n]

    h = XMSSMT_ALG_DETAILS[name.lower()]["h"]
    offset2 = math.ceil(h / 8) - 4
    root_off += offset2
    pub_seed_off += offset2
    # for XMSSMT, the public key is constructed as:
    # OID(4) || root(n) || PUB_SEED(n)
    # For "60/6" "60/3" "60/12" plus 4.
    # For "20/2" "20/4" minus 1.
    # For "40/2" "40/4" "40/8" plus 1.
    return oid + sk[root_off : root_off + n] + sk[pub_seed_off : pub_seed_off + n]


class XMSSPublicKey(PQHashStatefulSigPublicKey):
    """Class representing an XMSS public key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSS private key."""
        return b"XMSS"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmss":
            name = "xmss-sha2_20_256"
        if name.upper() not in XMSS_ALG_IDS.values():
            raise ValueError(f"Unsupported XMSS algorithm: {name}")
        return name, name.upper()

    def _initialize_key(self):
        """Initialize the XMSS public key with the provided name and public key bytes."""
        if len(self._public_key_bytes) != self.key_size:
            msg = (
                f"Invalid public key size for {self.name}: expected {self.key_size + 4}, "
                f"got {len(self._public_key_bytes)}"
            )
            raise InvalidKeyData(msg)
        self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the XMSS signature."""
        # The first 4 bytes of XMSS signature indicate the leaf index.
        if len(signature) != self.sig_size:
            raise ValueError(f"Invalid XMSS signature size: expected {self.sig_size}, got {len(signature)}")
        return int.from_bytes(signature[:4], "big")

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes):
        """Set the public key bytes from the provided bytes."""
        name = data[:4]
        alg_id = int.from_bytes(name, "big")
        if alg_id not in XMSS_ALG_IDS:
            raise InvalidKeyData(f"Unsupported XMSS algorithm ID: {alg_id}")
        return cls(XMSS_ALG_IDS[alg_id].upper(), data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the signature against the data using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        if not self._sig.verify(message=data, signature=signature, public_key=self._public_key_bytes):
            raise InvalidSignature("XMSS Signature verification failed")

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSS public key."""
        h = int(self.name.split("_")[1])
        return 2**h - 1

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this XMSS public key."""
        # public_key_size = n (seed) + n (root) = 2 ⋅ n
        # details = XMSS_ALG_DETAILS[self.name.lower()]
        # n = details["n"]
        hash_num = self.name.split("_")[-1]  # Extract the hash algorithm and parameters
        n = int(hash_num) // 8
        return 2 * n + 4  # 4 bytes for the algorithm identifier

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSSMT public key."""
        # 4+n+(l+h)n
        # Where:
        # 4: Algorithm identifier size
        # n: Hash output size
        # h: Height of the tree
        # l: Winternitz parameter
        # details = XMSS_ALG_DETAILS[self.name.lower()]
        # n = details["n"]  # Hash output size
        # height = details["h"]  # Height of the tree
        # length = details["len"]  # Winternitz parameter
        # return 4 + n + (length + height) * n
        return self._sig.length_signature

    @property
    def hash_alg(self) -> str:
        """Return the hash algorithm used by this XMSS public key."""
        # Different name formats for XMSS:
        # - xmss-sha2_10_256
        # - xmss-shake256_10_256
        # - xmss-shake_10_256
        if self.name.startswith("xmss-shake_"):
            output_size = int(self.name.split("_")[-1])
            if output_size == 256:
                return "shake128"
            if output_size == 512:
                return "shake256"
            return "shake128"
        return XMSS_ALG_DETAILS[self.name.lower()]["hash_alg"]

    @property
    def key_bit_security(self) -> int:
        """Return the traditional bit security of the XMSS public key."""
        # Approximate bit security based on the hash output size
        return int(self.name.split("_")[-1]) // 2


class XMSSPrivateKey(PQHashStatefulSigPrivateKey):
    """Class representing an XMSS private key."""

    _sig: Optional["oqs.StatefulSignature"]

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSS private key."""
        return b"XMSS"

    def public_key(self) -> XMSSPublicKey:
        """Return the corresponding public key for this XMSS private key."""
        if self._public_key_bytes is None:
            self._public_key_bytes = _xmss_liboqs_sk_to_pk(self._sig.export_secret_key(), self._other_name)
        return XMSSPublicKey(self._name, public_key=self._public_key_bytes)

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmss":
            name = "xmss-sha2_10_256"
        if name.upper() not in XMSS_ALG_IDS.values():
            msg = f"Unsupported XMSS algorithm: {name}"
            raise ValueError(msg)

        return name, name.upper()

    def _initialize_key(self):
        """Initialize the XMSS private key with the provided name and private key bytes."""
        if self._private_key_bytes is not None:
            self._sig = oqs.StatefulSignature(self._other_name, secret_key=self._private_key_bytes)  # type: ignore
            if len(self._private_key_bytes) != self.key_size:
                msg = (
                    f"Invalid private key size for {self.name}: expected {self.key_size}, "
                    f"got {len(self._private_key_bytes)}"
                )
                raise InvalidKeyData(msg)
        else:
            self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
            self._public_key_bytes = self._sig.generate_keypair()
            self._private_key_bytes = self._sig.export_secret_key()

    def private_numbers(self) -> bytes:
        """Return the private key as bytes.

        Returns the seed used to derive the private key:
        - 4 bytes for the algorithm identifier
        - 4 bytes for the current leaf counter.
        - 3 * n bytes for the seed, where n is the hash output size.
        - n for the root hash.

        :return: The private key seed bytes.
        """
        n = XMSS_ALG_DETAILS[self.name.lower()]["n"]
        return self._sig.export_secret_key()[: 4 + 4 * n]

    @classmethod
    def from_private_bytes(cls, data: bytes):
        """Set the private key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        # Only support XMSS used by OQS, the seed derivation is not implemented.
        # Starts with:
        # 4 bytes for the algorithm identifier
        # 4 bytes for the current leaf counter.
        # n-bytes (hash output size) for the seed.
        # SK_SEED(n) || SK_PRF(n) || PUB_SEED(n) || root(n)
        # The total length is 4 + 4 + 3 * n, where n is the hash output size.
        # Afterwards follows the BDS traversal cache,
        # otherwise would the size be a lot bigger.
        name = XMSS_ALG_IDS.get(alg_id)
        n = int(name.split("_")[-1]) // 8 if name else None
        if name is None:
            raise InvalidKeyData(f"Unsupported XMSS algorithm ID: {alg_id}")
        if len(data) < 4 + 3 * n:
            raise InvalidKeyData(f"Invalid private key size for {name}: expected at least {4 + 3 * n}, got {len(data)}")
        if len(data) == 4 + 3 * n:
            raise NotImplementedError("Derivation of the private from a seed is not implemented yet.")
        return cls(XMSS_ALG_IDS[alg_id], data)

    def _change_index(self, new_index: int) -> "XMSSPrivateKey":
        """Change the index of the private key.

        :param new_index: The new index to set.
        """
        private_key_bytes = self.private_bytes_raw()
        oid = private_key_bytes[:4]  # Algorithm identifier
        # Extract the current index (4 bytes after the OID)
        current_index = int.from_bytes(private_key_bytes[4:8], "big")
        if current_index == new_index:
            return self

        return XMSSPrivateKey(
            alg_name=self.name,
            private_bytes=oid + new_index.to_bytes(4, "big") + private_key_bytes[8:],
            public_key=self.public_key().public_bytes_raw(),
        )

    def sign(self, data: bytes) -> bytes:
        """Sign the data using the private key.

        :param data: The data to sign.
        :return: The signature of the data.
        """
        return self._sig.sign(data)

    @property
    def used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()

    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""
        return self._sig.export_secret_key()

    def private_bytes_raw(self) -> bytes:
        """Return the raw private key bytes."""
        return self._export_private_key()

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this XMSS private key."""
        return self._sig.sigs_remaining()

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSS private key."""
        return self._sig.sigs_total()

    @property
    def key_size(self) -> int:
        """Return the size of the private key for this XMSS private key."""
        return self._sig.details["length_secret_key"]

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSS private key."""
        return self._sig.length_signature


class XMSSMTPublicKey(PQHashStatefulSigPublicKey):
    """Class representing an XMSSMT public key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSSMT public key."""
        return b"XMSSMT"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmssmt":
            name = "xmssmt-sha2_20/2_256"
        if name.upper() not in XMSSMT_ALG_IDS.values():
            raise ValueError(f"Unsupported XMSS^MT algorithm: {name}")
        return name, name.upper()

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    def _initialize_key(self):
        """Initialize the XMSS public key with the provided name and public key bytes."""
        self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
        if len(self._public_key_bytes) != self.key_size:
            msg = (
                f"Invalid public key size for {self.name}: expected {self.key_size + 4}, "
                f"got {len(self._public_key_bytes)}"
            )
            raise InvalidKeyData(msg)

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the XMSSMT signature.

        :param signature: The XMSSMT signature to extract the leaf index from.
        :return: The leaf index extracted from the signature.
        """
        if len(signature) < 4:
            raise ValueError("Invalid XMSSMT signature: too short")

        # According to RFC 8391 Section 4.2.3.  XMSS^MT Signature.
        length = math.ceil(self.tree_height / 8)
        # The leaf index is stored as a big-endian integer
        return int.from_bytes(signature[:length], "big")  # Ensure it's a valid integer

    @classmethod
    def from_public_bytes(cls, data: bytes):
        """Set the public key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        _name = XMSSMT_ALG_IDS[alg_id]
        key_size = XMSSMT_ALG_DETAILS[_name.lower()]["n"] * 2
        if len(data) != key_size + 4:
            raise InvalidKeyData(f"Invalid public key size for {_name}: expected {key_size + 4}, got {len(data)}")
        if alg_id not in XMSSMT_ALG_IDS:
            raise InvalidKeyData(f"Unsupported XMSSMT algorithm ID: {alg_id}")
        return cls(XMSSMT_ALG_IDS[alg_id], data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the signature against the data using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        if not self._sig.verify(message=data, signature=signature, public_key=self._public_key_bytes):
            raise InvalidSignature("XMSS^MT Signature verification failed")

    def get_used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSSMT public key."""
        h = XMSSMT_ALG_DETAILS[self.name.lower()]["h"]
        return 2**h - 1

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSSMT public key."""
        # Where:
        # 4: Algorithm identifier size
        # n: Hash output size
        # h: Height of the tree
        # l: Winternitz parameter
        # d: Number of trees in the forest.
        # details = XMSSMT_ALG_DETAILS[self.name.lower()]
        # n = details["n"]
        # height = details["h"]
        # length = details["len"]
        # d = details["d"]
        # return math.ceil(height / 8) + n + (height + d * length) * n
        return self._sig.length_signature

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this XMSSMT public key."""
        return self._sig.details["length_public_key"]

    @property
    def tree_height(self) -> int:
        """Return the Merkle tree height for this key."""
        # name format: "xmssmt-sha2_20/2_256"
        return int(self.name.split("_")[1].split("/")[0])  # e.g. "20/2" -> 20

    @property
    def layers(self) -> int:
        """Return the number of XMSSMT layers."""
        # name format: "xmssmt-sha2_20/2_256"
        return int(self.name.split("_")[1].split("/")[1])  # e.g. "20/2" -> 2

    @property
    def hash_alg(self) -> str:
        """Return the hash algorithm used by this XMSSMT public key."""
        return XMSSMT_ALG_DETAILS[self.name.lower()]["hash_alg"]

    @property
    def key_bit_security(self) -> int:
        """Return the pq bit security of the XMSSMT public key."""
        # Approximate bit security based on the hash output size
        return XMSSMT_ALG_DETAILS[self.name.lower()]["n"] * 4


class XMSSMTPrivateKey(PQHashStatefulSigPrivateKey):
    """Class representing an XMSSMT private key."""

    def _get_header_name(self) -> bytes:
        """Return the header name for the XMSSMT private key."""
        return b"XMSSMT"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name.

        :param name: The name of the XMSS public key.
        :return: A tuple containing the algorithm name and the public key bytes.
        """
        name = name.lower()
        if name == "xmssmt":
            name = "xmssmt-sha2_20/2_256"
        if name not in XMSSMT_ALG_DETAILS:
            raise ValueError(f"Unsupported XMSS^MT algorithm: {name}")
        return name.lower(), name.upper()

    def _initialize_key(self):
        """Initialize the XMSSMT private key with the provided name and private key bytes."""
        if self._private_key_bytes is not None:
            self._sig = oqs.StatefulSignature(self._other_name, secret_key=self._private_key_bytes)  # type: ignore
            if len(self._private_key_bytes) != self.key_size:
                msg = (
                    f"Invalid private key size for {self.name}: expected {self.key_size}, "
                    f"got {len(self._private_key_bytes)}"
                )
                raise InvalidKeyData(msg)
        else:
            self._sig = oqs.StatefulSignature(self._other_name)  # type: ignore
            self._public_key_bytes = self._sig.generate_keypair()
            self._private_key_bytes = self._sig.export_secret_key()

    def public_key(self) -> XMSSMTPublicKey:
        """Return the corresponding public key for this XMSSMT private key."""
        if self._public_key_bytes is None:
            self._public_key_bytes = _xmss_liboqs_sk_to_pk(self._sig.export_secret_key(), self._other_name)
        return XMSSMTPublicKey(self._name, public_key=self._public_key_bytes)

    def sign(self, data: bytes) -> bytes:
        """Sign the data using the private key.

        :param data: The data to sign.
        :return: The signature of the data.
        """
        return self._sig.sign(data)

    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""
        return self._sig.export_secret_key()

    def private_bytes_raw(self) -> bytes:
        """Return the raw private key bytes."""
        return self._export_private_key()

    @classmethod
    def from_private_bytes(cls, data: bytes):
        """Set the private key bytes from the provided bytes."""
        alg_id = int.from_bytes(data[:4], "big")
        return cls(XMSSMT_ALG_IDS[alg_id], data)

    @property
    def key_size(self) -> int:
        """Return the size of the private key for this XMSSMT private key."""
        return self._sig.details["length_secret_key"]

    @property
    def max_sig_size(self) -> int:
        """Return the maximum size of the signature for this XMSSMT private key."""
        return self._sig.sigs_total()

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this XMSSMT private key."""
        return self._sig.sigs_remaining()

    @property
    def used_keys(self) -> list[bytes]:
        """Return the list of used keys during signing."""
        return self._sig.export_used_keys()

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this XMSS private key."""
        return self._sig.length_signature

    @property
    def tree_height(self) -> int:
        """Return the height of the tree for this XMSSMT private key."""
        return self.public_key().tree_height

    @property
    def layers(self) -> int:
        """Return the number of layers in the XMSSMT tree."""
        return self.public_key().layers

    def _change_index(self, new_index: int) -> "XMSSMTPrivateKey":
        """Change the index of the public key.

        :param new_index: The new index to set.
        """
        private_key_bytes = self.private_bytes_raw()
        oid = private_key_bytes[:4]
        index_size = math.ceil(self.tree_height / 8)
        new_index_bytes = new_index.to_bytes(index_size, "big")
        return XMSSMTPrivateKey(
            alg_name=self.name,
            private_bytes=oid + new_index_bytes + private_key_bytes[4 + index_size :],
            public_key=self.public_key().public_bytes_raw(),
        )


class HSSPublicKey(PQHashStatefulSigPublicKey):
    """Representation of an HSS public key."""

    def __init__(self, alg_name: str, public_key: bytes):
        """Initialize the HSS public key.

        :param alg_name: The name of the HSS algorithm.
        :param public_key: The public key bytes.
        """
        self._details: Dict[str, Union[str, int]] = {}
        self._levels = 0
        self._hss_pub: Optional[pyhsslms.HssPublicKey]
        self._sig: Optional["oqs.StatefulSignature"] = None
        super().__init__(alg_name, public_key)

    def _get_header_name(self) -> bytes:
        """Return the header name for the HSS public key."""
        return b"HSS"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name."""
        normalized = _get_and_chck_hss_name(name)
        details = HSS_ALGORITHM_DETAILS.get(normalized)
        if details is None:
            raise ValueError(f"Unsupported HSS algorithm: {name}")
        self._details = details
        return normalized, normalized

    def _initialize_key(self):
        """Initialize the HSS public key with the provided name and public key bytes."""
        try:
            self._hss_pub = pyhsslms.HssPublicKey.deserialize(self._public_key_bytes)
        except ValueError as e:
            raise InvalidKeyData("Failed to parse HSS public key bytes.") from e
        expected_len = 4 + self._details["lms_public_key_length"]
        if len(self._public_key_bytes) != expected_len:
            raise InvalidKeyData(
                f"Invalid HSS public key size for {self.name}: expected {expected_len}, "
                f"got {len(self._public_key_bytes)}"
            )
        self._levels = self._hss_pub.levels
        root_pub = self._hss_pub.pub
        canonical = build_hss_name_from_codes(root_pub.lms_type, root_pub.lmots_type)
        if canonical != self._name:
            raise InvalidKeyData(
                "The LMS/LMOTS types embedded in the HSS public key do not match the requested algorithm."
            )

        if oqs is not None and self._can_verify_with_ops():
            self._sig = oqs.StatefulSignature(self._convert_hss_name_to_oqs())  # type: ignore

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "HSSPublicKey":
        """Load an HSS public key from the provided bytes."""
        hss_pub = pyhsslms.HssPublicKey.deserialize(data)
        root_pub = hss_pub.pub
        lms_params = PYHSSLMS_LMS_PARAMS.get(root_pub.lms_type)
        lmots_params = PYHSSLMS_LMOTS_PARAMS.get(root_pub.lmots_type)
        try:
            name = build_hss_name_from_codes(root_pub.lms_type, root_pub.lmots_type)
        except InvalidKeyData:
            if lms_params and lmots_params:
                lms_hash, m, _ = lms_params
                lmots_hash, n, p, w, ls = lmots_params
                if lms_hash != lmots_hash or m != n:
                    logging.info(
                        "HSS public key LMS/LMOTS mismatch: LMS hash=%s digest=%d vs LMOTS hash=%s digest=%d. "
                        "LMOTS parameters: %s",
                        lms_hash,
                        m,
                        lmots_hash,
                        n,
                        {
                            "hash_alg": lmots_hash,
                            "n": n,
                            "p": p,
                            "w": w,
                            "ls": ls,
                        },
                    )
            raise
        return cls(name, data)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Verify the HSS signature using the public key.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        :raises InvalidSignature: If the signature is invalid.
        """
        if self._hss_pub is None:
            raise InvalidKeyData("The HSS public key is not initialised.")
        try:
            if self._can_verify_with_ops():
                self._verify_with_oqs(data, signature)
                return

            if not self._hss_pub.verify(data, signature):
                raise InvalidSignature("HSS signature verification failed")
        except ValueError as exc:
            raise InvalidSignature("Malformed HSS signature") from exc

    def _convert_hss_name_to_oqs(self) -> str:
        """Translate the internal algorithm name into the liboqs identifier.

        :return: The liboqs algorithm name for this HSS key.
        :raises InvalidKeyData: If the HSS parameter set is not supported by liboqs.
        """
        if self.name not in LIBOQS_LMS_NAME_BY_ALG:
            raise InvalidKeyData(f"The HSS parameter set {self.name} is not supported by the liboqs LMS provider.")
        return LIBOQS_LMS_NAME_BY_ALG[self.name]

    def _verify_with_oqs(self, data: bytes, signature: bytes) -> None:
        """Verify the HSS signature using the oqs provider.

        :param data: The data to verify the signature against.
        :param signature: The signature to verify.
        """
        if oqs is None:
            raise InvalidSignature("The oqs backend is not available for HSS verification.")

        sig = oqs.StatefulSignature(self._convert_hss_name_to_oqs())

        if len(signature) != self.sig_size:
            raise InvalidSignature(f"Signature size mismatch: expected {self.sig_size}, got {len(signature)}")

        if not sig.verify(message=data, signature=signature, public_key=self._public_key_bytes):
            raise InvalidSignature("HSS Signature verification failed")

    def _can_verify_with_ops(self) -> bool:
        """Return whether ops-backed verification is supported for this key.

        The ops provider only exposes SHA-2 based parameter sets, so SHAKE
        variants must fall back to the software verifier.
        """
        return self.name in LIBOQS_LMS_NAME_BY_ALG and self.levels < 9

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the HSS signature."""
        try:
            hss_sig = pyhsslms.HssSignature.deserialize(signature)
        except ValueError as exc:  # pragma: no cover - library validation
            raise ValueError("Malformed HSS signature") from exc
        return hss_sig.lms_sig.q

    @property
    def max_sig_size(self) -> int:
        """Return the maximum number of signatures supported by this HSS key."""
        # TODO fix, if needed for different LMS and LMOTS key types.
        return self._hss_pub.maxSignatures()

    @property
    def key_size(self) -> int:
        """Return the size of the public key for this HSS key."""
        return len(self._public_key_bytes)

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this HSS key."""
        return _compute_hss_signature_length(self._details, self._levels)

    @property
    def hash_alg(self) -> str:
        """Return the hash algorithm used by the HSS key."""
        return self._details["hash_alg"]

    @property
    def levels(self) -> int:
        """Return the number of LMS layers used by the HSS key."""
        return self._levels

    def get_level_names(self) -> Sequence[Tuple[str, str]]:
        """Return the LMS and LMOTS parameter names for each level of the HSS key."""
        # TODO fix for multiple levels with different parameters.
        # Extract LMS and LMOTS type codes from the root public key
        root_pub = self._hss_pub.pub
        lms_type_code = root_pub.lms_type
        lmots_type_code = root_pub.lmots_type

        # Convert type codes to canonical parameter names
        lms_name = PYHSS_LMS_NAME_BY_CODE.get(lms_type_code)
        lmots_name = PYHSS_LMOTS_NAME_BY_CODE.get(lmots_type_code)

        if lms_name is None:
            raise InvalidKeyData(f"Unrecognized LMS type code in HSS public key: 0x{lms_type_code.hex()}")
        if lmots_name is None:
            raise InvalidKeyData(f"Unrecognized LMOTS type code in HSS public key: 0x{lmots_type_code.hex()}")

        # In the current implementation, all levels use the same LMS/LMOTS parameters
        # Return a list with the same pair repeated for each level
        num_levels = self.levels
        levels = [(lms_name, lmots_name)] * num_levels
        return levels

    @property
    def key_bit_security(self) -> int:
        """Return the key bit security of this HSS key."""
        # TODO fix for multiple levels with different parameters.
        n = self._details["n"]
        if n == 24:
            return 96
        return 128


class HSSPrivateKey(PQHashStatefulSigPrivateKey):
    """Representation of an HSS private key."""

    def __init__(
        self,
        alg_name: str,
        private_bytes: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        levels: Optional[int] = None,
    ):
        """Initialize a HSS private key.

        :param alg_name: The name of the HSS algorithm.
        :param private_bytes: The bytes of the private key to use.
        :param public_key: The public key bytes to use. Defaults to `None`.
        :param levels: The number of LMS layers to use. Defaults to `None`.
        """
        self._requested_levels = int(levels) if levels is not None else None
        self._details: Dict[str, int] = {}
        self._hss: Optional[pyhsslms.HssPrivateKey] = None
        self._levels = 0
        self._used_signatures: List[bytes] = []
        super().__init__(
            alg_name=alg_name,
            private_bytes=private_bytes,
            public_key=public_key,
        )

    def _get_header_name(self) -> bytes:
        """Return the header name for the HSS private key."""
        return b"HSS"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid and return the algorithm name and the `liboqs` equivalent, if possible."""
        normalized = _get_and_chck_hss_name(name)
        details = HSS_ALGORITHM_DETAILS.get(normalized)
        if details is None:
            raise ValueError(f"Unsupported HSS algorithm: {name}")
        self._details = details
        other_name = LIBOQS_LMS_NAME_BY_ALG.get(normalized) or normalized
        return normalized, other_name

    def _initialize_key(self):
        """Initialize the HSS private key with the provided name and private key bytes."""
        target_levels = self._requested_levels or 1

        if self._private_key_bytes is not None:
            try:
                self._hss = pyhsslms.HssPrivateKey.deserialize(self._private_key_bytes)
            except ValueError as exc:  # pragma: no cover - library validation
                raise InvalidKeyData("Failed to parse HSS private key bytes.") from exc
            self._levels = self._hss.levels
            if self._levels != target_levels:
                raise InvalidKeyData(
                    f"The provided HSS private key uses {self._levels} levels, expected {target_levels}."
                )
            name = build_hss_name_from_codes(
                self._hss.prv[0].lms_type,
                self._hss.prv[0].lmots_type,
            )
            if name != self._name:
                raise InvalidKeyData(
                    "The LMS/LMOTS types encoded in the HSS private key do not match the requested algorithm."
                )
        else:
            self._hss = pyhsslms.HssPrivateKey(
                levels=target_levels,
                lms_type=self._details["lms_type_py"],
                lmots_type=self._details["lmots_type_py"],
            )
        if self._hss is None:
            raise InvalidKeyData("Failed to initialize the HSS private key.")

        self._levels = self._hss.levels
        self._public_key_bytes = self._hss.publicKey().serialize()
        self._private_key_bytes = self._hss.serialize()

    def public_key(self) -> HSSPublicKey:
        """Return the corresponding public key for this HSS private key."""
        if self._public_key_bytes is None:
            raise InvalidKeyData("The HSS public key bytes are not initialised.")
        return HSSPublicKey(self._name, self._public_key_bytes)

    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""
        if self._hss is None:
            raise InvalidKeyData("The HSS private key is not initialised.")
        return self._hss.serialize()

    def private_bytes_raw(self) -> bytes:
        """Return the raw private key bytes."""
        return self._private_key_bytes

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "HSSPrivateKey":
        """Load an HSS private key from its serialized byte representation."""
        hss = pyhsslms.HssPrivateKey.deserialize(data)
        name = build_hss_name_from_codes(hss.prv[0].lms_type, hss.prv[0].lmots_type)
        return cls(name, private_bytes=data, levels=hss.levels)

    def sign(self, data: bytes) -> bytes:
        """Sign the data using the HSS private key."""
        if self._hss is None:
            raise ValueError("The HSS private key is not initialised.")
        signature = self._hss.sign(data)
        self._private_key_bytes = self._hss.serialize()
        try:
            hss_sig = pyhsslms.HssSignature.deserialize(signature)
            self._used_signatures.append(hss_sig.lms_sig.q.to_bytes(4, "big"))
        except ValueError:  # pragma: no cover - library validation
            self._used_signatures.append(signature)
        return signature

    @property
    def max_sig_size(self) -> int:
        """Return the maximum number of signatures supported by this HSS key."""
        return self.public_key().max_sig_size

    @property
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this HSS key."""
        if self._hss is None:
            raise InvalidKeyData("The HSS private key is not initialised.")
        return self._hss.remaining()

    @property
    def used_keys(self) -> list[bytes]:
        """Return a copy of the consumed LMS leaf identifiers."""
        return list(self._used_signatures)

    @property
    def sig_size(self) -> int:
        """Return the size of the signature for this HSS key."""
        return self.public_key().sig_size

    @property
    def key_size(self) -> int:
        """Return the size of the private key for this HSS key."""
        return len(self._private_key_bytes)

    @classmethod
    def supported_algorithms(cls) -> List[str]:
        """Return all supported HSS algorithm identifiers."""
        return sorted(HSS_ALGORITHM_DETAILS.keys())

    @staticmethod
    def normalize_algorithm(name: str) -> str:
        """Normalise an HSS algorithm string, extracting the optional hierarchy depth."""
        return _get_and_chck_hss_name(name)

    @property
    def levels(self) -> int:
        """Return the configured number of LMS layers."""
        return self._levels


XMSS_ALG_IDS = {
    0x00000001: "XMSS-SHA2_10_256",
    0x00000002: "XMSS-SHA2_16_256",
    0x00000003: "XMSS-SHA2_20_256",
    0x00000004: "XMSS-SHA2_10_512",
    0x00000005: "XMSS-SHA2_16_512",
    0x00000006: "XMSS-SHA2_20_512",
    0x00000007: "XMSS-SHAKE_10_256",
    0x00000008: "XMSS-SHAKE_16_256",
    0x00000009: "XMSS-SHAKE_20_256",
    0x0000000A: "XMSS-SHAKE_10_512",
    0x0000000B: "XMSS-SHAKE_16_512",
    0x0000000C: "XMSS-SHAKE_20_512",
    0x0000000D: "XMSS-SHA2_10_192",
    0x0000000E: "XMSS-SHA2_16_192",
    0x0000000F: "XMSS-SHA2_20_192",
    0x00000010: "XMSS-SHAKE256_10_256",
    0x00000011: "XMSS-SHAKE256_16_256",
    0x00000012: "XMSS-SHAKE256_20_256",
    0x00000013: "XMSS-SHAKE256_10_192",
    0x00000014: "XMSS-SHAKE256_16_192",
    0x00000015: "XMSS-SHAKE256_20_192",
}
XMSS_NOT_APPROVED = [
    "XMSS-SHA2_10_512",
    "XMSS-SHA2_16_512",
    "XMSS-SHA2_20_512",
    "XMSS-SHAKE_10_256",
    "XMSS-SHAKE_16_256",
    "XMSS-SHAKE_20_256",
    "XMSS-SHAKE_10_512",
    "XMSS-SHAKE_16_512",
    "XMSS-SHAKE_20_512",
]


XMSSMT_ALG_IDS = {
    0x00000001: "XMSSMT-SHA2_20/2_256",
    0x00000002: "XMSSMT-SHA2_20/4_256",
    0x00000003: "XMSSMT-SHA2_40/2_256",
    0x00000004: "XMSSMT-SHA2_40/4_256",
    0x00000005: "XMSSMT-SHA2_40/8_256",
    0x00000006: "XMSSMT-SHA2_60/3_256",
    0x00000007: "XMSSMT-SHA2_60/6_256",
    0x00000008: "XMSSMT-SHA2_60/12_256",
    0x00000009: "XMSSMT-SHA2_20/2_512",
    0x0000000A: "XMSSMT-SHA2_20/4_512",
    0x0000000B: "XMSSMT-SHA2_40/2_512",
    0x0000000C: "XMSSMT-SHA2_40/4_512",
    0x0000000D: "XMSSMT-SHA2_40/8_512",
    0x0000000E: "XMSSMT-SHA2_60/3_512",
    0x0000000F: "XMSSMT-SHA2_60/6_512",
    0x00000010: "XMSSMT-SHA2_60/12_512",
    0x00000011: "XMSSMT-SHAKE_20/2_256",
    0x00000012: "XMSSMT-SHAKE_20/4_256",
    0x00000013: "XMSSMT-SHAKE_40/2_256",
    0x00000014: "XMSSMT-SHAKE_40/4_256",
    0x00000015: "XMSSMT-SHAKE_40/8_256",
    0x00000016: "XMSSMT-SHAKE_60/3_256",
    0x00000017: "XMSSMT-SHAKE_60/6_256",
    0x00000018: "XMSSMT-SHAKE_60/12_256",
    0x00000019: "XMSSMT-SHAKE_20/2_512",
    0x0000001A: "XMSSMT-SHAKE_20/4_512",
    0x0000001B: "XMSSMT-SHAKE_40/2_512",
    0x0000001C: "XMSSMT-SHAKE_40/4_512",
    0x0000001D: "XMSSMT-SHAKE_40/8_512",
    0x0000001E: "XMSSMT-SHAKE_60/3_512",
    0x0000001F: "XMSSMT-SHAKE_60/6_512",
    0x00000020: "XMSSMT-SHAKE_60/12_512",
    0x00000021: "XMSSMT-SHA2_20/2_192",
    0x00000022: "XMSSMT-SHA2_20/4_192",
    0x00000023: "XMSSMT-SHA2_40/2_192",
    0x00000024: "XMSSMT-SHA2_40/4_192",
    0x00000025: "XMSSMT-SHA2_40/8_192",
    0x00000026: "XMSSMT-SHA2_60/3_192",
    0x00000027: "XMSSMT-SHA2_60/6_192",
    0x00000028: "XMSSMT-SHA2_60/12_192",
    0x00000029: "XMSSMT-SHAKE256_20/2_256",
    0x0000002A: "XMSSMT-SHAKE256_20/4_256",
    0x0000002B: "XMSSMT-SHAKE256_40/2_256",
    0x0000002C: "XMSSMT-SHAKE256_40/4_256",
    0x0000002D: "XMSSMT-SHAKE256_40/8_256",
    0x0000002E: "XMSSMT-SHAKE256_60/3_256",
    0x0000002F: "XMSSMT-SHAKE256_60/6_256",
    0x00000030: "XMSSMT-SHAKE256_60/12_256",
    0x00000031: "XMSSMT-SHAKE256_20/2_192",
    0x00000032: "XMSSMT-SHAKE256_20/4_192",
    0x00000033: "XMSSMT-SHAKE256_40/2_192",
    0x00000034: "XMSSMT-SHAKE256_40/4_192",
    0x00000035: "XMSSMT-SHAKE256_40/8_192",
    0x00000036: "XMSSMT-SHAKE256_60/3_192",
    0x00000037: "XMSSMT-SHAKE256_60/6_192",
    0x00000038: "XMSSMT-SHAKE256_60/12_192",
}

XMSSMT_NOT_APPROVED = [
    "XMSSMT-SHA2_20/2_512",
    "XMSSMT-SHA2_20/4_512",
    "XMSSMT-SHA2_40/2_512",
    "XMSSMT-SHA2_40/4_512",
    "XMSSMT-SHA2_40/8_512",
    "XMSSMT-SHA2_60/3_512",
    "XMSSMT-SHA2_60/6_512",
    "XMSSMT-SHA2_60/12_512",
    "XMSSMT-SHAKE256_20/2_512",
    "XMSSMT-SHAKE256_20/4_512",
    "XMSSMT-SHAKE256_40/2_512",
    "XMSSMT-SHAKE256_40/4_512",
    "XMSSMT-SHAKE256_40/8_512",
    "XMSSMT-SHAKE256_60/3_512",
    "XMSSMT-SHAKE256_60/6_512",
    "XMSSMT-SHAKE256_60/12_512",
]
