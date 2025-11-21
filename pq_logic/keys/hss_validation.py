"""Validation helpers for HSS (Hierarchical Signature System) parameters.

The routines implemented here enforce the LMS/LMOTS pairing and hierarchy
rules described in RFC 8554:

* RFC 8554, Section 5.1 requires (SHOULD BE) the LMS and LMOTS layers to use the same hash
  function family and digest size.  When these differ, the overall security is
  bounded by the weaker primitive which we treat as an error.
* RFC 8554, Section 6 constrains the number of hierarchy levels to the range
  (1 to 8). (The number of levels is denoted as L and is between one and eight, inclusive.)

"""

from __future__ import annotations

import re
from typing import List, Sequence, Tuple, Union

from pq_logic.keys.stateful_sig_keys import HSSPrivateKey, HSSPublicKey
from resources.exceptions import InvalidKeyData

# Canonical parameter names derived from the RFC parameter tables.  The lists
# intentionally cover the full Cartesian product of the permitted values so the
# validator can recognise any well-formed identifier even if a particular
# combination is unsupported by the backing libraries.
LMOTS_SHAKE_NAMES = [f"lmots_shake_n{n}_w{w}" for n in (24, 32) for w in (1, 2, 4, 8)]
LMS_SHA256_NAMES = [f"lms_sha256_m{m}_h{h}" for m in (24, 32) for h in (5, 10, 15, 20, 25)]
LMS_SHAKE_NAMES = [f"lms_shake_m{m}_h{h}" for m in (24, 32) for h in (5, 10, 15, 20, 25)]
LMOTS_SHA256_NAMES = [f"lmots_sha256_n{n}_w{w}" for n in (24, 32) for w in (1, 2, 4, 8)]

_ALL_LMOTS_NAMES = { *LMOTS_SHA256_NAMES, *LMOTS_SHAKE_NAMES }
_ALL_LMS_NAMES = { *LMS_SHA256_NAMES, *LMS_SHAKE_NAMES }

_LMOTS_NAME_RE = re.compile(r"^lmots_(sha256|shake)_n(24|32)_w([1248])$")
_LMS_NAME_RE = re.compile(r"^lms_(sha256|shake)_m(24|32)_h(5|10|15|20|25)$")


def _normalise_pairs(
    levels: Sequence[Tuple[str, str]],
) -> List[Tuple[str, str]]:
    """Normalise a sequence of (LMS, LMOTS) parameter name pairs."""
    return [(lms.lower(), lmots.lower()) for lms, lmots in levels]


def _parse_lmots(name: str) -> Tuple[str, int, int]:
    """Parse an LMOTS identifier into (hash family, digest bytes, Winternitz w)."""
    match = _LMOTS_NAME_RE.match(name)
    if match is None:
        raise InvalidKeyData(f"Unknown/invalid LMOTS parameter set: {name}")
    family, digest_size, w_value = match.group(1), int(match.group(2)), int(match.group(3))
    return family, digest_size, w_value


def _parse_lms(name: str) -> Tuple[str, int, int]:
    """Parse an LMS identifier into (hash family, digest bytes, tree height)."""
    match = _LMS_NAME_RE.match(name)
    if match is None:
        raise InvalidKeyData(f"Unknown/invalid LMS parameter set: {name}")
    family, digest_size, height = match.group(1), int(match.group(2)), int(match.group(3))
    return family, digest_size, height


def _validate_lms_lmots_pair(lms: str, lmots: str) -> List[str]:
    """Validate that a single LMS/LMOTS parameter pair satisfies RFC 8554."""
    errors: List[str] = []

    if lms not in _ALL_LMS_NAMES:
        errors.append(f"Unknown LMS parameter set: {lms}")
    if lmots not in _ALL_LMOTS_NAMES:
        errors.append(f"Unknown LMOTS parameter set: {lmots}")

    if errors:
        return errors

    lms_family, lms_digest, lms_height = _parse_lms(lms)
    lmots_family, lmots_digest, lmots_w = _parse_lmots(lmots)

    if lms_family != lmots_family:
        errors.append(
            f"Hash family mismatch: LMS uses {lms_family} while LMOTS uses {lmots_family} (RFC 8554 §5.1)."
        )

    if lms_digest != lmots_digest:
        errors.append(
            f"Digest size mismatch: LMS m={lms_digest} bytes, LMOTS n={lmots_digest} bytes (must match)."
        )

    if lmots_w not in (1, 2, 4, 8):
        errors.append(f"Invalid LMOTS Winternitz parameter w={lmots_w}. Allowed: 1, 2, 4, 8.")
    if lms_height not in (5, 10, 15, 20, 25):
        errors.append(f"Invalid LMS tree height h={lms_height}. Allowed: 5, 10, 15, 20, 25.")

    return errors


def _validate_hss_configuration(
    levels: Sequence[Tuple[str, str]],
) -> List[str]:
    """Validate an HSS hierarchy definition.

    :param levels: Iterable of (LMS, LMOTS) parameter names for each hierarchy level.
    :return: A list of validation error messages.  The list is empty when the
        configuration satisfies all constraints.
    """
    errors: List[str] = []
    canonical_levels = _normalise_pairs(levels)

    hierarchy_depth = len(canonical_levels)
    if not 1 <= hierarchy_depth <= 8:
        errors.append(f"Invalid number of HSS levels L={hierarchy_depth}. Allowed range is 1 to 8 (RFC 8554 §6).")

    for idx, (lms_name, lmots_name) in enumerate(canonical_levels):
        for issue in _validate_lms_lmots_pair(lms_name, lmots_name):
            errors.append(f"Level {idx}: {issue}")

    return errors


def _check_digest_size_mismatch(
    levels: Sequence[Tuple[str, str]],
) -> List[str]:
    """Check for digest size mismatches across HSS levels.

    :param levels: Iterable of (LMS, LMOTS) parameter names for each hierarchy level.
    :return: A list of validation error messages related to digest size mismatches.
    """
    issues: List[str] = []
    canonical_levels = _normalise_pairs(levels)

    if not canonical_levels:
        return issues

    _, first_lmots = canonical_levels[0]
    _, first_digest_size, _ = _parse_lmots(first_lmots)

    for idx, (_, lmots_name) in enumerate(canonical_levels[1:], start=1):
        _, digest_size, _ = _parse_lmots(lmots_name)
        if digest_size != first_digest_size:
            issues.append(
                f"Level {idx}: Digest size mismatch with level 0: "
                f"LMOTS uses n={digest_size} bytes while level 0 uses n={first_digest_size} bytes."
            )

    return issues


def _check_hash_family_mismatch(
    levels: Sequence[Tuple[str, str]],
) -> List[str]:
    """Check for hash family mismatches across HSS levels.

    :param levels: Iterable of (LMS, LMOTS) parameter names for each hierarchy level.
    :return: A list of validation error messages related to hash family mismatches.
    """
    issues: List[str] = []
    canonical_levels = _normalise_pairs(levels)

    if not canonical_levels:
        return issues

    first_lms, _ = canonical_levels[0]
    first_family, _, _ = _parse_lms(first_lms)

    for idx, (lms_name, _) in enumerate(canonical_levels[1:], start=1):
        lms_family, _, _ = _parse_lms(lms_name)
        if lms_family != first_family:
            issues.append(
                f"Level {idx}: Hash family mismatch with level 0: "
                f"LMS uses {lms_family} while level 0 uses {first_family}."
            )

    return issues


def _check_winternitz_parameter_mismatch(
    levels: Sequence[Tuple[str, str]],
) -> List[str]:
    """Check for Winternitz parameter mismatches across HSS levels.

    :param levels: Iterable of (LMS, LMOTS) parameter names for each hierarchy level.
    :return: A list of validation error messages related to Winternitz parameter mismatches.
    """
    issues: List[str] = []
    canonical_levels = _normalise_pairs(levels)

    if not canonical_levels:
        return issues

    _, first_lmots = canonical_levels[0]
    _, _, first_w = _parse_lmots(first_lmots)

    for idx, (_, lmots_name) in enumerate(canonical_levels[1:], start=1):
        _, _, w = _parse_lmots(lmots_name)
        if w != first_w:
            issues.append(
                f"Level {idx}: Winternitz parameter mismatch with level 0: "
                f"LMOTS uses w={w} while level 0 uses w={first_w}."
            )

    return issues


def validate_hss_key_levels(
    levels: Sequence[Tuple[str, str]],
    allow_diff_hash_and_output_size_per_level: bool = False,
) -> None:
    """Raise :class:`InvalidKeyData` if an HSS configuration violates RFC 8554."""
    issues = _validate_hss_configuration(levels)

    if not allow_diff_hash_and_output_size_per_level and len(levels) > 1:
        issues.extend(_check_hash_family_mismatch(levels))
        issues.extend(_check_digest_size_mismatch(levels))
        issues.extend(_check_winternitz_parameter_mismatch(levels))

    if issues:
        raise InvalidKeyData("; ".join(issues), error_details=issues)


def validate_hss_key(
    key: Union[HSSPrivateKey, HSSPublicKey], hss_allow_diff_hash_and_output_size_per_level: bool = False
) -> None:
    """Validate an HSS key's parameters against RFC 8554 and NIST SP 800-208 guideline.

    :param key: An HSS private or public key instance.
    :param hss_allow_diff_hash_and_output_size_per_level: If ``True``, skip checks that
        enforce uniform hash family and output size across all hierarchy levels.
    :raises InvalidKeyData: If the key's parameters violate any constraints.
    """
    if isinstance(key, HSSPrivateKey):
        key = key.public_key()

    levels = key.get_level_names()
    validate_hss_key_levels(
        levels, allow_diff_hash_and_output_size_per_level=hss_allow_diff_hash_and_output_size_per_level
    )
