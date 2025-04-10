# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory for creating hybrid keys based on PQ (post-quantum) and traditional components."""

import logging
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5958

from pq_logic.keys.abstract_wrapper_keys import HybridPrivateKey, PQPrivateKey, TradKEMPrivateKey
from pq_logic.keys.chempat_key import ChempatPrivateKey, ChempatPublicKey
from pq_logic.keys.composite_kem05 import (
    CompositeKEMPrivateKey,
)
from pq_logic.keys.composite_kem06 import CompositeDHKEMRFC9180PrivateKey, CompositeKEM06PrivateKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.trad_key_factory import generate_trad_key
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.tmp_oids import CHEMPAT_OID_2_NAME
from pq_logic.trad_typing import ECDHPrivateKey
from resources.exceptions import BadAlg, InvalidKeyCombination
from resources.oid_mapping import KEY_CLASS_MAPPING, may_return_oid_to_name
from resources.oidutils import (
    ALL_COMPOSITE_SIG04_COMBINATIONS,
    ALL_COMPOSITE_SIG_COMBINATIONS,
    XWING_OID_STR,
)
from resources.typingutils import ECSignKey, Strint

TradPartPrivateKey = Union[ECSignKey, ECDHPrivateKey, RSAPrivateKey, TradKEMPrivateKey]

ALL_CHEMPAT_COMBINATIONS = [
    {"pq_name": "sntrup761", "trad_name": "x25519"},
    {"pq_name": "mceliece-348864", "trad_name": "x25519"},
    {"pq_name": "mceliece-460896", "trad_name": "x25519"},
    {"pq_name": "mceliece-6688128", "trad_name": "x25519"},
    {"pq_name": "mceliece-6960119", "trad_name": "x25519"},
    {"pq_name": "mceliece-8192128", "trad_name": "x25519"},
    {"pq_name": "mceliece-348864", "trad_name": "x448"},
    {"pq_name": "mceliece-460896", "trad_name": "x448"},
    {"pq_name": "mceliece-6688128", "trad_name": "x448"},
    {"pq_name": "mceliece-6960119", "trad_name": "x448"},
    {"pq_name": "mceliece-8192128", "trad_name": "x448"},
    {"pq_name": "ml-kem-768", "trad_name": "x25519"},
    {"pq_name": "ml-kem-1024", "trad_name": "x448"},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "brainpoolP384r1"},
]

CHEMPAT_FRODOKEM_COMBINATIONS = [
    {"pq_name": "frodokem-976-aes", "trad_name": "x25519"},
    {"pq_name": "frodokem-976-shake", "trad_name": "x25519"},
    {"pq_name": "frodokem-640-aes", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
    {"pq_name": "frodokem-640-shake", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "brainpoolp512r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "brainpoolp512r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "x448"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "x448"},
]
ALL_CHEMPAT_COMBINATIONS += CHEMPAT_FRODOKEM_COMBINATIONS

ALL_COMPOSITE_KEM05_COMBINATIONS = [
    {"pq_name": "ml-kem-768", "trad_name": "x25519"},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "x448"},
]

ALL_COMPOSITE_KEM06_COMBINATIONS = [{"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"}]
ALL_COMPOSITE_KEM06_COMBINATIONS += ALL_COMPOSITE_KEM05_COMBINATIONS

ALL_COMPOSITE_KEM_FRODOKEM_COMBINATIONS = [
    # Claimed NIST level 3
    {"pq_name": "frodokem-976-aes", "trad_name": "x25519"},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "x25519"},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": "2048"},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": "4096"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
    # Claimed NIST level 5
    {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "x448"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "x448"},
]

ALL_COMPOSITE_KEM06_COMBINATIONS += ALL_COMPOSITE_KEM_FRODOKEM_COMBINATIONS


def _get_trad_key_from_pq_key(
    trad_key, allowed_key: List[str], comb_name: str
) -> Tuple[str, Optional[str], Optional[str]]:
    """Return traditional key parameters based on the provided traditional key.

    :param trad_key: The traditional key object.
    :param allowed_key: Allowed traditional key types for the given combination.
    :param comb_name: Name of the combination for error messages.
    :return: A tuple containing the traditional key name, length, and curve.
    :raises ValueError: If the traditional key is not allowed.
    """
    trad_name = KEY_CLASS_MAPPING[trad_key.__class__.__name__]  # only returns ECDSA!

    # Handle the case where ECDSA and ECDH names might be interchanged.
    if trad_name == "ecdsa" and "ecdh" in allowed_key:
        trad_name = "ecdh"

    if trad_name not in allowed_key:
        raise ValueError(f"Traditional key '{trad_name}' not allowed for '{comb_name}'.")

    length = curve = None

    if trad_name == "rsa":
        value = trad_key.key_size
        predefined_values = [2048, 3072, 4096]
        length = str(min(predefined_values, key=lambda x: abs(x - value)))
    elif trad_name in ["ecdsa", "ecdh"]:
        curve = trad_key.curve.name

    return trad_name, length, curve


def get_valid_hybrid_combination(
    combinations: List[dict],
    algorithm: str,
    pq_name: Optional[str] = None,
    trad_name: Optional[str] = None,
    length: Optional[Strint] = None,
    curve: Optional[str] = None,
) -> dict:
    """Return the first valid matching combination based on provided criteria.

    :param combinations: A list of dictionaries representing valid combinations.
    :param algorithm:    The hybrid algorithm name (e.g., 'composite-sig-04', 'composite-kem', etc.).
    :param pq_name:      The post-quantum algorithm name.
    :param trad_name:    The traditional algorithm name.
    :param length:       The length of the traditional key. If `None`, the first length is chosen.
    :param curve:        The curve of the traditional key. If `None`, the first curve is chosen.
    :return:  A valid combination dictionary.
    :raises ValueError: If no valid combination is found.
    """
    if not pq_name and not trad_name and not length and not curve:
        return combinations[0]

    if length:
        length = str(length)

    if curve:
        curve = curve.lower()

    for entry in combinations:
        if pq_name and entry["pq_name"] != pq_name:
            continue
        if trad_name and entry["trad_name"] != trad_name:
            continue
        if length and entry.get("length") != length:
            continue
        if curve and entry.get("curve", "").lower() != curve:
            continue

        return entry

    raise ValueError(
        f"No valid {algorithm} combination found for pq_name={pq_name}, "
        f"trad_name={trad_name}, length={length}, curve={curve}"
    )


def _parse_private_keys(hybrid_type: str, pq_key, trad_key) -> HybridPrivateKey:
    """Parse the provided keys based on the hybrid key type."""
    if "chempat" == hybrid_type:
        return ChempatPrivateKey.parse_keys(pq_key, trad_key)

    hybrid_type = hybrid_type.replace("composite-", "")
    key_class_mappings = {
        "sig-04": CompositeSig04PrivateKey,
        "sig-03": CompositeSig03PrivateKey,
        "kem": CompositeKEM06PrivateKey,  # always the latest version
        "kem-06": CompositeKEM06PrivateKey,
        "kem-05": CompositeKEMPrivateKey,
        "dhkem": CompositeDHKEMRFC9180PrivateKey,  # always the latest version
        "sig": CompositeSig04PrivateKey,  # always the latest version
    }
    key_class = key_class_mappings[hybrid_type]
    return key_class(pq_key, trad_key)


class HybridKeyFactory:
    """Factory for creating hybrid keys based on traditional and post-quantum (PQ) key types."""

    hybrid_mappings = {
        "sig-04": ALL_COMPOSITE_SIG04_COMBINATIONS,
        "sig-03": ALL_COMPOSITE_SIG_COMBINATIONS,
        "sig": ALL_COMPOSITE_SIG04_COMBINATIONS,
        "kem-05": ALL_COMPOSITE_KEM05_COMBINATIONS,
        "kem": ALL_COMPOSITE_KEM06_COMBINATIONS,
        "kem-06": ALL_COMPOSITE_KEM06_COMBINATIONS,
        "chempat": ALL_CHEMPAT_COMBINATIONS,
        "dhkem": ALL_COMPOSITE_KEM06_COMBINATIONS,
        "xwing": [],
    }

    default_comb = {
        "sig": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        "sig-04": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        "sig-03": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        "kem": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        "chempat": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        "dhkem": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
    }

    @staticmethod
    def generate_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
        trad_key: Optional[TradPartPrivateKey] = None,
        pq_key: Optional[PQPrivateKey] = None,
    ) -> HybridPrivateKey:
        """Generate a hybrid key based on the requested algorithm and optional parameters

        :param algorithm: The hybrid key algorithm (e.g. 'xwing', 'chempat', etc.).
        :param pq_name:   Name of the post-quantum algorithm. Defaults to `None`.
        :param trad_name: Name of the traditional algorithm Defaults to `None`.
        :param length:    Length of the RSA key (if applicable).
        :param curve:     EC curve of the EC key (if applicable).
        :param trad_key:  Traditional key object. Defaults to `None`.
        :param pq_key:    Post-quantum key object. Defaults to `None`.
        :return:          An instance of HybridPrivateKey (e.g., XWingPrivateKey, CompositeKEMPrivateKey, etc.).
        :raises ValueError: If the algorithm is unknown.
        """
        if pq_key is not None or trad_key is not None:
            return HybridKeyFactory.from_keys(algorithm, pq_key, trad_key)

        if algorithm == "xwing":
            return XWingPrivateKey(pq_key=pq_key, trad_key=trad_key)

        if all(x is None for x in [pq_name, trad_name, length, curve]):
            hybrid = algorithm.replace("composite-", "")
            default_entry = HybridKeyFactory.default_comb[hybrid]
            return HybridKeyFactory.generate_hybrid_key(algorithm, **default_entry)  # type: ignore

        return HybridKeyFactory._generate_default_hybrid_key(
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

    @staticmethod
    def from_keys(algorithm: str, pq_key=None, trad_key=None) -> HybridPrivateKey:
        """Create a hybrid key from existing PQ and traditional keys."""
        if pq_key is None and trad_key is None:
            raise ValueError("Either pq_key or trad_key must be provided.")

        if algorithm == "xwing":
            if pq_key is None:
                pq_key = PQKeyFactory.generate_pq_key("ml-kem-768")
            if trad_key is None:
                trad_key = generate_trad_key("x25519")
            return XWingPrivateKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

        algo = algorithm.lower()
        pq_name = trad_name = length = curve = None
        if pq_key is None:
            allowed_keys = {
                "chempat": ["ecdh", "x25519", "x448"],
                "composite-kem": ["rsa", "ecdh", "x25519", "x448"],
                "composite-sig": ["rsa", "ecdsa", "ed25519", "ed448"],
                "composite-sig-04": ["rsa", "ecdsa", "ed25519", "ed448"],
                "composite-sig-03": ["rsa", "ecdsa", "ed25519", "ed448"],
                "xwing": ["x25519"],
            }.get(algo, [])

            trad_name, length, curve = _get_trad_key_from_pq_key(
                trad_key, allowed_key=allowed_keys, comb_name=algorithm
            )

        if pq_key is not None:
            pq_name = pq_key.name

        hybrid_key = HybridKeyFactory._generate_default_hybrid_key(
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

        if trad_key is None:
            trad_key = hybrid_key.trad_key

        if pq_key is None:
            pq_key = hybrid_key.pq_key

        return _parse_private_keys(hybrid_type=algorithm, pq_key=pq_key, trad_key=trad_key)

    @staticmethod
    def get_all_kem_coms_as_dict() -> Dict[str, List[Dict]]:
        """Return a dictionary of all possible composite-KEM key combinations."""
        return {
            "xwing": [{}],
            "composite-kem": ALL_COMPOSITE_KEM05_COMBINATIONS,
            "chempat": ALL_CHEMPAT_COMBINATIONS,
        }

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return a list of supported hybrid algorithms."""
        return [
            "xwing",
            "composite-sig",
            "composite-sig-03",
            "composite-sig-04",
            "composite-kem-05",
            "composite-dhkem",
            "composite-kem",
            "composite-kem-06",
            "chempat",
        ]

    @staticmethod
    def _generate_default_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ) -> HybridPrivateKey:
        """Generate composite signature or KEM keys based on provided parameters."""
        hybrid_type = algorithm.lower().replace("composite-", "")

        if hybrid_type not in HybridKeyFactory.hybrid_mappings:
            raise InvalidKeyCombination(f"Unsupported hybrid type: {algorithm}")

        valid_combinations = HybridKeyFactory.hybrid_mappings[hybrid_type]

        if hybrid_type in ["dhkem", "kem"] and pq_name in ["frodokem-aes-640", "frodokem-shake-640"]:
            raise InvalidKeyCombination("FrodoKEM-640 is not supported (the claimed NIST level is only `1`).")

        params = get_valid_hybrid_combination(
            valid_combinations,
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

        pq_key = PQKeyFactory.generate_pq_key(params["pq_name"])
        trad_key = generate_trad_key(
            algorithm=params["trad_name"],
            length=params.get("length"),
            curve=params.get("curve"),
        )
        return _parse_private_keys(algorithm, pq_key, trad_key)

    @staticmethod
    def from_one_asym_key(one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes]) -> "HybridPrivateKey":  # ytpe: ignore
        """Create a new hybrid key from an `OneAsymmetricKey` structure."""
        if isinstance(one_asym_key, bytes):
            one_asym_key = decoder.decode(one_asym_key, asn1Spec=rfc5958.OneAsymmetricKey())[0]

        one_asym_key: rfc5958.OneAsymmetricKey
        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        alg_oid = str(oid)

        private_bytes = one_asym_key["privateKey"].asOctets()
        public_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None

        if alg_oid == XWING_OID_STR:
            private_key = XWingPrivateKey.from_private_bytes(private_bytes)
            if len(private_bytes) not in [32, 96]:
                logging.info("The XWing key size is not 32 or 96 bytes.")
            if public_bytes is not None:
                pub = private_key.public_key().from_public_bytes(public_bytes)
                if pub.public_bytes_raw() != private_key.public_key().public_bytes_raw():
                    raise ValueError("Public key does not match the private key.")
            return private_key

        if oid in CHEMPAT_OID_2_NAME:
            name = CHEMPAT_OID_2_NAME[oid]
            private_key = ChempatPrivateKey.from_private_bytes(data=private_bytes, name=name)
            if public_bytes is not None:
                public_key = ChempatPublicKey.from_public_bytes(data=public_bytes, name=name)
                # Currently does OQS not support the derivation of the public key from the private key.
                # Therefore, we need to set the public key bytes manually.
                # If the seed derivation is implemented, this part can be removed.
                private_key.pq_key._public_key_bytes = public_key._public_key_bytes  # pylint: disable=protected-access

                if public_key.public_bytes_raw() != private_key.public_key().public_bytes_raw():
                    raise ValueError("Public key does not match the private key.")
            return private_key

        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Cannot load the private key. Unsupported algorithm: {_name}")
