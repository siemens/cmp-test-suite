# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory for creating hybrid keys based on PQ (post-quantum) and traditional components."""

import logging
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958

from pq_logic.keys.abstract_wrapper_keys import HybridPrivateKey, HybridPublicKey, PQPrivateKey, TradKEMPrivateKey
from pq_logic.keys.chempat_key import ChempatPrivateKey, ChempatPublicKey
from pq_logic.keys.composite_kem import (
    CompositeDHKEMRFC9180PrivateKey,
    CompositeKEMPrivateKey,
)
from pq_logic.keys.composite_sig import CompositeSigPrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.serialize_utils import prepare_ec_private_key
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, RSADecapKey
from pq_logic.keys.trad_key_factory import generate_trad_key
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.tmp_oids import CHEMPAT_OID_2_NAME, COMPOSITE_KEM_VERSION, COMPOSITE_SIG_VERSION
from resources.exceptions import BadAlg, InvalidKeyCombination, InvalidKeyData, MismatchingKey
from resources.oid_mapping import KEY_CLASS_MAPPING, may_return_oid_to_name
from resources.oidutils import (
    ALL_COMPOSITE_SIG_COMBINATIONS,
    PQ_NAME_2_OID,
    XWING_OID_STR,
)
from resources.suiteenums import KeySaveType
from resources.typingutils import ECDHPrivateKey, ECPrivateKey, ECSignKey, Strint

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


ALL_COMPOSITE_KEM07_COMBINATIONS = [
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "rsa", "length": "3072"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp512r1"},
]
ALL_COMPOSITE_KEM07_COMBINATIONS += ALL_COMPOSITE_KEM05_COMBINATIONS

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

ALL_COMPOSITE_KEM07_COMBINATIONS += ALL_COMPOSITE_KEM_FRODOKEM_COMBINATIONS


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
    :param algorithm:    The hybrid algorithm name (e.g., 'composite-sig-13', 'composite-kem', etc.).
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
        "kem": CompositeKEMPrivateKey,  # always the latest version
        f"kem-{COMPOSITE_KEM_VERSION}": CompositeKEMPrivateKey,
        f"kem{COMPOSITE_KEM_VERSION}": CompositeKEMPrivateKey,
        "dhkem": CompositeDHKEMRFC9180PrivateKey,  # always the latest version
        "sig": CompositeSigPrivateKey,  # always the latest version
        f"sig-{COMPOSITE_SIG_VERSION}": CompositeSigPrivateKey,
    }
    key_class = key_class_mappings[hybrid_type]
    return key_class(pq_key, trad_key)


class HybridKeyFactory:
    """Factory for creating hybrid keys based on traditional and post-quantum (PQ) key types."""

    hybrid_mappings = {
        f"sig-{COMPOSITE_SIG_VERSION}": ALL_COMPOSITE_SIG_COMBINATIONS,
        "sig": ALL_COMPOSITE_SIG_COMBINATIONS,
        "kem": ALL_COMPOSITE_KEM07_COMBINATIONS,
        f"kem-{COMPOSITE_KEM_VERSION}": ALL_COMPOSITE_KEM07_COMBINATIONS,
        f"kem{COMPOSITE_KEM_VERSION}": ALL_COMPOSITE_KEM07_COMBINATIONS,
        "chempat": ALL_CHEMPAT_COMBINATIONS,
        "dhkem": ALL_COMPOSITE_KEM07_COMBINATIONS,
        "xwing": [],
    }

    default_comb = {
        "sig": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        f"sig-{COMPOSITE_SIG_VERSION}": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        "kem": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        f"kem{COMPOSITE_KEM_VERSION}": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        f"kem-{COMPOSITE_KEM_VERSION}": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
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
                f"composite-sig-{COMPOSITE_SIG_VERSION}": ["rsa", "ecdsa", "ed25519", "ed448"],
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
            f"composite-sig-{COMPOSITE_SIG_VERSION}",
            "composite-dhkem",
            "composite-kem",
            f"composite-kem-{COMPOSITE_KEM_VERSION}",
            f"composite-kem{COMPOSITE_KEM_VERSION}",
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
    def _load_pq_key(name: str, data: bytes) -> PQPrivateKey:
        """Load a post-quantum key from the provided bytes.

        Necessary for loading hybrid keys, to ensure that the old key loading logic and the
        new key loading logic are compatible (ML-KEM and ML-DSA keys).

        :param name: The name of the key.
        :param data: The key bytes.
        :return: The loaded post-quantum key.
        """
        pq_one_asym_key = rfc5958.OneAsymmetricKey()
        pq_one_asym_key["version"] = 0
        pq_one_asym_key["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[name]
        pq_one_asym_key["privateKey"] = data
        return PQKeyFactory.from_one_asym_key(pq_one_asym_key)

    @staticmethod
    def _load_chempat_private_key(
        private_bytes: bytes,
        oid: univ.ObjectIdentifier,
    ) -> ChempatPrivateKey:
        """Load a Chempat private key from the provided bytes.

        :param private_bytes: The private key bytes to load.
        :param oid: The OID of the key.
        :return: An instance of ChempatPrivateKey.
        :raises InvalidKeyData: If the private key data is invalid.
        :raises ValueError: If the name is invalid.
        """
        name = CHEMPAT_OID_2_NAME[oid]
        name = name.lower()
        tmp_name = name.replace("chempat-", "", 1)
        _length = int.from_bytes(private_bytes[:4], "little")

        pq_private_bytes = private_bytes[4 : 4 + _length]
        pq_name = PQKeyFactory.get_pq_alg_name(tmp_name)
        try:
            pq_key = HybridKeyFactory._load_pq_key(name=pq_name, data=pq_private_bytes)
        except InvalidKeyData as e:
            raise InvalidKeyData(f"Invalid Chempat pq private key data for {tmp_name}: {e}") from e

        trad_private_bytes = private_bytes[4 + _length :]
        tmp_name = tmp_name.replace(f"{pq_name}-", "", 1)
        try:
            trad_key = DHKEMPrivateKey.from_private_bytes(data=trad_private_bytes, name=tmp_name)
        except ValueError as e:
            raise InvalidKeyData(f"Invalid Chempat traditional private key data for {tmp_name}: {e}") from e
        private_key = ChempatPrivateKey.parse_keys(pq_key, trad_key)
        return private_key

    @staticmethod
    def from_one_asym_key(one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes]) -> "HybridPrivateKey":  # ytpe: ignore
        """Create a new hybrid key from an `OneAsymmetricKey` structure.

        :param one_asym_key: The `OneAsymmetricKey` structure or its DER-encoded bytes.
        :return: An instance of HybridPrivateKey.
        :raises BadAlg: If the algorithm is not supported.
        :raises MismatchingKey: If the public key does not match the private key.
        :raises InvalidKeyData: If the key data is invalid.
        """
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
                    raise MismatchingKey("Public key does not match the private key.")
            return private_key

        if oid in CHEMPAT_OID_2_NAME:
            name = CHEMPAT_OID_2_NAME[oid]
            private_key = HybridKeyFactory._load_chempat_private_key(
                private_bytes=private_bytes,
                oid=oid,
            )

            if public_bytes is not None:
                public_key = ChempatPublicKey.from_public_bytes(data=public_bytes, name=name)
                # Currently does OQS not support the derivation of the public key from the private key.
                # Therefore, we need to set the public key bytes manually.
                # If the seed derivation is implemented, this part can be removed.
                private_key.pq_key._public_key_bytes = public_key.pq_key._public_key_bytes  # pylint: disable=protected-access
                if public_key.public_bytes_raw() != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey("Public key does not match the private key.")
            return private_key

        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Cannot load the private key. Unsupported algorithm: {_name}")

    @staticmethod
    def _get_hybrid_pub_key_bytes(public_key: HybridPublicKey) -> bytes:
        """Get the public key bytes from the hybrid public key."""
        der_data = public_key.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        spki = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
        return spki["subjectPublicKey"].asOctets()

    @staticmethod
    def _may_get_pub_key(
        private_key: HybridPrivateKey,
        public_key: Optional[HybridPublicKey],
        include_pub_key: Optional[bool] = True,
        version: int = 1,
    ) -> Optional[bytes]:
        """May get the public key from the private key.

        :param private_key: The private key to be saved.
        :param public_key: The public key to be included in the `OneAsymmetricKey` object. Defaults to `None`.
        :param include_pub_key: If True, include the public key in the `OneAsymmetricKey` object. Used
        for negative testing. Defaults to `None` will be determined by the version.
        :param version: The version of the `OneAsymmetricKey` object. Defaults to 1.
        """
        if include_pub_key or version >= 1:
            public_key = public_key or private_key.public_key()
            return HybridKeyFactory._get_hybrid_pub_key_bytes(public_key)

        return None

    @staticmethod
    def _get_private_trad_key_der_data(
        private_key: Union[TradKEMPrivateKey, TradPartPrivateKey],
    ) -> bytes:
        """Save the private key in the respected format.

        :param private_key: The private key to be saved.
        :return: The DER-encoded private key.
        :raises ValueError: If the private key is not supported.
        """
        if isinstance(private_key, RSAPrivateKey):
            private_key = RSADecapKey(private_key)

        elif isinstance(private_key, EllipticCurvePrivateKey):
            ec_key_asn1 = prepare_ec_private_key(
                ec_key=private_key,
            )
            return encoder.encode(ec_key_asn1)

        if isinstance(private_key, ECPrivateKey):
            private_key = DHKEMPrivateKey(private_key)

        return private_key.encode()

    @staticmethod
    def _save_keys_with_support_seed(
        private_key: HybridPrivateKey,
        save_type: Union[str, KeySaveType] = "seed",
        unsafe: bool = False,
    ) -> bytes:
        """Save the private key in a format that supports seed extraction.

        :param private_key: The private key to be saved.
        :param save_type: The type of saving (e.g., 'seed', 'raw', 'seed_and_raw'). Defaults to 'seed'.
        :param unsafe: The PQ liboqs keys do not allow one to derive the public key from the
        private key, disables the exception call. Defaults to `False`.
        :return: The DER-encoded private key.
        :raise NotImplementedError: Version 1 is not supported for `liboqs` keys.
        """
        key_type = KeySaveType.get(save_type)

        pq_key_bytes = PQKeyFactory.save_keys_with_support_seed(
            private_key=private_key.pq_key,
            key_type=key_type,
        )

        if isinstance(private_key, (CompositeKEMPrivateKey, CompositeSigPrivateKey)):
            if key_type == KeySaveType.SEED and hasattr(private_key.pq_key, "private_numbers"):
                pq_key_bytes = private_key.pq_key.private_numbers()
            elif key_type == KeySaveType.SEED_AND_RAW and hasattr(private_key.pq_key, "private_numbers"):
                pq_key_bytes = private_key.pq_key.private_numbers() + private_key.private_bytes_raw()
            else:
                pq_key_bytes = private_key.pq_key.private_bytes_raw()
            trad_key_bytes = private_key._export_trad_private_key()
            return pq_key_bytes + trad_key_bytes

        if isinstance(private_key, XWingPrivateKey):
            if key_type == KeySaveType.SEED:
                return private_key.private_numbers()
            if key_type == KeySaveType.RAW:
                return private_key.private_bytes_raw()
            return private_key.private_numbers() + private_key.private_bytes_raw()

        if isinstance(private_key, ChempatPrivateKey):
            _length = len(pq_key_bytes)
            return _length.to_bytes(4, "little") + pq_key_bytes + private_key.trad_key.encode()

        raise ValueError(
            f"Unsupported private key type: {type(private_key)}. "
            f"Supported types are: {HybridKeyFactory.hybrid_mappings}"
        )

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: HybridPrivateKey,
        public_key: Optional[HybridPublicKey] = None,
        version: int = 1,
        save_type: Union[str, KeySaveType] = "seed",
        include_public_key: Optional[bool] = None,
        unsafe: bool = False,
    ) -> bytes:
        """Convert a hybrid private key to an `OneAsymmetricKey` structure, DER-encoded.

        :param private_key: The hybrid private key to be converted.
        :param public_key:  The corresponding public key. Defaults to `None`.
        :param version:     The version of the `OneAsymmetricKey` structure. Defaults to `1`.
        :param save_type:   The type of pq-key saving (e.g., 'seed', 'raw', 'seed_and_raw'). Defaults to 'seed'.
        :param include_public_key: Whether to include the public key in the output. If `None`, it will be
        determined based on the key type. Defaults to `None`.
        :param unsafe: The PQ liboqs keys do not allow one to derive the public key from the
        private key, disables the exception call. Defaults to `False`.
        :return: The DER-encoded private key.
        :raise NotImplementedError: Version 1 is not supported for `liboqs` keys.
        """
        key_type = KeySaveType.get(save_type)
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = version

        oid = private_key.get_oid()

        one_asym_key["privateKeyAlgorithm"]["algorithm"] = oid

        one_asym_key["privateKey"] = HybridKeyFactory._save_keys_with_support_seed(
            private_key=private_key, save_type=key_type, unsafe=unsafe
        )
        public_key_bytes = HybridKeyFactory._may_get_pub_key(
            private_key=private_key, public_key=public_key, include_pub_key=include_public_key, version=version
        )

        if public_key_bytes is not None:
            public_key_asn1 = univ.BitString(hexValue=public_key_bytes.hex()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
            one_asym_key["publicKey"] = public_key_asn1

        der_data = encoder.encode(one_asym_key)
        return der_data
