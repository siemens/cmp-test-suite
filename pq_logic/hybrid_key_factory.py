# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory for creating hybrid keys based on pq and traditional components."""

from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from resources import keyutils
from resources.exceptions import InvalidKeyCombination
from resources.typingutils import Strint

from pq_logic.chempatkem import ChempatPrivateKey
from pq_logic.keys.abstract_composite import (
    AbstractCompositeSigPrivateKey,
)
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, get_valid_comb
from pq_logic.keys.composite_kem_pki import (
    CompositeDHKEMRFC9180PrivateKey,
    CompositeKEMPrivateKey,
    parse_private_keys,
)
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.trad_key_factory import generate_ec_key, generate_trad_key

ALL_CHEMPAT_POSS_COMBINATIONS = [
    {"pq_name": "sntrup761", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-348864", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-460896", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-6688128", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-6960119", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-8192128", "trad_name": "x25519", "curve": None},
    {"pq_name": "mceliece-348864", "trad_name": "x448", "curve": None},
    {"pq_name": "mceliece-460896", "trad_name": "x448", "curve": None},
    {"pq_name": "mceliece-6688128", "trad_name": "x448", "curve": None},
    {"pq_name": "mceliece-6960119", "trad_name": "x448", "curve": None},
    {"pq_name": "mceliece-8192128", "trad_name": "x448", "curve": None},
    {"pq_name": "ml-kem-768", "trad_name": "x25519", "curve": None},
    {"pq_name": "ml-kem-1024", "trad_name": "x448", "curve": None},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "brainpoolP384r1"},
]

CHEMPAT_FRODOKEM_POSS_COMBINATIONS = [
    {"pq_name": "frodokem-976-aes", "trad_name": "x25519", "curve": None},
    {"pq_name": "frodokem-976-shake", "trad_name": "x25519", "curve": None},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "secp256r1"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "brainpoolP256r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "brainpoolP256r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "brainpoolP384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "brainpoolP384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "x448", "curve": None},
    {"pq_name": "frodokem-1344-shake", "trad_name": "x448", "curve": None},
]

ALL_CHEMPAT_POSS_COMBINATIONS += CHEMPAT_FRODOKEM_POSS_COMBINATIONS


def _get_chempat_combinations(
    pq_name: Optional[str] = None, trad_name: Optional[str] = None, curve: Optional[str] = None
) -> dict:
    """Create a matching Chempat combination of pq_name and trad_name.

    :param pq_name: The post-quantum algorithm.
    :param trad_name: The traditional algorithm.
    :param curve: The curve of the traditional algorithm.
    :return: A dictionary with the pq_name, trad_name and curve.
    """
    if pq_name is None and trad_name is None and curve is None:
        return {"pq_name": "ml-kem-768", "trad_name": "x25519", "curve": None}

    for entry in ALL_CHEMPAT_POSS_COMBINATIONS:
        if pq_name is not None and entry["pq_name"] != pq_name:
            continue

        if trad_name is not None and entry["trad_name"] != trad_name:
            continue

        if curve is not None and entry.get("curve") != curve:
            continue

        return entry

    raise ValueError("Invalid Chempat combinations!")


ALL_COMPOSITE_KEM_COMBINATIONS = [
    {"pq_name": "ml-kem-768", "trad_name": "x25519"},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": 2048},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": 3072},
    {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": 4096},
    {"pq_name": "ml-kem-768", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "ml-kem-768", "trad_name": "ec", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ec", "curve": "brainpoolP384r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "x448"},
]

ALL_COMPOSITE_KEM_FRDODOKEM_COMBINATIONS = [
    # Claimed NIST level 3
    {"pq_name": "frodokem-976-aes", "trad_name": "x25519"},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": 2048},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": 3072},
    {"pq_name": "frodokem-976-aes", "trad_name": "rsa", "length": 4096},
    {"pq_name": "frodokem-976-aes", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "frodokem-976-aes", "trad_name": "ec", "curve": "brainpoolP256r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "x25519"},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": 2048},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": 3072},
    {"pq_name": "frodokem-976-shake", "trad_name": "rsa", "length": 4096},
    {"pq_name": "frodokem-976-shake", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "frodokem-976-shake", "trad_name": "ec", "curve": "brainpoolP256r1"},
    # Claimed NIST level 5
    {"pq_name": "frodokem-1344-aes", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "ec", "curve": "brainpoolP384r1"},
    {"pq_name": "frodokem-1344-aes", "trad_name": "x448"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ec", "curve": "secp384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "ec", "curve": "brainpoolP384r1"},
    {"pq_name": "frodokem-1344-shake", "trad_name": "x448"},
]

ALL_COMPOSITE_KEM_COMBINATIONS += ALL_COMPOSITE_KEM_FRDODOKEM_COMBINATIONS


def _get_kem_comp_combinations(
    pq_name: Optional[str] = None,
    trad_name: Optional[str] = None,
    length: Optional[Strint] = None,
    curve: Optional[str] = None,
) -> dict:
    """Generate a matching combination of post-quantum and traditional key exchange algorithms.

    :param pq_name: The post-quantum key exchange algorithm.
    :param trad_name: The traditional key exchange algorithm.
    :param length: The length of the RSA key.
    :param curve: The curve of the EC key.
    :return: The post-quantum and traditional key instances.
    """
    if length is not None:
        length = int(length)

    if pq_name is None and trad_name is None:
        return {"pq_name": "ml-kem-768", "trad_name": "x25519"}

    if pq_name is None and trad_name is None and curve is None and length is None:
        return {"pq_name": "ml-kem-768", "trad_name": "x25519"}

    for entry in ALL_COMPOSITE_KEM_COMBINATIONS:
        if pq_name is not None and entry["pq_name"] != pq_name:
            continue

        if trad_name is not None and entry["trad_name"] != trad_name:
            continue

        if length is not None and entry.get("length") != length:
            continue

        if curve is not None and entry.get("curve") != curve:
            continue

        return entry

    raise ValueError("Invalid combination of post-quantum and traditional composite-kem key.")


class HybridKeyFactory:
    """Factory for creating composite keys based on classical key types."""

    @staticmethod
    def from_keys(algorithm: str, pq_key, trad_key):
        """Create a composite key from existing keys.

        :param algorithm: The hybrid algorithm.
        :param pq_key: The post-quantum key.
        :param trad_key: The traditional key.
        :return: A composite key.
        """
        if algorithm == "xwing":
            if pq_key is None:
                pq_key = PQKeyFactory.generate_pq_key("ml-kem-768")

            if trad_key is None:
                trad_key = generate_ec_key("x25519", curve=None)

            return XWingPrivateKey(pq_key=pq_key, trad_key=trad_key)

        elif algorithm == "chempat":
            if pq_key is None and trad_key is None:
                raise ValueError("Either a pq_key or trad_key must be provided, to generate a chempat key.")

            if pq_key is None:
                if isinstance(trad_key, rsa.RSAPrivateKey):
                    raise ValueError("RSA is not supported as traditional key for Chempat.")

                if isinstance(trad_key, ec.EllipticCurvePrivateKey):
                    curve = trad_key.curve.name
                    trad_name = "ecdh"

                elif isinstance(trad_key, x25519.X25519PrivateKey):
                    trad_name = "x25519"
                    curve = None
                elif isinstance(trad_key, x448.X448PrivateKey):
                    trad_name = "x448"
                    curve = None
                else:
                    raise ValueError(f"Unsupported traditional key type: {type(trad_key)}")

                comp_key = HybridKeyFactory.generate_chempat(pq_name=None, trad_name=trad_name, curve=curve)
                pq_key = comp_key.pq_key

            if trad_key is None:
                pq_name = pq_key.name
                comp_key = HybridKeyFactory.generate_chempat(
                    pq_name=pq_name,
                )
                trad_key = comp_key.trad_key

            return ChempatPrivateKey(pq_key, trad_key)

        elif algorithm == "composite-kem":
            if pq_key is None and trad_key is None:
                raise ValueError("Either a pq_key or trad_key must be provided, to generate a composite kem key.")

            if pq_key is None:
                if isinstance(trad_key, rsa.RSAPrivateKey):
                    length = min(max(trad_key.key_size, 2048), 4096)
                    curve = None
                    trad_name = "rsa"
                elif isinstance(trad_key, ec.EllipticCurvePrivateKey):
                    length = None
                    curve = trad_key.curve.name
                    trad_name = "ec"
                elif isinstance(trad_key, x25519.X25519PrivateKey):
                    length = None
                    curve = None
                    trad_name = "x25519"
                elif isinstance(trad_key, x448.X448PrivateKey):
                    length = None
                    curve = None
                    trad_name = "x448"
                else:
                    raise ValueError(f"Unsupported traditional key type: {type(trad_key)}")

                comp_key = HybridKeyFactory.generate_comp_kem_key(
                    pq_name=None, trad_name=trad_name, length=length, curve=curve
                )

                return CompositeKEMPrivateKey(pq_key=comp_key.pq_key, trad_key=trad_key)

            if trad_key is None:
                pq_name = pq_key.name
                comp_key = HybridKeyFactory.generate_comp_kem_key(
                    pq_name=pq_name,
                )
                return CompositeKEMPrivateKey(pq_key, comp_key.trad_key)

            return CompositeKEMPrivateKey(pq_key, trad_key)

        elif algorithm == "composite-sig":
            if pq_key is None and trad_key is None:
                raise ValueError("Either a pq_key or trad_key must be provided, to generate a composite sig key.")

            if pq_key is None:
                if isinstance(trad_key, rsa.RSAPrivateKey):
                    length = min(max(trad_key.key_size, 2048), 4096)
                    curve = None
                    trad_name = "rsa"
                elif isinstance(trad_key, ec.EllipticCurvePrivateKey):
                    length = None
                    curve = trad_key.curve.name
                    trad_name = "ecdsa"
                elif isinstance(trad_key, ed448.Ed448PrivateKey):
                    length = None
                    curve = None
                    trad_name = "ed448"
                elif isinstance(trad_key, ed25519.Ed25519PrivateKey):
                    length = None
                    curve = None
                    trad_name = "ed25519"
                else:
                    raise ValueError(f"Unsupported traditional key type: {type(trad_key)}")

                comp_key = HybridKeyFactory.generate_comp_sig_key(
                    pq_name=None, trad_name=trad_name, length=length, curve=curve
                )

                pq_key = comp_key.pq_key

            if trad_key is None:
                pq_name = pq_key.name
                return HybridKeyFactory.generate_comp_sig_key(
                    pq_name=pq_name,
                )

            return CompositeSigCMSPrivateKey(pq_key, trad_key)

        elif algorithm == "composite-dhkem":
            keys = HybridKeyFactory.from_keys(algorithm="composite-kem", pq_key=pq_key, trad_key=trad_key)
            return CompositeDHKEMRFC9180PrivateKey(pq_key=keys.pq_key, trad_key=keys.trad_key)
        else:
            raise NotImplementedError(f"Unsupported hybrid algorithm: {algorithm}")

    @staticmethod
    def get_all_kem_coms_as_dict() ->Dict[str, List[Dict]]:
        """Return a dictionary of all possible hybrid key combinations to generate a stat table."""
        data = {"xwing": [{}]}
        data["composite-kem"] = ALL_COMPOSITE_KEM_COMBINATIONS
        data["chempat"] = ALL_CHEMPAT_POSS_COMBINATIONS
        return data

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return a list of supported hybrid algorithms."""
        return ["xwing", "composite-sig", "composite-kem", "composite-dhkem", "chempat"]

    @staticmethod
    def generate_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ):
        """Generate a hybrid key.

        :param algorithm: The hybrid key algorithm.
        :param pq_name: Name of the post-quantum key algorithm.
        :param trad_name: Name of the traditional key algorithm.
        :param length: Length of the RSA key.
        :param curve: Curve of the EC key.
        :return: Instance of a Hybrid key.
        """
        if algorithm == "xwing":
            return XWingPrivateKey.generate()
        elif algorithm == "composite-sig":
            return HybridKeyFactory.generate_comp_sig_key(
                pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
            )
        elif algorithm == "composite-kem":
            return HybridKeyFactory.generate_comp_kem_key(
                pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
            )

        elif algorithm == "composite-dhkem":
            keys = HybridKeyFactory.generate_comp_kem_key(
                pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
            )

            return CompositeDHKEMRFC9180PrivateKey(pq_key=keys.pq_key, trad_key=keys.trad_key)

        elif algorithm == "chempat":
            return HybridKeyFactory.generate_chempat(pq_name=pq_name, trad_name=trad_name, curve=curve)
        else:
            raise ValueError(f"Unknown hybrid key algorithm: {algorithm}")

    @staticmethod
    def _get_combinations(
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ):
        """
        Get the valid combinations of post-quantum and traditional signature algorithms.

        :param pq_name: Name of the post-quantum signature algorithm.
        :param trad_name: Name of the traditional signature algorithm.
        :param length: Length of the traditional signature key.
        :param curve: Curve of the traditional signature key.
        :return: The pq and traditional key instances.
        """
        if pq_name is None or trad_name is None:
            key_params = get_valid_comb(pq_name=pq_name, trad_name=trad_name)
            pq_key = PQKeyFactory.generate_pq_key(key_params["pq_name"])
            trad_key = keyutils.generate_key(
                algorithm=key_params["trad_name"], length=key_params.get("length"), curve=key_params.get("curve")
            )
        else:
            pq_key = PQKeyFactory.generate_pq_key(pq_name)
            trad_key = keyutils.generate_key(algorithm=trad_name, length=length, curve=curve)

        return pq_key, trad_key

    @staticmethod
    def generate_comp_sig_key(
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ) -> AbstractCompositeSigPrivateKey:
        """
        Generate a composite signature key.

        :param pq_name: Name of the post-quantum signature algorithm.
        :param trad_name: Name of the traditional signature algorithm.
        :return: Instance of a subclass of Abstract
        """
        pq_key, trad_key = HybridKeyFactory._get_combinations(
            pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
        )
        return CompositeSigCMSPrivateKey(pq_key, trad_key)

    @staticmethod
    def generate_comp_kem_key(
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ) -> CompositeKEMPrivateKey:
        """Generate a composite KEM key.

        :param pq_name: Name of the post-quantum key exchange algorithm.
        :param trad_name: Name of the traditional key exchange algorithm.
        :param length: Length of the RSA key.
        :param curve: Curve of the EC key.
        :return: A `CompositeMLKEMPrivateKey` instance.
        :raises InvalidKeyCombination: If the algorithm combination is not supported.
        """
        if pq_name in ["frodokem-aes-640", "frdokem-shake-640"]:
            raise InvalidKeyCombination(
                "FrodoKEM-640 is not supported as a composite KEM key, because it only claims NIST level 1!"
            )

        if pq_name is not None and pq_name not in ([entry["pq_name"] for entry in ALL_COMPOSITE_KEM_COMBINATIONS]):
            raise InvalidKeyCombination(f"Unsupported post-quantum key exchange algorithm: {pq_name}")

        key_params = _get_kem_comp_combinations(pq_name=pq_name, trad_name=trad_name, length=length, curve=curve)

        pq_key = PQKeyFactory.generate_pq_key(key_params["pq_name"])
        trad_key = generate_trad_key(
            algorithm=key_params["trad_name"], length=key_params.get("length"), curve=key_params.get("curve")
        )

        return parse_private_keys(pq_key, trad_key)

    @staticmethod
    def generate_chempat(
        pq_name: Optional[str] = None, trad_name: Optional[str] = None, curve: Optional[str] = None
    ) -> ChempatPrivateKey:
        """Create a `ChempatPrivateKey` instance based on the traditional key or pq-key type.

        :param pq_name: The post-quantum algorithm name.
        :param trad_name: The traditional algorithm name.
        :param curve: The EC-curve name of the traditional algorithm.
        :return: A `ChempatPrivateKey` instance.
        """
        if pq_name is None or trad_name is None:
            key_params = _get_chempat_combinations(pq_name=pq_name, trad_name=trad_name, curve=curve)

            pq_key = PQKeyFactory.generate_pq_key(key_params["pq_name"])
            trad_key = generate_trad_key(
                algorithm=key_params["trad_name"], length=key_params.get("length"), curve=key_params.get("curve")
            )
        else:
            pq_key = PQKeyFactory.generate_pq_key(algorithm=pq_name)
            trad_key = generate_ec_key(algorithm=trad_name, curve=curve)

        return ChempatPrivateKey.parse_keys(pq_key, trad_key)
