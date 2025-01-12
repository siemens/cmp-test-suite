# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from resources import keyutils, oid_mapping
from resources.typingutils import Strint
from typing import Optional

from pq_logic.chempatkem import ChempatPrivateKey

from pq_logic.keys.abstract_composite import (
    AbstractCompositeSigPrivateKey,
)
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, get_valid_comb
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.pq_key_factory import PQKeyFactory

ALL_CHEMPAT_POSS_COMBINATIONS = [
    {"pq_name": "sntrup761", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece348864", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece460896", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece6688128", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece6960119", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece8192128", "trad_name": "x25519", "curve": None},
    {"pq_name": "McEliece348864", "trad_name": "x448", "curve": None},
    {"pq_name": "McEliece460896", "trad_name": "x448", "curve": None},
    {"pq_name": "McEliece6688128", "trad_name": "x448", "curve": None},
    {"pq_name": "McEliece6960119", "trad_name": "x448", "curve": None},
    {"pq_name": "McEliece8192128", "trad_name": "x448", "curve": None},
    {"pq_name": "ml-kem-768", "trad_name": "x25519", "curve": None},
    {"pq_name": "ml-kem-1024", "trad_name": "x448", "curve": None},
    {"pq_name": "ml-kem-768", "trad_name": "ec", "curve": "sepc256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ec", "curve": "sepc384r1"},
    {"pq_name": "ml-kem-768", "trad_name": "ec", "curve": "brainpoolP256r1"},
    {"pq_name": "ml-kem-1024", "trad_name": "ec", "curve": "brainpoolP384r1"},
]


def _get_chempat_combinations(
    pq_name: Optional[str] = None, trad_name: Optional[str] = None, curve: Optional[str] = None
) -> dict:
    """Create a matching Chempat combination of pq_name and trad_name.

    :param pq_name: The post-quantum algorithm.
    :param trad_name: The traditional algorithm.
    :param curve: The curve of the traditional algorithm.
    :return: A dictionary with the pq_name, trad_name and curve.
    """
    if pq_name is None or trad_name is None:
        return {"pq_name": "ml-kem-768", "trad_name": "x25519"}

    for entry in ALL_CHEMPAT_POSS_COMBINATIONS:
        if pq_name and entry["pq_name"] == pq_name:
            return entry

        if entry["trad_name"] == trad_name or curve == entry["curve"]:
            return entry

    return {"pq_name": pq_name, "trad_name": trad_name, "curve": curve}


# TODO fix for CompositeKEM
class CompositeKeyFactory:
    """
    Factory for creating composite keys based on classical key types.
    """

    @staticmethod
    def from_keys(algorithm: str, pq_key, trad_key):
        """Create a composite key from existing keys.

        :param algorithm: The hybrid algorithm.
        :param pq_key: The post-quantum key.
        :param trad_key: The traditional key.
        :return: A composite key.
        """

        if algorithm == "composite-sig":
            if pq_key is None and trad_key is None:
                raise ValueError("Either a pq_key or trad_key must be provided, to generate a composite key.")

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

                comp_key =  CompositeKeyFactory.generate_comp_sig_key(
                    pq_name=None, trad_name=trad_name, length=length, curve=curve
                )

                pq_key = comp_key.pq_key

            if trad_key is None:
                pq_name = pq_key.name
                return CompositeKeyFactory.generate_comp_sig_key(
                    pq_name=pq_name,
                )

            return CompositeSigCMSPrivateKey(pq_key, trad_key)
        else:
            raise NotImplementedError(f"Unsupported hybrid algorithm: {algorithm}")




    @staticmethod
    def generate_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ):
        """Generate a hybrid key.

        :param pq_name: Name of the post-quantum key algorithm.
        :param trad_name: Name of the traditional key algorithm.
        :return: Instance of a Hybrid key.
        """
        if algorithm == "xwing":
            return XWingPrivateKey.generate()
        elif algorithm == "composite_sig":
            return CompositeKeyFactory.generate_comp_sig_key(
                pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
            )

        elif algorithm == "composite_kem":
            raise NotImplementedError("Currently not supported to create a `composite_kem` hybrid key.")

        elif algorithm == "chempat":
            return CompositeKeyFactory.generate_chempat(pq_name=pq_name, trad_name=trad_name, curve=curve)
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
        pq_key, trad_key = CompositeKeyFactory._get_combinations(
            pq_name=pq_name, trad_name=trad_name, length=length, curve=curve
        )
        return CompositeSigCMSPrivateKey(pq_key, trad_key)


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
            key_params = _get_chempat_combinations(pq_name=pq_name, trad_name=trad_name)

            pq_key = PQKeyFactory.generate_pq_key(key_params["pq_name"])
            trad_key = keyutils.generate_key(
                algorithm=key_params["trad_name"], length=key_params.get("length"), curve=key_params.get("curve")
            )
        else:
            pq_key = PQKeyFactory.generate_pq_key(pq_name)
            trad_key = keyutils.generate_key(algorithm=trad_name, curve=curve)

        return ChempatPrivateKey.parse_keys(pq_key, trad_key)
