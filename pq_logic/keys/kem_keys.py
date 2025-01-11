# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""
Provided Wrapper classes for Post-Quantum Key Encapsulation Mechanisms (KEM) Keys.

Classes in this file follow the `cryptography` library style. This ensures seamless integration
and allows the classes to be easily swapped out or extended in the future.

APIs are:

### Public Keys:
- `public_bytes(encoding: Encoding, format: PublicFormat)`: Serialize the public key into the specified encoding
and format.
- `_check_name(name: str)`: Validate the provided algorithm name.

### Private Keys:
- `public_key()`: Derive the corresponding public key from the private key.
- `generate(kem_alg: str)`: Generate a new private key for the specified algorithm.
- `_check_name(name: str)`: Validate the provided algorithm name.
"""
import logging
import os
from typing import Optional, Tuple

from pq_logic.fips.fips203 import ML_KEM
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.tmp_oids import FRODOKEM_NAME_2_OID

try:
    import oqs
except ImportError:
    logging.info("liboqs support is disabled.")
    oqs = None


##########################
# ML-KEM
##########################


class MLKEMPublicKey(PQKEMPublicKey):
    """Represents an ML-KEM public key."""


    def _initialize(self, kem_alg: str, public_key: bytes):
        """Initialize the ML-KEM public key.

        :param kem_alg: Algorithm name to use (e.g., "ml-kem-512").
        :param public_key: Public key as raw bytes.
        """

        if oqs is not None:
            super()._initialize(kem_alg=kem_alg, public_key=public_key)
        else:
            self._check_name(kem_alg)
            self.kem_alg = kem_alg
            self.ml_class = ML_KEM(kem_alg)
            self._public_key_bytes = public_key

    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return self.kem_alg.lower()

    def _check_name(self, name: str):
        """Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "ml-kem-512", "ml-kem-768", or "ml-kem-1024".
        """
        if name.lower() not in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            raise ValueError(
                f"Invalid ML-KEM algorithm name: {name}. Supported options: ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']"
            )
        self.kem_alg = name.upper()

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "MLKEMPublicKey":
        """Create an ML-KEM public key from raw bytes."""
        key = cls(kem_alg=name, public_key=data)
        return key

    def encaps(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""

        if oqs is not None:
            return super().encaps()
        else:
            return self.ml_class.encaps_internal(ek=self._public_key_bytes, m=os.urandom(32))



class MLKEMPrivateKey(PQKEMPrivateKey):
    """Represents an ML-KEM private key.

    This class provides functionality for validating, managing, and using ML-KEM private keys.
    """

    def _initialize(self, kem_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None):
        """Initialize the ML-KEM private key.

        :param kem_alg: Algorithm name to use (e.g., "ml-kem-512").
        :param private_bytes: Private key as raw bytes.
        :param public_key: Public key as raw bytes.
        """
        if oqs is not None:
            super()._initialize(kem_alg=kem_alg, private_bytes=private_bytes, public_key=public_key)
        else:
            logging.info("ML-DSA Key generation is done with pure python.")
            self._check_name(kem_alg)
            self.kem_alg = kem_alg
            self.ml_class = ML_KEM(kem_alg)

            if private_bytes is None:
                d, z = os.urandom(32), os.urandom(32)
                self._public_key, self._private_key = self.ml_class.keygen_internal(d=d, z=z)
            else:
                self._private_key = private_bytes
                self._public_key = public_key

    def _get_key_name(self) -> bytes:
        return b"ML-KEM"

    def _check_name(self, name: str):
        """Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "ml-kem-512", "ml-kem-768", or "ml-kem-1024".
        """
        if name not in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            raise ValueError(
                f"Invalid ML-KEM algorithm name: {name}. Supported options: ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']"
            )
        self.kem_alg = name.upper()

    @property
    def name(self) -> str:
        """Get the algorithm name for this private key.

        :return: The name of the algorithm (e.g., "ml-kem-512").
        """
        return self.kem_alg.lower()

    def public_key(self) -> MLKEMPublicKey:
        """Derive the corresponding ML-KEM public key from this private key.

        :return: An instance of `MLKEMPublicKey`.
        """
        if self._public_key_bytes is None:
            # addresses a bug in the liboqs-python library,
            # if a private key is parsed, the public key is not set.
            k = {"ml-kem-768": 3, "ml-kem-512": 2, "ml-kem-1024": 4}[self.name]
            self._public_key_bytes = self.private_bytes_raw()[384 * k : 768 * k + 32]

        return MLKEMPublicKey(public_key=self._public_key_bytes, kem_alg=self.kem_alg)

    @classmethod
    def generate(cls, kem_alg: str = "ml-kem-512") -> "MLKEMPrivateKey":
        """
        Generate a new ML-KEM private key.

        :param kem_alg: Algorithm name to use (default: "ml-kem-512").
        :return: An instance of `MLKEMPrivateKey`.
        """
        if kem_alg not in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            raise ValueError(
                f"Invalid ML-KEM algorithm name: {kem_alg}."
                f"Supported options: ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']"
            )
        return MLKEMPrivateKey(kem_alg=kem_alg)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "MLKEMPrivateKey":
        """
        Create an ML-KEM public key from raw bytes.

        :param data: The public key as raw bytes.
        :param name: The algorithm name.
        :return: An instance of `MLKEMPublicKey`.
        """
        key = cls(kem_alg=name, private_bytes=data)
        return key

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret using the private key.

        :param ct: The ciphertext to decapsulate the shared secret from.
        :return: The shared secret.
        """
        if oqs is not None:
            return super().decaps(ct)
        else:
            return self.ml_class.decaps_internal(dk=self._private_key, c=ct)


##########################
# McEliece
##########################

VALID_MCELIECE_OPTIONS = {
    "mceliece-348864": "Classic-McEliece-348864",
    "mceliece-460896": "Classic-McEliece-460896",
    "mceliece-6688128": "Classic-McEliece-6688128",
    "mceliece-6960119": "Classic-McEliece-6960119",
    "mceliece-8192128": "Classic-McEliece-8192128",
}


class McEliecePublicKey(PQKEMPublicKey):
    """
    Represents a McEliece public key.

    This class provides functionality for validating and managing McEliece public keys.
    """

    def _check_name(self, name: str):
        """Validate the provided algorithm name against supported McEliece options.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not supported.
        """
        for x, y in VALID_MCELIECE_OPTIONS.items():
            if y == name or x == name:
                self.kem_alg = y
                return
        raise ValueError(f"Invalid McEliece algorithm name: {name}. " f"Supported options: {VALID_MCELIECE_OPTIONS}")

    @property
    def name(self) -> str:
        """Return the algorithm name."""
        for x, y in VALID_MCELIECE_OPTIONS.items():
            if y == self.kem_alg:
                return x

        raise ValueError(
            f"Invalid McEliece algorithm name: {self.kem_alg}. Supported options: {VALID_MCELIECE_OPTIONS}"
        )

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "McEliecePublicKey":
        """
        Create a McEliece public key from raw bytes.

        :param data: The public key as raw bytes.
        :param name: The algorithm name.
        :return: An instance of `McEliecePublicKey`.
        """
        key = cls(kem_alg=name, public_key=data)
        return key


class McEliecePrivateKey(PQKEMPrivateKey):
    """
    Represents a McEliece private key.

    This class provides functionality for validating, managing, and using McEliece private keys.
    """

    @property
    def name(self) -> str:
        """Return the key algorithm name."""
        for x, y in VALID_MCELIECE_OPTIONS.items():
            if y == self.kem_alg:
                return x

        raise ValueError(
            f"Invalid McEliece algorithm name: {self.kem_alg}. Supported options: {VALID_MCELIECE_OPTIONS}"
        )

    def _get_key_name(self) -> bytes:
        return b"McEliece"

    def _check_name(self, name: str):
        """Validate the provided algorithm name against supported McEliece options.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not supported.
        """
        if name not in VALID_MCELIECE_OPTIONS:
            raise ValueError(f"Invalid McEliece algorithm name: {name}. Supported options: {VALID_MCELIECE_OPTIONS}")

        self.kem_alg = VALID_MCELIECE_OPTIONS[name]

    def public_key(self) -> McEliecePublicKey:
        """
        Derive the corresponding McEliece public key from this private key.

        :return: An instance of `McEliecePublicKey`.
        """
        return McEliecePublicKey(public_key=self._public_key_bytes, kem_alg=self.kem_alg)


##########################
# SNTRUP761
##########################


class Sntrup761PublicKey(PQKEMPublicKey):
    """
    Represents an SNTRUP761 public key.

    This class provides functionality for validating and managing SNTRUP761 public keys.
    """

    def _check_name(self, name: str):
        """
        Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "sntrup761".
        """
        if name != "sntrup761":
            raise ValueError(f"Invalid key name '{name}'. Expected 'sntrup761'.")
        self.kem_alg = name

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "Sntrup761PublicKey":
        """
        Create an Sntrup761 public key from raw bytes.

        :param data: The public key as raw bytes.
        :param name: The algorithm name.
        :return: An instance of `Sntrup761PublicKey`.
        """
        key = cls(kem_alg=name, public_key=data)
        key._check_name(name)
        return key


class Sntrup761PrivateKey(PQKEMPrivateKey):
    """
    Represents an SNTRUP761 private key.

    This class provides functionality for validating, managing, and using SNTRUP761 private keys.
    """

    def _get_key_name(self) -> bytes:
        return b"SNTRUP761"

    def _check_name(self, name: str):
        """
        Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "sntrup761".
        """
        if name != "sntrup761":
            raise ValueError(f"Invalid key name '{name}'. Expected 'sntrup761'.")

        self.kem_alg = name

    @property
    def name(self) -> str:
        """
        Get the algorithm name for this private key.

        :return: The name of the algorithm, "sntrup761".
        """
        return self.kem_alg

    def public_key(self) -> Sntrup761PublicKey:
        """
        Derive the corresponding SNTRUP761 public key from this private key.

        :return: An instance of `Sntrup761PublicKey`.
        """
        return Sntrup761PublicKey(public_key=self._public_key_bytes, kem_alg="sntrup761")

    @classmethod
    def generate(cls) -> "Sntrup761PrivateKey":
        """
        Generate a new SNTRUP761 private key.

        :return: An instance of `Sntrup761PrivateKey`.
        """
        return Sntrup761PrivateKey(kem_alg="sntrup761")


##########################
# FrodoKEM key
##########################


class FrodoKEMPublicKey(PQKEMPublicKey):
    """Represents a FrodoKEM public key."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str):
        """Create a FrodoKEM public key from raw bytes."""
        return cls(kem_alg=name, public_key=data)

    def _check_name(self, name: str):
        """Validate the provided algorithm name."""
        if name.lower() not in FRODOKEM_NAME_2_OID:
            raise ValueError(f"Invalid key name '{name}'. Expected one of {FRODOKEM_NAME_2_OID.keys()}.")

        self.kem_alg = name.upper().replace("FRODOKEM", "FrodoKEM")


class FrodoKEMPrivateKey(PQKEMPrivateKey):
    """Represents a FrodoKEM private key."""

    def _check_name(self, name: str):
        """Validate the provided algorithm name."""
        if name not in FRODOKEM_NAME_2_OID:
            raise ValueError(f"Invalid key name '{name}'. Expected one of {FRODOKEM_NAME_2_OID.keys()}.")

        self.kem_alg = name.upper().replace("FRODOKEM", "FrodoKEM")

    def _get_key_name(self) -> bytes:
        """Return the key name to write the PEM-header for the key."""
        return b"FrodoKEM"

    def public_key(self) -> FrodoKEMPublicKey:
        """Derive the corresponding public key from the private key."""
        return FrodoKEMPublicKey(public_key=self._public_key_bytes, kem_alg=self.kem_alg)
