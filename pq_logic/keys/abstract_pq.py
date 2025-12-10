# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Utility for preparing and generating post-quantum keys."""

import importlib.util
import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from pq_logic.keys.abstract_wrapper_keys import KEMPrivateKey, KEMPublicKey, PQPrivateKey, PQPublicKey
from resources.exceptions import InvalidKeyData

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name


class PQSignaturePublicKey(PQPublicKey, ABC):
    """Abstract base class for Post-Quantum Signature Public Keys."""

    _sig_method: Optional["oqs.Signature"]

    def _initialize_key(self) -> None:
        """Initialize the `PQSignaturePublicKey` object."""
        if oqs is None:
            raise ImportError("The `liboqs` is not installed.")

        self._sig_method = oqs.Signature(self._other_name)

    @abstractmethod
    def check_hash_alg(
        self,
        hash_alg: Union[None, str, hashes.HashAlgorithm],
    ) -> Optional[str]:
        """Check if the hash algorithm is valid and return the name of the hash algorithm.

        If the name is invalid returns `None`.

        :return: The name of the hash algorithm.
        """

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify a signature of the provided data.

        :param signature: The signature of the provided data.
        :param data: The data to verify against the signature.
        :param hash_alg: The pre-hashed hash algorithm used for the pre-hashed data
        or supposed to be used.
        :param is_prehashed: Flag indicating if the pre-hashed data is to be verified
        (without the hash-oid.).
        :param ctx: The optional context to use.
        :raises InvalidSignature: If the signature is invalid.
        """
        self.check_hash_alg(hash_alg)

        if hash_alg is not None:
            raise NotImplementedError("Currently can the hash algorithm not parsed directly.")

        if is_prehashed:
            raise NotImplementedError("Currently can the pre-hashed data not parsed, in python-liboqs.")

        try:
            if ctx != b"":
                result = self._sig_method.verify_with_ctx_str(data, signature, ctx, self._public_key_bytes)
            else:
                result = self._sig_method.verify(data, signature, self._public_key_bytes)
        except RuntimeError as e:
            raise InvalidSignature(f"Signature verification failed, for {self.name}.") from e

        if not result:
            raise InvalidSignature(f"Signature verification failed, for {self.name}.")

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        return self._sig_method.details["length_signature"]

    @property
    def nist_level(self) -> int:
        """Return the claimed NIST security level as string."""
        return int(self._sig_method.details["claimed_nist_level"])


class PQSignaturePrivateKey(PQPrivateKey, ABC):
    """Abstract base class for Post-Quantum Signature Private Keys."""

    _sig_method: Optional["oqs.Signature"]

    def _initialize_key(self) -> None:
        """Initialize the private key and public key bytes."""
        self._sig_method = oqs.Signature(
            self._other_name,  # type: ignore
            secret_key=self._private_key_bytes,
        )

        self._public_key_bytes = self._public_key_bytes or self._sig_method.generate_keypair()  # type: ignore
        self._private_key_bytes = self._private_key_bytes or self._sig_method.export_secret_key()  # type: ignore

    @abstractmethod
    def public_key(self) -> PQSignaturePublicKey:
        """Derive the corresponding public key."""

    def check_hash_alg(
        self,
        hash_alg: Union[None, str, hashes.HashAlgorithm],
    ) -> Optional[str]:
        """Check if a specified or parsed hash algorithm is allowed."""
        return self.public_key().check_hash_alg(hash_alg)

    def sign(
        self,
        data: bytes,
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        ctx: bytes = b"",
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign provided data.

        :param data: The data to sign.
        :param hash_alg: The pre-hashed hash algorithm used for the pre-hashed data
        or supposed to be used.
        :param ctx: The optional context to use.
        :param is_prehashed: Flag indicating if the pre-hashed data is to be verified.
        (without the hash-oid.)
        :return: The signature as bytes.
        """
        self.check_hash_alg(hash_alg)

        if hash_alg is not None:
            raise NotImplementedError("Currently can the hash algorithm not parsed directly.")

        if is_prehashed:
            raise NotImplementedError("Currently can the pre-hashed data not parsed, in python-liboqs.")

        if ctx != b"":
            return self._sig_method.sign_with_ctx_str(data, ctx)  # type: ignore
        return self._sig_method.sign(data)  # type: ignore

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        return self._sig_method.details["length_signature"]

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        return len(self._private_key_bytes)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "PQSignaturePrivateKey":
        """Create a new private key object from the provided bytes."""
        key = cls(alg_name=name, private_bytes=data)
        if key.key_size != len(data):
            raise ValueError(f"Invalid key size expected {key.key_size}, but got: {len(data)}")
        return key

    @property
    def nist_level(self) -> int:
        """Return the claimed NIST security level as string."""
        return self.public_key().nist_level


class PQKEMPublicKey(PQPublicKey, KEMPublicKey, ABC):
    """Abstract base class for Post-Quantum KEM Public Keys."""

    _kem_method: Optional["oqs.KeyEncapsulation"]  # type: ignore

    def _initialize_key(self):
        """Initialize the KEM method, defaults to liboqs."""
        self._kem_method = oqs.KeyEncapsulation(self._other_name)  # type: ignore

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @property
    def ct_length(self) -> int:
        """Return the size of the ciphertext."""
        return self._kem_method.details["length_ciphertext"]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        return self._kem_method.details["length_public_key"]

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "PQKEMPublicKey":
        """Create a new public key object from the provided bytes."""
        key = cls(alg_name=name, public_key=data)
        if key.key_size != len(data):
            raise InvalidKeyData(f"Invalid key size expected {key.key_size}, but got: {len(data)}")
        return key

    def encaps(self) -> Tuple[bytes, bytes]:
        """Perform encapsulation to generate a shared secret.

        :return: The shared secret and the ciphertext as bytes.
        """
        ct, ss = self._kem_method.encap_secret(self._public_key_bytes)
        return ss, ct

    @property
    def nist_level(self) -> int:
        """Return the claimed NIST security level as string."""
        return int(self._kem_method.details["claimed_nist_level"])


class PQKEMPrivateKey(PQPrivateKey, KEMPrivateKey, ABC):
    """Concrete implementation of a Post-Quantum KEM Private Key.

    This class provides functionality to manage, serialize, and use KEM private keys.
    """

    _kem_method: Optional["oqs.KeyEncapsulation"]  # type: ignore

    def _initialize_key(self):
        """Initialize the KEM method, defaults to liboqs."""
        if oqs is None:
            raise ImportError(f"The `liboqs` is not installed, The {self.name} key cannot be used.")

        self._kem_method = oqs.KeyEncapsulation(
            self._other_name,  # type: ignore
            secret_key=self._private_key_bytes,
        )

        if self._private_key_bytes is None:
            self._public_key_bytes = self._kem_method.generate_keypair()

        # MUST first generate a keypair, before the secret key can be exported.
        self._private_key_bytes = self._private_key_bytes or self._kem_method.export_secret_key()  # type: ignore

    def decaps(self, ct: bytes) -> bytes:
        """Perform decapsulation to retrieve a shared secret.

        Use the ciphertext to recover the shared secret corresponding to this private key.

        :param ct: The ciphertext generated during encapsulation.
        :return: The shared secret as bytes.
        """
        return self._kem_method.decap_secret(ct)

    @property
    def ct_length(self) -> int:
        """Return the size of the ciphertext."""
        return self._kem_method.details["length_ciphertext"]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        return self._kem_method.details["length_secret_key"]

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str):
        """Create a new private key object from the provided bytes.

        :param data: The private key as bytes.
        :param name: The algorithm name.
        :return: The private key object.
        :raises ValueError: If the key size does not match the expected size.
        """
        key = cls(alg_name=name, private_bytes=data)
        if len(data) != key.key_size:
            raise ValueError(f"Invalid private key size for {cls.name}. Expected {key.key_size}, got {len(data)}")
        return key

    @abstractmethod
    def public_key(self) -> PQKEMPublicKey:
        """Derive the corresponding public key."""

    @property
    def nist_level(self) -> int:
        """Return the claimed NIST security level as string."""
        return self.public_key().nist_level

    @staticmethod
    def _seed_size(name: str) -> int:
        """Return the size of the seed used for key generation."""
        if oqs is None:
            raise ImportError("The `liboqs` is not installed.")
        _kem_method = oqs.KeyEncapsulation(name)
        if not hasattr(_kem_method, "length_keypair_seed"):
            logging.warning("The KEM method does not support keypair seed length, returning 0.")
            return 0
        return _kem_method.length_keypair_seed if _kem_method else 0

    @property
    def seed_size(self) -> int:
        """Return the size of the seed used for key generation."""
        return self._seed_size(self._other_name)
