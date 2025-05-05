# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Stateful Hash Signature Key Classes."""

import logging
from abc import ABC, abstractmethod
from typing import Optional

from pyasn1.codec.der import decoder
from pyasn1.type import univ

from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey


class PQHashStatefulSigPublicKey(PQPublicKey, ABC):
    """Abstract base class for Post-Quantum Hash Stateful Signature Public Keys."""

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size."""

    @abstractmethod
    def verify(
        self,
        data: bytes,
        signature: bytes,
    ) -> Optional[int]:
        """Verify a signature of the provided data."""

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""

    def __eq__(self, other):
        """Compare two public keys for equality."""
        raise NotImplementedError("Equality check is not implemented for this class: type(self)")


class PQHashStatefulSigPrivateKey(PQPrivateKey, ABC):
    """Abstract base class for Post-Quantum Hash Stateful Signature Private Keys."""

    _sig_count: int

    def __init__(
        self,
        alg_name: str,
        private_bytes: Optional[bytes] = None,
        public_bytes: Optional[bytes] = None,
        seed: Optional[bytes] = None,
        count_sig: int = 0,
    ):
        """Initialize the private key object."""
        super().__init__(alg_name=alg_name, private_bytes=private_bytes, public_key=public_bytes, seed=seed)

        self._sig_count = count_sig

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size."""

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""

    def _check_sig_size(self, index: Optional[int]) -> int:
        """Check the signature size."""
        if index is None:
            index = self._sig_count

        if index >= self.max_sig_size:
            raise ValueError(f"Invalid signature index: {index}, max is {self.max_sig_size}")

        if index < self._sig_count:
            logging.warning("The signature index %s is already used", index)
        return index

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "PQHashStatefulSigPrivateKey":
        """Create a new private key object from the provided bytes."""
        count_sig, rest = decoder.decode(data, asn1Spec=univ.Integer())[0]
        key = cls(alg_name=name, private_bytes=rest, count_sig=count_sig)

        if key.key_size != len(data):
            raise ValueError(f"Invalid key size expected {key.key_size}, but got: {len(data)}")
        return key

    @abstractmethod
    def sign(self, data: bytes, index: Optional[int] = None) -> bytes:
        """Sign the provided data.

        :param data: The data to sign.
        :param index: The index of the secret key to use for signing.
        """
