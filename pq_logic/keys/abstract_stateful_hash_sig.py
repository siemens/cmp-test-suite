# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Stateful Hash Signature Key Classes."""

from abc import ABC, abstractmethod
from typing import Any

from pyasn1.type import univ

from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey
from resources.oidutils import PQ_NAME_2_OID


class PQHashStatefulSigPublicKey(PQPublicKey, ABC):
    """Abstract base class for Post-Quantum Hash Stateful Signature Public Keys."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the public key."""
        if self.name.startswith("xmss-") or self.name.startswith("xmssmt-"):
            alg_name = self.name.split("-")[0]
        else:
            alg_name = self.name.split("_")[0]
        return PQ_NAME_2_OID[alg_name]

    @abstractmethod
    def verify(
        self,
        data: bytes,
        signature: bytes,
    ) -> int:
        """Verify a signature of the provided data.

        :param data: The data to verify.
        :param signature: The signature to verify.
        :return: The leaf index if the signature is valid, otherwise raises an exception.
        :raises InvalidSignature: If the signature is invalid.
        """

    @classmethod
    @abstractmethod
    def from_public_bytes(cls, data: bytes) -> "PQHashStatefulSigPublicKey":
        """Create a new public key object from the provided bytes."""

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""

    def __eq__(self, other: Any) -> bool:
        """Compare two public keys for equality."""
        if not isinstance(other, PQHashStatefulSigPublicKey):
            return False
        if self.name != other.name or self.public_bytes_raw() != other.public_bytes_raw():
            return False
        return True

    @abstractmethod
    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the public key.

        :return: The leaf index.
        :raises ValueError: If the signature is invalid or cannot be extracted.
        """

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size."""


class PQHashStatefulSigPrivateKey(PQPrivateKey, ABC):
    """Abstract base class for Post-Quantum Hash Stateful Signature Private Keys."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the public key."""
        if self.name.startswith("xmss-") or self.name.startswith("xmssmt-"):
            alg_name = self.name.split("-")[0]
        else:
            alg_name = self.name.split("_")[0]
        return PQ_NAME_2_OID[alg_name]

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Return the private key as bytes."""

    @abstractmethod
    def public_key(self) -> PQHashStatefulSigPublicKey:
        """Return the corresponding public key for this private key."""

    @abstractmethod
    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from the signature.

        :param signature: The signature to extract the leaf index from.
        :return: The leaf index if it can be extracted, otherwise None.
        """

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "PQHashStatefulSigPrivateKey":
        """Create a new private key object from the provided bytes."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign the provided data.

        :param data: The data to sign.
        """

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size."""

    @property
    @abstractmethod
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining for this private key."""
