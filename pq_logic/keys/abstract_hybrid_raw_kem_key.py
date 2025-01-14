# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract class for a hybrid raw keys which perform a key encapsulation mechanism (KEM)"""

import base64
import textwrap
from abc import ABC, abstractmethod
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5958, rfc5280

from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.serialize_utils import prepare_enc_key_pem


class AbstractHybridRawPublicKey(ABC):
    """Abstract class for a raw hybrid public key."""

    def __eq__(self, other):
        if not type(self) == type(other):
            raise ValueError(f"Cannot compare `{type(self)}` with `{type(other)}`")
        return self.pq_key == other.pq_key and self.trad_key == other.trad_key

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: x25519.X25519PublicKey):
        """
        Initialize the public key with post-quantum and traditional public keys.

        :param pq_key: Post-quantum public key.
        :param trad_key: Traditional public key (X25519).
        """
        self.pq_key = pq_key
        self.trad_key = trad_key

    @abstractmethod
    def get_oid(self) -> univ.ObjectIdentifier:
        """Get the OID of the key."""
        pass

    @abstractmethod
    def public_bytes_raw(self) -> bytes:
        """Serialize the public key to raw bytes."""
        pass

    @classmethod
    def from_public_bytes(cls, data: bytes):
        """Deserialize raw bytes into a public key.

        :param data: Concatenated raw bytes.
        :return: An instance of AbstractHybridRawPublicKey.
        """
        pass


    def _to_spki(self) -> bytes:
        """Encode the public key into the `SubjectPublicKeyInfo` (spki) format.

        :return: The public key in DER-encoded spki format as bytes.
        """
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(self.public_bytes_raw())
        return encoder.encode(spki)

    def public_bytes(
            self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        """Get the serialized public key in bytes format.

        Serialize the public key into the specified encoding (`Raw`, `DER`, or `PEM`) and
        format (`Raw` or `SubjectPublicKeyInfo`).

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
                        Defaults to `Raw`.
        :param format: The public key format. Can be `PublicFormat.Raw` or `PublicFormat.SubjectPublicKeyInfo`.
                      Defaults to `SubjectPublicKeyInfo`.
        :return: The serialized public key as bytes (or string for PEM).
        :raises ValueError: If the combination of encoding and format is unsupported.
        """
        if encoding == encoding.Raw and format == PublicFormat.Raw:
            return self.public_bytes_raw()

        if encoding == Encoding.DER and format == PublicFormat.SubjectPublicKeyInfo:
            return self._to_spki()

        elif encoding == Encoding.PEM and format == PublicFormat.SubjectPublicKeyInfo:
            b64_encoded = base64.b64encode(self._to_spki()).decode("utf-8")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem = "-----BEGIN PUBLIC KEY-----\n" + b64_encoded + "\n-----END PUBLIC KEY-----\n"
            return pem.encode("utf-8")

        raise ValueError(
            "Unsupported combination of encoding and format. " "Only Raw-Raw, DER-SPKI, and PEM-SPKI are supported."
        )




class AbstractHybridRawPrivateKey(ABC):
    """Abstract class representing a hybrid raw private key."""

    def __init__(self, pq_key: MLKEMPrivateKey, trad_key: x25519.X25519PrivateKey):
        """
        Initialize the private key with post-quantum and traditional private keys.

        :param pq_key: Post-quantum private key (ML-KEM).
        :param trad_key: Traditional private key (X25519).
        """
        self.pq_key = pq_key
        self.trad_key = trad_key

    def _get_key_name(self) -> bytes:
        """Get the name of the key, to save the key to a file."""
        return b"HYBRID-RAW-KEY"

    @classmethod
    @abstractmethod
    def generate(cls):
        """Generate a new hybrid private key consisting of a post-quantum key and a traditional X25519 key.

        :return: An instance of AbstractHybridRawPrivateKey.
        """
        pass

    def public_key(self) -> AbstractHybridRawPublicKey:
        """Generate the corresponding public key for the hybrid private key.

        :return: An instance of AbstractHybridRawPublicKey.
        """
        return AbstractHybridRawPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @abstractmethod
    def encaps(self, peer_key: AbstractHybridRawPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate the shared secret and ciphertext using the peer's public key.

        :param peer_key: The peer's public key.
        :return: A tuple containing the encapsulated shared secret and the encapsulated ciphertext.
        """
        pass

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate the shared secret using the provided ciphertext.

        :param ct: The ciphertext to decapsulate the shared secret from.
        :return: The shared secret.
        """
        pass

    @abstractmethod
    def private_bytes_raw(self) -> bytes:
        """Serialize the private key to raw bytes."""
        pass

    @classmethod
    @abstractmethod
    def from_private_bytes(cls, data: bytes):
        """Deserialize raw bytes into a private key."""
        pass

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the key. Default is to use the public key OID."""
        return self.public_key().get_oid()

    def _to_one_asym_key(self) -> bytes:
        """Convert the hybrid key to an `rfc5958.OneAsymmetricKey` object.

        :return: The serialized key as DER-encoded bytes.
        """
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = 1
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        one_asym_key["privateKey"] = self.private_bytes_raw()
        one_asym_key["publicKey"] = one_asym_key["publicKey"].fromOctetString(self.public_key().public_bytes_raw())

        return encoder.encode(one_asym_key)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """Get the serialized private key in bytes format.

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
        :param format: The private key format. Can be `PrivateFormat.Raw` or `PrivateFormat.PKCS8`.
        :return: The serialized private key as bytes.
        """
        if format != PrivateFormat.PKCS8:
            raise ValueError("Only PKCS8 format is supported.")

        if not isinstance(encryption_algorithm, serialization.NoEncryption) and encoding == encoding.DER:
            raise ValueError("Encryption is not supported for DER encoding, only for PEM.")

        if encoding == Encoding.DER:
            return self._to_one_asym_key()

        if encoding == encoding.PEM and isinstance(encryption_algorithm, serialization.BestAvailableEncryption):
            password = encryption_algorithm.password.decode("utf-8")
            return prepare_enc_key_pem(password, self._to_one_asym_key(), self._get_key_name())

        if encoding == Encoding.PEM:
            data = self._to_one_asym_key()
            b64_encoded = base64.b64encode(data).decode("utf-8")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem = "-----BEGIN PUBLIC KEY-----\n" + b64_encoded + "\n-----END PUBLIC KEY-----\n"
            return pem.encode("utf-8")

        raise NotImplementedError(f"The encoding is not supported. Encoding: {encoding} .Format: {format}.")
