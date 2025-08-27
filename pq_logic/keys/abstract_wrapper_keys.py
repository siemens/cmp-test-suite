# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=redefined-builtin
"""Abstract classes for public and private keys.

These classes define the abstract methods that must be implemented by the concrete
public and private key classes. The abstract classes provide a common interface for
working with public and private keys, and they define the methods for exporting the
keys in different formats.

The abstract classes follow the API functions defined in the `cryptography` library.

- The `public_bytes` and `private_bytes` methods are used to serialize the keys into
different formats, such as DER, PEM, or raw bytes.

- The `public_key` method is used to get the public key from a private key.

- The `from_public_bytes` and `from_private_bytes` methods are used to create public
and private keys from bytes (only for raw keys).

- The `public_bytes_raw` and `private_bytes_raw` methods are used to get the public
and private keys as raw bytes.

- The `get_oid` method is used to get the Object Identifier of the key.

- The `get_subject_public_key` method is used to get the public key for the
`SubjectPublicKeyInfo` structure.

The `WrapperPublicKey` and `WrapperPrivateKey` classes are abstract classes that should be able to
serialize the keys into different formats. The `BaseKey` class is an abstract class that provides
common functionality and properties for all key types.

The idea was to create a WrapperKey which supports are different challenges to allow the support
of diverse key exports, for that purpose, contains the wrapper classes for public and private keys.
The private functions are supposed to be used by the wrapper classes to export the keys in different formats.
The Factories are used to create the keys. Inside the `keyutils` is the logic how to create the keys and
work with them.



"""

import base64
import textwrap
from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958

from pq_logic.keys.serialize_utils import prepare_enc_key_pem
from resources.oidutils import PQ_NAME_2_OID

ECSignKey = Union[ec.EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey]
ECVerifyKey = Union[ec.EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey]

ECDHPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]
ECDHPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]

HybridTradPubComp = Union["TradKEMPublicKey", ECDHPublicKey, rsa.RSAPublicKey, ECVerifyKey]
HybridTradPrivComp = Union["TradKEMPrivateKey", ECDHPrivateKey, rsa.RSAPrivateKey, ECSignKey]

# TODO decide if the comparison function should raise a error if a public key and
# a None public key are compared.


# Base Key Class
# to add functionality and properties to all key types.


class BaseKey(ABC):
    """Abstract Base Class for all key types."""

    _name: str
    # this name is used if a library uses a different name style for the algorithm.
    _other_name: Optional[str]

    def __eq__(self, other) -> bool:
        """Compare two keys."""
        if not isinstance(other, BaseKey):
            return False
        return type(self) is type(other)

    @property
    def name(self) -> str:
        """Get the name of the key."""
        return self._name.lower()

    @abstractmethod
    def get_oid(self) -> univ.ObjectIdentifier:
        """Retrieve the Object Identifier of the key."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Retrieve the size of the key in bytes."""

    def _get_header_name(self) -> bytes:
        """Return the algorithm name, used in the header of the PEM file."""
        return b"BASE"


class WrapperPublicKey(BaseKey):
    """Abstract class for public keys."""

    _public_key_bytes: bytes

    def __eq__(self, other) -> bool:
        """Compare two public keys."""
        result = super().__eq__(other)
        if not result:
            return False
        return self._public_key_bytes == other._public_key_bytes

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Export the public key as bytes or seed for some PQ keys."""

    @abstractmethod
    def _get_subject_public_key(self) -> bytes:
        """Get the public key for the `SubjectPublicKeyInfo` structure.

        Will be included in the SubjectPublicKeyInfo structure,
        MUST not include the BIT STRING encoding.
        """

    def _to_spki(self) -> bytes:
        """Encode the public key into the `SubjectPublicKeyInfo` (spki) format.

        :return: The public key in DER-encoded spki format as bytes.
        """
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(self._get_subject_public_key())
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
        if encoding == Encoding.Raw and format.Raw == PublicFormat.Raw:
            return self._export_public_key()

        if encoding == Encoding.DER:
            if format == PublicFormat.SubjectPublicKeyInfo:
                return self._to_spki()
            raise ValueError(f"Unsupported format for DER encoding: {format}")

        if encoding == Encoding.PEM:
            if format == PublicFormat.SubjectPublicKeyInfo:
                data = self._to_spki()
            else:
                raise ValueError(f"Unsupported format for PEM encoding: {format}")

            b64_encoded = base64.b64encode(data).decode("ascii")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            _name = self._get_header_name()
            pem = f"-----BEGIN {_name} PUBLIC KEY-----\n" + b64_encoded + f"\n-----END {_name} PUBLIC KEY-----\n"
            return pem.encode("ascii")

        raise ValueError(f"Unsupported encoding: {encoding}")


class WrapperPrivateKey(BaseKey):
    """Abstract class for private keys."""

    @abstractmethod
    def public_key(self) -> WrapperPublicKey:
        """Get the public key."""

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Export the private key as bytes, to put it inside a `OneAsymmetricKey` `v0` structure."""

    def _to_one_asym_key(self) -> bytes:
        """Convert the private key to a OneAsymmetricKey structure.

        :return: The DER-encoded OneAsymmetricKey structure.
        """
        data = rfc5958.OneAsymmetricKey()
        data["version"] = 0
        data["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        data["privateKey"] = univ.OctetString(self._export_private_key())
        return encoder.encode(data)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm: Union[NoEncryption, BestAvailableEncryption] = NoEncryption(),
    ) -> bytes:
        """Get the serialized private key in bytes format.

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
        :param format: The private key format. Can be `PrivateFormat.Raw` or `PrivateFormat.PKCS8`.
        :param encryption_algorithm: The encryption algorithm to use. Defaults to `NoEncryption`.
        (Only `NoEncryption` and `BestAvailableEncryption` are supported).
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
            return prepare_enc_key_pem(password, self._to_one_asym_key(), key_name=self._get_header_name())

        if encoding == Encoding.PEM:
            data = self._to_one_asym_key()
            header_name = self._get_header_name()
            if isinstance(header_name, bytes):
                header_name = header_name.decode("ascii")

            b64_encoded = base64.b64encode(data).decode("ascii")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem_str = (
                f"-----BEGIN {header_name} PRIVATE KEY-----\n{b64_encoded}\n-----END {header_name} PRIVATE KEY-----\n"
            )
            return pem_str.encode("ascii")

        raise NotImplementedError(f"The encoding is not supported. Encoding: {encoding} .Format: {format}.")


class KEMPublicKey(WrapperPublicKey, ABC):
    """Abstract class for KEM public keys."""

    @classmethod
    @abstractmethod
    def encaps(cls, **kwargs) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and the ciphertext.

        :param kwargs: Additional arguments for encapsulation.
        :return: The shared secret and the ciphertext.
        """

    @property
    def ct_length(self):
        """Get the length of the ciphertext."""
        return len(self.encaps()[1])


class KEMPrivateKey(WrapperPrivateKey, ABC):
    """Abstract class for KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct: The ciphertext.
        :return: The shared secret.
        """

    @abstractmethod
    def public_key(self) -> KEMPublicKey:
        """Derive the public key from the private key."""

    @property
    def ct_length(self):
        """Get the length of the ciphertext."""
        return self.public_key().ct_length


class PQPublicKey(WrapperPublicKey, ABC):
    """Post-Quantum Public Key class."""

    _public_key_bytes: bytes

    def __init__(self, alg_name: str, public_key: bytes):
        """Initialize the PQPublicKey.

        :param public_key: The public key as bytes.
        :param alg_name: The name of the algorithm.
        """
        self._public_key_bytes = public_key
        self._name, self._other_name = self._check_name(alg_name)
        self._initialize_key()

    def __eq__(self, other: "Any") -> bool:
        """Compare two public keys.

        :param other: The other public key to compare with.
        :return: The result of the comparison.
        """
        if type(other) is not type(self):
            return False
        return self._public_key_bytes == other._public_key_bytes

    @abstractmethod
    def _initialize_key(self):
        """Initialize the key."""

    def _get_header_name(self) -> bytes:
        """Return the algorithm name, used in the header of the PEM file."""
        return b"PQ"

    def public_bytes_raw(self) -> bytes:
        """Return the public key as raw bytes."""
        return self._public_key_bytes

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes."""
        return self._public_key_bytes

    def get_oid(self) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""
        return PQ_NAME_2_OID[self.name]

    @abstractmethod
    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the parsed name is correct."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "PQPublicKey":
        """Create a public key from bytes."""
        key = cls(name, data)
        if len(data) != key.key_size:
            raise ValueError(f"Invalid key size. Expected {key.key_size}, but got: {len(data)}")
        return key

    def _get_subject_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return len(self.public_bytes_raw())


class PQPrivateKey(WrapperPrivateKey, ABC):
    """Post-Quantum Private Key class."""

    _seed: Optional[bytes]
    _private_key_bytes: bytes
    _public_key_bytes: bytes

    def __init__(
        self,
        alg_name: str,
        private_bytes: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        seed: Optional[bytes] = None,
    ):
        """Initialize the PQPrivateKey.

        :param alg_name: The name of the algorithm.
        :param private_bytes: The private key as bytes.
        :param public_key: The public key as bytes.
        :param seed: The seed used to generate the key pair.
        """
        self._name, self._other_name = self._check_name(alg_name)
        self._private_key_bytes = private_bytes  # type: ignore
        self._public_key_bytes = public_key  # type: ignore
        self._seed = seed
        self._initialize_key()

    @property
    def name(self) -> str:
        """Get the name of the key."""
        return self._name

    def _initialize_key(self):
        """Initialize the key."""
        # currently must be both keys for liboqs to work.
        if self._private_key_bytes is not None and self._public_key_bytes is not None:
            return
        if self._seed is not None:
            self._private_key_bytes, self._public_key_bytes, self._seed = self._from_seed(self._name, self._seed)
            return
        raise NotImplementedError("The private key can not be initialized without a seed or private key.")

    @staticmethod
    def _from_seed(alg_name: str, seed: bytes) -> Tuple[bytes, bytes, bytes]:
        """Generate a key pair from a seed.

        :param alg_name: The name of the algorithm.
        :param seed: The seed to generate the key pair.
        :return: The private key, the public key, and the seed.
        """
        raise NotImplementedError("The method `_from_seed` is not implemented.")

    @classmethod
    def from_seed(cls, alg_name: str, seed: bytes) -> "PQPrivateKey":
        """Generate a private key from a seed.

        :param alg_name: The name of the algorithm.
        :param seed: The seed to generate the key pair.
        :return: The generated private key.
        """
        private_key, public_key, seed = cls._from_seed(alg_name, seed)
        return cls(alg_name, private_key, public_key, seed)

    @abstractmethod
    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the parsed name is correct.

        :param name: The name to check.
        :return: The correct name and the name of the public key for OQS or other library.
        """

    def get_oid(self) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""
        return PQ_NAME_2_OID[self.name]

    def _to_one_asym_key(self) -> bytes:
        """Prepare a PyAsn1 OneAsymmetricKey structure."""
        one_asym_key = rfc5958.OneAsymmetricKey()
        # MUST be version 1 otherwise, liboqs will generate a wrong key.
        one_asym_key["version"] = 1
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        one_asym_key["privateKey"] = univ.OctetString(self._export_private_key())
        public_key_asn1 = univ.BitString(hexValue=self.public_key().public_bytes_raw().hex()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        one_asym_key["publicKey"] = public_key_asn1
        return encoder.encode(one_asym_key)

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        return self._private_key_bytes

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes."""
        return self._seed or self._private_key_bytes

    @abstractmethod
    def public_key(self) -> PQPublicKey:
        """Get the public key."""


class TradKEMPublicKey(KEMPublicKey, ABC):
    """Abstract class for traditional KEM public keys."""

    _public_key: Union[ECDHPublicKey, rsa.RSAPublicKey]

    def __eq__(self, other: "TradKEMPublicKey") -> bool:
        """Compare two public keys.

        :param other: The other public key to compare with.
        :return: The result of the comparison.
        :raises ValueError: If the types of the keys are different.
        """
        if not isinstance(other, TradKEMPublicKey):
            return False
        return self._public_key == other._public_key

    @abstractmethod
    def encaps(self, **kwargs) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and the ciphertext.

        :param kwargs: Additional arguments for encapsulation.
        :return: The shared secret and the ciphertext.
        """

    @property
    @abstractmethod
    def get_trad_name(self) -> str:
        """Get the name of the traditional algorithm."""

    @abstractmethod
    def encode(self) -> bytes:
        """Encode the public key."""


class TradKEMPrivateKey(KEMPrivateKey, ABC):
    """Abstract class for traditional KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct: The ciphertext.
        :return: The shared secret.
        """

    @abstractmethod
    def encode(self) -> bytes:
        """Encode the private key."""

    @abstractmethod
    def public_key(self) -> TradKEMPublicKey:
        """Derive the public key from the private key."""

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return self.public_key().ct_length

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Get the key size."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""
        return self.public_key().get_oid()

    @property
    def get_trad_name(self) -> str:
        """Get the name of the traditional algorithm."""
        return self.public_key().get_trad_name


class HybridPublicKey(WrapperPublicKey, ABC):
    """Abstract class for hybrid public keys."""

    _pq_key: PQPublicKey
    _trad_key: HybridTradPubComp

    def __init__(self, pq_key: PQPublicKey, trad_key: HybridTradPubComp):
        """Initialize the HybridPublicKey.

        :param pq_key: The post-quantum public key object.
        :param trad_key: The traditional public key object.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    def __eq__(self, other: Any):
        """Compare two hybrid public keys."""
        if not isinstance(other, HybridPublicKey):
            return False

        if other.name != self.name:
            return False

        return self._pq_key == other.pq_key and self._trad_key == other.trad_key  # type: ignore

    @property
    def pq_key(self) -> PQPublicKey:
        """Get the public key of the post-quantum algorithm."""
        return self._pq_key

    @property
    def trad_key(self) -> HybridTradPubComp:
        """Get the public key of the traditional algorithm."""
        return self._trad_key


class HybridPrivateKey(WrapperPrivateKey, ABC):
    """Abstract class for hybrid private keys."""

    _pq_key: PQPrivateKey
    _trad_key: HybridTradPrivComp

    def __init__(self, pq_key: PQPrivateKey, trad_key: HybridTradPrivComp):
        """Initialize the HybridPrivateKey.

        :param pq_key: The post-quantum private key object.
        :param trad_key: The traditional private key object.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    @property
    def pq_key(self) -> PQPrivateKey:
        """Get the private key of the post-quantum algorithm."""
        return self._pq_key

    @property
    def trad_key(self) -> HybridTradPrivComp:
        """Get the private key of the traditional algorithm."""
        return self._trad_key

    @abstractmethod
    def public_key(self) -> HybridPublicKey:
        """Get the public key."""


class HybridSigPublicKey(HybridPublicKey, ABC):
    """A public key for a hybrid signature scheme."""

    _trad_key: ECVerifyKey
    _name: str = "hybrid-sig"

    def __eq__(self, other: Any) -> bool:
        """Compare two hybrid public keys."""
        if not isinstance(other, HybridSigPublicKey):
            return False

        if other.name != self.name:
            return False

        return self._pq_key == other.pq_key and self._trad_key == other.trad_key

    @property
    def trad_key(self) -> ECVerifyKey:
        """Return the traditional key."""
        return self._trad_key

    @property
    def pq_key(self):
        """Return the pq key."""
        return self._pq_key  # type: ignore

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, hash_alg: Optional[str] = None) -> bool:
        """Verify the signature."""

    def _get_trad_key_name(self) -> str:
        """Return the name of the traditional key."""
        if isinstance(self._trad_key, ec.EllipticCurvePublicKey):
            return "ecdsa-" + self._trad_key.curve.name
        if isinstance(self._trad_key, ed25519.Ed25519PublicKey):
            return "ed25519"
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self._trad_key, rsa.RSAPublicKey):
            return f"rsa-{self._trad_key.key_size}"
        raise ValueError("Unsupported key type: " + str(type(self._trad_key)))

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return f"{self._name}-{self._pq_key.name}-{self._get_trad_key_name()}"


class HybridSigPrivateKey(HybridPrivateKey, ABC):
    """A private key for a hybrid signature scheme."""

    _trad_key: Union[ECSignKey, RSAPrivateKey]
    _name: str = "hybrid-sig"

    @property
    def trad_key(self) -> Union[ECSignKey, RSAPrivateKey]:
        """Return the traditional key."""
        return self._trad_key

    @property
    def pq_key(self):
        """Return the pq key."""
        return self._pq_key  # type: ignore

    @abstractmethod
    def sign(self, data: bytes, **kwargs) -> bytes:
        """Sign the message."""

    def _get_trad_key_name(self) -> str:
        """Return the name of the traditional key."""
        if isinstance(self._trad_key, ec.EllipticCurvePrivateKey):
            return "ecdsa-" + self._trad_key.curve.name
        if isinstance(self._trad_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self._trad_key, rsa.RSAPrivateKey):
            return f"rsa-{self._trad_key.key_size}"
        raise ValueError("Unsupported key type: " + str(type(self._trad_key)))

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return f"{self._name}-{self._pq_key.name}-{self._get_trad_key_name()}"


class HybridKEMPublicKey(HybridPublicKey, KEMPublicKey, ABC):
    """Abstract class for KEM public keys."""

    @abstractmethod
    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the hybrid KEM algorithm."""

    @abstractmethod
    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and the ciphertext.

        :param private_key: The ECDH private key to use for encapsulation. Defaults to `None`.
        :return: The shared secret and the ciphertext.
        """

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return len(self.encaps()[1])


class HybridKEMPrivateKey(HybridPrivateKey, KEMPrivateKey, ABC):
    """Abstract class for KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct: The ciphertext.
        :return: The shared secret.
        """

    @abstractmethod
    def public_key(self) -> HybridKEMPublicKey:
        """Derive the public key from the private key."""

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.public_key().ct_length

    def _get_trad_key_name(self) -> str:
        """Return the name of the traditional key."""
        if isinstance(self._trad_key, TradKEMPrivateKey):
            return self._trad_key.get_trad_name

        if isinstance(self._trad_key, ec.EllipticCurvePublicKey):
            return f"ecdh-{self._trad_key.curve.name.lower()}"

        if isinstance(self._trad_key, x25519.X25519PrivateKey):
            return "x25519"

        if isinstance(self._trad_key, x448.X448PrivateKey):
            return "x448"

        raise ValueError(f"Unsupported Hybrid KEM key type: {type(self._trad_key).__name__}")


class AbstractCompositePublicKey(HybridPublicKey, ABC):
    """Abstract class for Composite public keys."""

    _pq_key: PQPublicKey
    _trad_key: Union[ECDHPublicKey, rsa.RSAPublicKey]

    def _prepare_old_spki(self) -> rfc5280.SubjectPublicKeyInfo:
        """Prepare the old SPKI structure.

        :return: The prepared SPKI structure.
        """
        tmp = univ.SequenceOf()

        pq_der_data = self._pq_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pq_tmp = decoder.decode(pq_der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]

        trad_der_data = self._trad_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        trad_tmp = decoder.decode(trad_der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]

        tmp.append(pq_tmp)
        tmp.append(trad_tmp)

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(encoder.encode(tmp))
        return spki

    def _get_subject_public_key(self) -> bytes:
        """Get the public key for the `SubjectPublicKeyInfo` structure.

        Will be included in the SubjectPublicKeyInfo structure,
        MUST not include the BIT STRING encoding.
        """
        return self._export_public_key()

    def _get_trad_key_name(
        self,
        use_pss: bool = False,
    ) -> str:
        """Retrieve the traditional algorithm name based on the key type."""
        trad_key = self._trad_key
        if isinstance(trad_key, ec.EllipticCurvePublicKey):
            trad_name = f"ecdsa-{trad_key.curve.name}"
        elif isinstance(trad_key, rsa.RSAPublicKey):
            trad_name = f"rsa{trad_key.key_size}"
            if use_pss:
                trad_name += "-pss"
        elif isinstance(trad_key, ed25519.Ed25519PublicKey):
            trad_name = "ed25519"
        elif isinstance(trad_key, ed448.Ed448PublicKey):
            trad_name = "ed448"
        else:
            raise ValueError(f"Unsupported key type: {type(trad_key).__name__}")
        return trad_name

    @abstractmethod
    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""

    def encode_trad_part(self) -> bytes:
        """Encode the traditional part of the public key.

        :return: The traditional part of the public key as bytes.
        """
        if isinstance(self._trad_key, TradKEMPublicKey):
            return self._trad_key.encode()

        if isinstance(self._trad_key, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return self._trad_key.public_bytes_raw()

        if isinstance(self._trad_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            return self._trad_key.public_bytes_raw()

        if isinstance(self._trad_key, rsa.RSAPublicKey):
            return self._trad_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)

        return self._trad_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes.

        :return: The combined public key as bytes, starting with the PQ key and followed by the traditional key.
        """
        return self._pq_key.public_bytes_raw() + self.encode_trad_part()

    def to_spki(
        self, use_pss: bool = False, pre_hash: bool = False, use_2_spki: bool = False
    ) -> rfc5280.SubjectPublicKeyInfo:
        """Convert CompositePublicKey to a SubjectPublicKeyInfo structure.

        :param use_2_spki: Whether to use `SequenceOf` 2 SPKI structures.
        :param use_pss: Whether RSA-PSS padding was used (if RSA).
        :param pre_hash: Whether the prehashed version was used.
        :return: `SubjectPublicKeyInfo`.
        """
        if not use_2_spki:
            data = self._export_public_key()
        else:
            data = encoder.encode(self._prepare_old_spki())

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid(use_pss, pre_hash)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(data)
        return spki

    def public_bytes(
        self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        """Get the serialized public key in bytes format.

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
        :param format: The public key format. Can be `PublicFormat.Raw` or `PublicFormat.SubjectPublicKeyInfo`.
        :return: The serialized public key as bytes (or string for PEM).
        """
        if encoding == Encoding.DER and format == PublicFormat.Raw:
            return self._export_public_key()
        return super().public_bytes(encoding, format)

    @property
    def key_size(self) -> int:
        """Return the size of the key inside the DER encoded structure."""
        return len(self._export_public_key())


class AbstractCompositePrivateKey(HybridPrivateKey, ABC):
    """Abstract class for Composite private keys."""

    @abstractmethod
    def public_key(self) -> "AbstractCompositePublicKey":
        """Return the corresponding public key class."""

    def _export_trad_private_key(self) -> bytes:
        """Export the traditional part of the private key.

        :return: The traditional part of the private key as bytes.
        """
        if isinstance(self._trad_key, (X25519PrivateKey, X448PrivateKey, Ed25519PrivateKey, Ed448PrivateKey)):
            return self._trad_key.private_bytes_raw()

        if isinstance(self._trad_key, EllipticCurvePrivateKey):
            return self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

        if isinstance(self._trad_key, RSAPrivateKey):
            der = self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            decoded = decoder.decode(der, asn1Spec=rfc5958.OneAsymmetricKey())[0]
            return decoded["privateKey"].asOctets()

        return self._trad_key.encode()

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes.

        :return: The combined private key as bytes, starting with the PQ key and followed by the traditional key.
        """
        if hasattr(self._pq_key, "private_numbers"):
            return self._pq_key.private_numbers() + self._export_trad_private_key()
        return self._pq_key.private_bytes_raw() + self._export_trad_private_key()

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return len(self._export_private_key())

    @classmethod
    def _get_rsa_size(cls, value: int):
        """Return the closest size to the allowed RSA key."""
        predefined_values = [2048, 3072, 4096]
        return min(predefined_values, key=lambda x: abs(x - value))

    def _get_trad_key_name(self) -> str:
        """Return the name of the traditional key."""
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            return f"rsa{self._get_rsa_size(self.trad_key.key_size)}"
        if isinstance(self.trad_key, ec.EllipticCurvePrivateKey):
            _curve = self.trad_key.curve.name
            if "kem" in self.name:
                return f"ecdh-{_curve}"
            return f"ecdsa-{_curve}"

        if isinstance(self.trad_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self.trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self.trad_key, x25519.X25519PrivateKey):
            return "x25519"
        if isinstance(self.trad_key, x448.X448PrivateKey):
            return "x448"

        raise ValueError("Unsupported key type: " + str(type(self.trad_key)))


class AbstractHybridRawPublicKey(HybridKEMPublicKey, ABC):
    """Abstract class for a raw hybrid public key."""

    _pq_key: PQPublicKey
    _trad_key: ECDHPublicKey

    def __init__(self, pq_key: PQPublicKey, trad_key: ECDHPublicKey):
        """Initialize the HybridRawPublicKey.

        :param pq_key: The post-quantum public key object.
        :param trad_key: The traditional public key object.
        """
        super().__init__(pq_key, trad_key)
        self._pq_key = pq_key
        self._trad_key = trad_key

    @abstractmethod
    def public_bytes_raw(self) -> bytes:
        """Return the public key as raw bytes."""

    @classmethod
    @abstractmethod
    def from_public_bytes(cls, data: bytes) -> "AbstractHybridRawPublicKey":
        """Create a public key from bytes."""

    def _get_subject_public_key(self) -> bytes:
        """Get the public key for the `SubjectPublicKeyInfo` structure.

        Will be included in the SubjectPublicKeyInfo structure,
        MUST not include the BIT STRING encoding.
        """
        return self.public_bytes_raw()

    def _export_public_key(self) -> bytes:
        """Export the public key to be stored inside a `SubjectPublicKeyInfo` structure."""
        return self.public_bytes_raw()


class AbstractHybridRawPrivateKey(HybridKEMPrivateKey, ABC):
    """Abstract class for a raw hybrid private key."""

    _pq_key: PQPrivateKey
    _trad_key: ECDHPrivateKey

    def _encode_trad_part(self) -> bytes:
        """Encode the traditional part of the private key.

        :return: The traditional part of the private key as bytes.
        """
        if isinstance(self._trad_key, TradKEMPrivateKey):
            return self._trad_key.encode()

        if isinstance(self._trad_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
            return self._trad_key.private_bytes_raw()
        private_numbers = self._trad_key.private_numbers()
        return private_numbers.private_value.to_bytes(self._trad_key.key_size, byteorder="big")

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        return self._pq_key.private_bytes_raw() + self._encode_trad_part()

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes."""
        pq_data = self._pq_key.private_bytes_raw()
        _length = len(pq_data)
        return _length.to_bytes(4, "little") + pq_data + self._encode_trad_part()

    @classmethod
    @abstractmethod
    def from_private_bytes(cls, data: bytes) -> "AbstractHybridRawPrivateKey":
        """Create a private key from bytes."""
