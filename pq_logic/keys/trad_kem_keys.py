# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=redefined-builtin

"""Traditional key encapsulation mechanism classes for RSA and DHKEM."""

from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958, rfc6664, rfc9481

from pq_logic.kem_mechanism import DHKEMRFC9180, ECDHKEM, RSAKem, RSAOaepKem
from pq_logic.keys.abstract_wrapper_keys import TradKEMPrivateKey, TradKEMPublicKey
from pq_logic.tmp_oids import id_rsa_kem_spki
from resources.exceptions import InvalidKeyData
from resources.oid_mapping import get_curve_instance
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey


class RSAEncapKey(TradKEMPublicKey):
    """Wrapper class to support encaps method using RSA-OAEP or RSA-KEM."""

    _public_key: rsa.RSAPublicKey

    def __init__(self, public_key: Union[rsa.RSAPublicKey, "RSAEncapKey"]):
        """Initialize the encapsulation class with a given RSA public key.

        :param public_key: The RSA public key to use for encapsulation.
        """
        if isinstance(public_key, RSAEncapKey):
            public_key = public_key._public_key
        self._public_key = public_key

    @classmethod
    def from_spki(cls, spki: rfc5280.SubjectPublicKeyInfo) -> "RSAEncapKey":
        """Create an RSAEncapKey from a SubjectPublicKeyInfo.

        :param spki: The SubjectPublicKeyInfo bytes.
        :return: The RSAEncapKey instance.
        """
        spki["algorithm"]["algorithm"] = rfc9481.rsaEncryption
        der_data = encoder.encode(spki)
        public_key = serialization.load_der_public_key(der_data)

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise InvalidKeyData("Invalid RSA public key.")

        return cls(public_key)

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the encapsulation key."""
        return id_rsa_kem_spki

    def _get_subject_public_key(self) -> bytes:
        """Return the subject public key."""
        return self._export_public_key()

    def encaps(
        self, use_oaep: bool = True, hash_alg: str = "sha256", ss_length: Optional[int] = None
    ) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using RSA-OAEP if `use_oaep` is True, otherwise RSA-KEM.

        :param use_oaep: Flag to determine whether to use RSA-OAEP. Defaults to `True`.
        :param hash_alg: Hash algorithm to use for RSA-OAEP. Defaults to "sha256".
        :param ss_length: Length of the shared secret for RSA-KEM.
        (means for RSA-KEM that the KDF3 is applied to get the shared secret ref: RFC9690)
        Defaults for RSA-OAEP to 32 bytes.
        :return: A tuple of (shared secret, ciphertext).
        """
        if use_oaep:
            kem = RSAOaepKem(hash_alg=hash_alg, ss_len=ss_length or 32)
        else:
            kem = RSAKem(ss_length=ss_length)

        return kem.encaps(self._public_key)

    @property
    def name(self) -> str:
        """Return the name of the encapsulation key.

        :return: The name of the key.
        """
        return "rsa-kem"

    @property
    def key_size(self) -> int:
        """Return the size of the encapsulation key."""
        return self._public_key.key_size // 8

    @property
    def get_trad_name(self) -> str:
        """Return the traditional name of the encapsulation key (rsa<size>)."""
        return f"rsa{self._public_key.key_size}"

    @property
    def public_numbers(self):
        """Return the public modulus and exponent of the RSA key."""
        return self._public_key.public_numbers()

    def encode(self) -> bytes:
        """Encode the public key as RSAPublicKey bytes."""
        return self._export_public_key()


class RSADecapKey(TradKEMPrivateKey):
    """Wrapper class to support decaps method using RSA-OAEP or RSA-KEM."""

    _private_key: rsa.RSAPrivateKey

    def __init__(self, private_key: Optional[Union[rsa.RSAPrivateKey, "RSADecapKey"]] = None):
        """Initialize the decryption class with a given RSA private key.

        :param private_key: The RSA private key to use for decapsulation.
        Defaults to `None`, in which case a new key is generated.
        """
        if isinstance(private_key, RSADecapKey):
            private_key = private_key._private_key  # pylint: disable=protected-access
        self._private_key = private_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _get_header_name(self) -> bytes:
        """Return the PEM header name for the encapsulation key."""
        return b"RSA-KEM"

    @classmethod
    def from_pkcs8(cls, data: Union[bytes, rfc5958.OneAsymmetricKey]) -> "RSADecapKey":
        """Create an RSADecapKey from a PKCS8 structure, load a private key from bytes.

        Does not support encrypted private keys.

        :param data: The PKCS8 bytes, containing the private key.
        :return: The RSADecapKey instance.
        """
        if isinstance(data, rfc5958.OneAsymmetricKey):
            obj = data
        else:
            obj, rest = decoder.decode(data, asn1Spec=rfc5958.OneAsymmetricKey())
            if rest:
                raise InvalidKeyData("Invalid PKCS8 structure, got a remainder.")

        private_key = serialization.load_der_private_key(obj["privateKey"].asOctets(), password=None)

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise InvalidKeyData("Invalid RSA private key.")

        if obj["publicKey"].isValue:
            public_key = serialization.load_der_public_key(obj["publicKey"].asOctets())
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise InvalidKeyData("Invalid RSA public key.")
            if public_key != private_key.public_key():
                raise InvalidKeyData("Public key does not match the private key.")

        return cls(private_key)

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes, to put it inside a `OneAsymmetricKey` `v0` structure."""
        der_data = self._private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        obj, _ = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())
        return obj["privateKey"].asOctets()

    @classmethod
    def generate_key(cls, key_size: int = 2048) -> "RSADecapKey":
        """Generate an RSA private key.

        :param key_size: The size of the key to generate.
        :return: The generated RSA private key.
        """
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=key_size))

    @property
    def name(self) -> str:
        """Return the name of the encapsulation key."""
        return "rsa-kem"

    @property
    def key_size(self) -> int:
        """Return the size of the decapsulation key in bits."""
        return self._private_key.key_size

    def public_key(self) -> RSAEncapKey:
        """Return the public encapsulation key.

        :return: The public key.
        """
        return RSAEncapKey(self._private_key.public_key())

    def decaps(
        self, ct: bytes, use_oaep: bool = True, hash_alg: str = "sha256", ss_length: Optional[int] = None
    ) -> bytes:
        """Decapsulate a shared secret using RSA-OAEP if `use_oaep` is True, otherwise RSA-KEM.

        :param ct: The ciphertext to decrypt.
        :param use_oaep: Flag to determine whether to use RSA-OAEP. Defaults to `True`.
        :param hash_alg: Hash algorithm to use for RSA-OAEP. Defaults to "sha256".
        :param ss_length: Length of the shared secret for RSA-KEM.
        :return: The decrypted shared secret.
        """
        if use_oaep:
            kem = RSAOaepKem(hash_alg=hash_alg)
        else:
            kem = RSAKem(ss_length=ss_length)

        return kem.decaps(self._private_key, ct)

    @property
    def get_trad_name(self) -> str:
        """Return the traditional name of the encapsulation key (rsa<size>)."""
        return f"rsa{self._private_key.key_size}"

    @property
    def private_numbers(self):
        """Return the private numbers of the RSA key."""
        return self._private_key.private_numbers()

    def encode(self) -> bytes:
        """Encode the private key as PKCS8 bytes."""
        der_data = self._private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        decoded, _ = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())
        return decoded["privateKey"].asOctets()


class DHKEMPublicKey(TradKEMPublicKey):
    """Wrapper class for Diffie-Hellman Key Encapsulation Mechanism (DHKEM) public keys."""

    _use_rfc9180: bool
    _public_key: Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]

    def __eq__(self, other: object) -> bool:
        """Check if the public keys are equal."""
        if isinstance(other, ECDHPublicKey):
            return DHKEMPublicKey(other) == self

        if not isinstance(other, DHKEMPublicKey):
            return False
        return self.encode() == other.encode()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the encapsulation key."""
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return rfc9481.id_X25519
        if isinstance(self._public_key, x448.X448PublicKey):
            return rfc9481.id_X448
        return rfc6664.id_ecPublicKey

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes.

        :return: return the public key as bytes.
        """
        return self.encode()

    def _get_subject_public_key(self) -> bytes:
        """Return the subject public key."""
        data = self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        obj, _ = decoder.decode(data, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        return obj["subjectPublicKey"].asOctets()

    def __init__(
        self,
        public_key: Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey, "DHKEMPublicKey"],
        use_rfc9180: bool = True,
    ):
        """Initialize the DHKEM public key.

        :param public_key: The Diffie-Hellman (ECDH/X25519/X448) public key.
        :param use_rfc9180: Whether to use DHKEM as per RFC 9180 (True) or ECDH-KEM (False).
        """
        if isinstance(public_key, DHKEMPublicKey):
            public_key = public_key._public_key  # pylint: disable=protected-access

        self._public_key = public_key  # type: ignore
        self.use_rfc9180 = use_rfc9180  # type: ignore

    def encaps(self, private_key: Optional[Union["DHKEMPrivateKey", "ECDHPrivateKey"]]) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using DHKEM (RFC 9180) or ECDH-KEM.

        :return: A tuple of (shared secret, encapsulated public key).
        """
        private_key = DHKEMPrivateKey(private_key, self.use_rfc9180)  # type: ignore
        if self.use_rfc9180:
            kem = DHKEMRFC9180(private_key._private_key)  # pylint: disable=protected-access
        else:
            kem = ECDHKEM(private_key._private_key)  # pylint: disable=protected-access
        return kem.encaps(self._public_key)

    @property
    def name(self) -> str:
        """Return the name of the encapsulation key."""
        return "dhkem-" if self.use_rfc9180 else "ecdh-kem-" + self.get_trad_name

    @property
    def key_size(self) -> int:
        """Return the size of the encapsulation key."""
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return 32
        if isinstance(self._public_key, x448.X448PublicKey):
            return 56

        # Plus one for the prefix that the key is a point on the curve,
        # which is negative or positive.
        # Currently only uncompressed point is supported.
        return self._public_key.curve.key_size // 8 + 1

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.key_size

    @property
    def get_trad_name(self) -> str:
        """Return the traditional name of the encapsulation key (curve-name)."""
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return "ecdh-" + self._public_key.curve.name
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return "x25519"
        if isinstance(self._public_key, x448.X448PublicKey):
            return "x448"
        raise ValueError("Unsupported public key type.")

    @property
    def curve_name(self) -> str:
        """Return the name of the curve.

        return: The name of the curve or x25519/x448.
        """
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return "x25519"
        if isinstance(self._public_key, x448.X448PublicKey):
            return "x448"

        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.curve.name

        raise ValueError(f"Unsupported public key type, got: {self._public_key.__class__.__name__}.")

    @property
    def public_numbers(self):
        """Return the public numbers of the key (curve-dependent)."""
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.public_numbers()
        raise ValueError("Public numbers are not available for this key type.")

    def public_bytes(
        self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        """Return the public key as bytes."""
        return self._public_key.public_bytes(encoding, format)

    def encode(self) -> bytes:
        """Encode the public key as bytes."""
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return self._public_key.public_bytes_raw()

    @classmethod
    def _ec_key_from_der(cls, data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePublicKey:
        """Reconstruct an EllipticCurvePublicKey from DER data.

        :param data: The DER encoded public key.
        :param curve: The elliptic curve.
        :return: The reconstructed public key.
        """
        return ec.EllipticCurvePublicKey.from_encoded_point(curve=curve, data=data)

    @classmethod
    def from_public_bytes(cls, name: str, data: bytes) -> "DHKEMPublicKey":
        """Load the public key from raw bytes.

        :param name: The name of the key. (e.g. "ecdh-secp256r1", "x25519", "x448")
        :param data: The raw bytes of the public key.
        :return: The DHKEMPublicKey instance.
        """
        if name not in ["x25519", "x448"]:
            curve = name.replace("ecdh-", "", 1)
            curve_inst = get_curve_instance(curve)
            trad_key = cls._ec_key_from_der(data, curve_inst)
        elif name == "x25519":
            trad_key = x25519.X25519PublicKey.from_public_bytes(data)
        elif name == "x448":
            trad_key = x448.X448PublicKey.from_public_bytes(data)
        else:
            raise ValueError(f"Unsupported key type: {name}. Expected one of 'x25519', 'x448' or 'ecdh-*'.")

        return cls(trad_key)


class DHKEMPrivateKey(TradKEMPrivateKey):
    """Wrapper class for Diffie-Hellman Key Encapsulation Mechanism (DHKEM) private keys."""

    _private_key: Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]

    def __init__(
        self,
        private_key: Union["DHKEMPrivateKey", ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey],
        use_rfc9180: bool = True,
    ):
        """Initialize the DHKEM private key.

        :param private_key: The private key.
        :param use_rfc9180: Whether to use DHKEM (RFC 9180) or ECDH-KEM.
        """
        if isinstance(private_key, DHKEMPrivateKey):
            private_key = private_key._private_key

        self._private_key = private_key
        self.use_rfc9180 = use_rfc9180

    @classmethod
    def generate_key(cls, curve: str = "secp256r1", use_rfc9180: bool = True) -> "DHKEMPrivateKey":
        """Generate a new DHKEM private key.

        :param curve: The elliptic curve or key type to generate.
        :param use_rfc9180: Whether to use DHKEM (RFC 9180) or ECDH-KEM.
        :return: A new DHKEMPrivateKey instance.
        :raises ValueError: If the curve is not supported.
        """
        if curve.lower() == "x25519":
            return cls(x25519.X25519PrivateKey.generate(), use_rfc9180)
        if curve.lower() == "x448":
            return cls(x448.X448PrivateKey.generate(), use_rfc9180)
        curve_obj = get_curve_instance(curve)
        return cls(ec.generate_private_key(curve_obj), use_rfc9180)

    @property
    def name(self) -> str:
        """Return the name of the decapsulation key."""
        return "dhkem-rfc9180" if self.use_rfc9180 else "ecdh-kem"

    @property
    def key_size(self) -> int:
        """Return the size of the decapsulation key."""
        return self.public_key().key_size

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.public_key().ct_length

    @property
    def get_trad_name(self) -> str:
        """Return the traditional name of the decapsulation key (curve-name)."""
        return self.public_key().get_trad_name

    @property
    def private_numbers(self):
        """Return the private numbers of the key (curve-dependent)."""
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            return self._private_key.private_numbers()
        raise ValueError("Private numbers are not available for this key type.")

    def public_key(self) -> DHKEMPublicKey:
        """Return the corresponding public key.

        :return: The public key.
        """
        return DHKEMPublicKey(self._private_key.public_key(), use_rfc9180=self.use_rfc9180)

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret using DHKEM (RFC 9180) or ECDH-KEM.

        :param ct: The encapsulated public key bytes.
        :return: The shared secret.
        """
        kem = (
            DHKEMRFC9180(private_key=self._private_key)
            if self.use_rfc9180
            else (ECDHKEM(private_key=self._private_key))
        )
        return kem.decaps(ct)

    def encode(self) -> bytes:
        """Encode the private key as bytes."""
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            private_numbers = self._private_key.private_numbers()
            return private_numbers.private_value.to_bytes(self._private_key.key_size, byteorder="big")
        return self._private_key.private_bytes_raw()

    @staticmethod
    def _ec_key_from_der(der_data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
        """Reconstruct an EllipticCurvePrivateKey from DER data.

        :param der_data: The DER encoded private key.
        :param curve: The elliptic curve.
        :return: The reconstructed private key.
        """
        private_value = int.from_bytes(der_data, byteorder="big")
        return ec.derive_private_key(private_value, curve)

    @classmethod
    def from_private_bytes(cls, name: str, data: bytes, curve: Optional[str] = None) -> "DHKEMPrivateKey":
        """Load the private key from raw bytes.

        :param name: The name of the key. (e.g. "ecdh-secp256r1", "x25519", "x448")
        :param data: The raw bytes of the private key.
        :param curve: The curve name for ECDH keys.
        :return: The DHKEMPrivateKey instance.
        """
        if name not in ["x25519", "x448"] and curve is None:
            curve = name.replace("ecdh-", "", 1)

        if name == "x25519":
            trad_key = x25519.X25519PrivateKey.from_private_bytes(data)
        elif name == "x448":
            trad_key = x448.X448PrivateKey.from_private_bytes(data)
        else:
            if curve is None:
                raise ValueError("Curve name must be provided for ECDH keys.")
            curve_inst = get_curve_instance(curve)
            trad_key = cls._ec_key_from_der(data, curve_inst)

        return cls(trad_key)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """Return the private key as bytes."""
        return self._private_key.private_bytes(encoding, format, encryption_algorithm)

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes (raw bytes)."""
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            return self._private_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
        return self._private_key.private_bytes_raw()

    @property
    def curve_name(self) -> str:
        """Return the name of the curve.

        return: The name of the curve or x25519/x448.
        """
        return self.public_key().curve_name
