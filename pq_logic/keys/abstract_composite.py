# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Define the abstract classes for composite keys."""

import base64
import textwrap
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules.rfc5958 import OneAsymmetricKey

from pq_logic.hybrid_structures import (
    CompositeSignaturePrivateKeyAsn1,
    CompositeSignaturePublicKeyAsn1,
    CompositeSignatureValue,
)
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQPrivateKey, PQPublicKey
from pq_logic.keys.serialize_utils import prepare_enc_key_pem
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.stat_utils import get_ct_length_for_trad_key, get_trad_key_length
from resources.oid_mapping import hash_name_to_instance

# Define the traditional public key types,
# for correct type hinting in the CompositePublicKey class.
TradPubKeySig = Union[
    EllipticCurvePublicKey,
    RSAPublicKey,
    Ed25519PublicKey,
    Ed448PublicKey,
]
# Define the traditional private key types,
# for correct type hinting in the CompositePrivateKey class.
TradPrivKeySig = Union[
    EllipticCurvePrivateKey,
    RSAPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
]

###########################
# Composite Abstract Class
###########################


class AbstractCompositePublicKey(ABC):
    """Abstract class for Composite public keys."""

    pq_key: PQPublicKey
    trad_key: TradPubKeySig

    def __init__(self, pq_key: PQPublicKey, trad_key: TradPubKeySig):
        """Initialize the CompositePublicKey.

        :param pq_key: The post-quantum public key object.
        :param trad_key: The traditional public key object.
        """
        self.pq_key = pq_key
        self.trad_key = trad_key

    @abstractmethod
    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""
        pass

    def _encode_pub_key(self) -> bytes:
        """Encode a traditional public key.

        :return: The encoded public key as bytes.
        """
        trad_key = self.trad_key

        if isinstance(trad_key, ed25519.Ed25519PublicKey) or isinstance(trad_key, ed448.Ed448PublicKey):
            public_key_bytes = trad_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

        elif isinstance(trad_key, x25519.X25519PublicKey) or isinstance(trad_key, x448.X448PublicKey):
            public_key_bytes = trad_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        elif isinstance(trad_key, ec.EllipticCurvePublicKey):
            public_key_bytes = trad_key.public_bytes(
                encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
            )
        elif isinstance(trad_key, rsa.RSAPublicKey):
            public_key_bytes = trad_key.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
            )
        else:
            raise NotImplementedError(f"Unsupported traditional public key type.: {type(trad_key).__name__}")

        return public_key_bytes

    def _prepare_pub_keys(self) -> CompositeSignaturePublicKeyAsn1:
        """Prepare the public keys for the `CompositeSignaturePublicKeyAsn1` structure.

        :return: The `CompositeSignaturePublicKeyAsn1` structure.
        """
        data = CompositeSignaturePublicKeyAsn1()
        data.append(univ.BitString.fromOctetString(self.pq_key.public_bytes_raw()))
        data.append(univ.BitString.fromOctetString(self._encode_pub_key()))
        return data

    def _prepare_old_spki(self) -> univ.SequenceOf:
        """Prepare the old SPKI structure with 2 SPKI structures.

        :return: The SequenceOf with 2 SPKI structures.
        """
        data = univ.SequenceOf()
        der_data = self.trad_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spki_trad, _ = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())

        der_data = self.pq_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spki_pq, _ = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())

        data.append(spki_pq)
        data.append(spki_trad)

        return data

    def _self_to_raw_der(self) -> bytes:
        """Convert the public key to a raw DER-encoded structure."""
        return encoder.encode(self._prepare_pub_keys())

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
            data = self._self_to_raw_der()
        else:
            data = encoder.encode(self._prepare_old_spki())

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(data)
        return spki

    def public_bytes(
        self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> Union[bytes, str]:
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
            raise NotImplementedError("Raw encoding with Raw format is not supported.")

        if encoding == Encoding.DER:
            if format == PublicFormat.SubjectPublicKeyInfo:
                return encoder.encode(self.to_spki())
            if format == PublicFormat.Raw:
                return self._self_to_raw_der()
            raise ValueError(f"Unsupported format for DER encoding: {format}")

        if encoding == Encoding.PEM:
            if format == PublicFormat.SubjectPublicKeyInfo:
                data = encoder.encode(self.to_spki())
            elif format == PublicFormat.Raw:
                data = self._self_to_raw_der()
            else:
                raise ValueError(f"Unsupported format for PEM encoding: {format}")

            b64_encoded = base64.b64encode(data).decode("utf-8")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem = "-----BEGIN PUBLIC KEY-----\n" + b64_encoded + "\n-----END PUBLIC KEY-----\n"
            return pem

        raise ValueError(f"Unsupported encoding: {encoding}")


class AbstractCompositePrivateKey(ABC):
    """Abstract class for Composite private keys."""

    pq_key: PQPrivateKey
    trad_key: TradPrivKeySig

    def __init__(self, pq_key: PQPrivateKey, trad_key: TradPrivKeySig):
        """Initialize the CompositePrivateKey.

        :param pq_key: The post-quantum private key object.
        :param trad_key: The traditional private key object.
        """
        self.pq_key = pq_key
        self.trad_key = trad_key

    @abstractmethod
    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""
        pass

    @staticmethod
    @abstractmethod
    def generate(pq_name: Optional[str] = None, trad_param: Optional[Union[int, str]] = None):
        """Generate a new CompositePrivateKey."""
        pass

    @abstractmethod
    def public_key(self) -> AbstractCompositePublicKey:
        """Return the corresponding public key class."""
        pass

    def _get_key_name(self) -> bytes:
        """Get the key name for the composite key, to set as the PEM header."""
        return b"ABSTRACT-COMPOSITE-KEY"

    def _to_der(self):
        """Convert the private key to a CompositeSignaturePrivateKeyAsn1 structure.

        :return: The DER-encoded CompositeSignaturePrivateKeyAsn1 structure.
        """
        data = CompositeSignaturePrivateKeyAsn1()

        pq_bytes = self.pq_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())
        trad_bytes = self.trad_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())

        obj, _ = decoder.decode(pq_bytes, asn1Spec=OneAsymmetricKey())
        obj2, _ = decoder.decode(trad_bytes, asn1Spec=OneAsymmetricKey())
        data.append(obj)
        data.append(obj2)

        return encoder.encode(data)

    def _to_one_asym_key(self) -> bytes:
        """Convert the private key to a OneAsymmetricKey structure.

        :return: The DER-encoded OneAsymmetricKey structure.
        """
        data = OneAsymmetricKey()
        data["version"] = 0
        data["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        data["privateKey"] = univ.OctetString(self._to_der())
        return encoder.encode(data)

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
            pem = (
                "-----BEGIN COMPOSITE SIG PRIVATE KEY-----\n"
                + b64_encoded
                + "\n-----END COMPOSITE SIG PRIVATE KEY-----\n"
            )
            return pem.encode("utf-8")

        raise NotImplementedError(f"The encoding is not supported. Encoding: {encoding} .Format: {format}.")


######################
# Composite KEM
#####################


class AbstractCompositeKEMPublicKey(AbstractCompositePublicKey, ABC):
    """Abstract class for Composite KEM public keys."""

    pq_key: PQKEMPublicKey

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
            data = self._self_to_raw_der()
        else:
            data = encoder.encode(self._prepare_old_spki())

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(data)
        return spki

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return self.pq_key.ct_length + get_ct_length_for_trad_key(self.trad_key)

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return self.pq_key.key_size + get_trad_key_length(self.trad_key)


class AbstractCompositeKEMPrivateKey(AbstractCompositePrivateKey, ABC):
    """Abstract class for Composite KEM private keys."""

    pq_key: PQKEMPrivateKey

    def _get_key_name(self) -> bytes:
        """Get the key name for the composite key, to set as the PEM header."""
        return b"ABSTRACT COMPOSITE KEM KEY"

    @abstractmethod
    def public_key(self) -> AbstractCompositeKEMPublicKey:
        """Return the corresponding public key class."""
        pass

    @abstractmethod
    def encaps(self, public_key: AbstractCompositeKEMPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret.

        :param public_key: The recipient's public key.
        :return: The encapsulated shared secret and the ciphertext.
        """
        pass

    @abstractmethod
    def decaps(self, ct_vals: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct_vals: THe ciphertext values as DER-encoded bytes.
        :return: The shared secret.
        """
        pass

    @abstractmethod
    def kem_combiner(self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine the shared secrets and ciphertexts to a shared secret."""
        pass

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return self.pq_key.key_size + get_trad_key_length(self.trad_key)

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return self.public_key().ct_length


######################
# Composite Sig
#####################


class AbstractCompositeSigPublicKey(AbstractCompositePublicKey, ABC):
    """Abstract class for Composite Signature public keys."""

    pq_key: MLDSAPublicKey
    trad_key: TradPubKeySig

    def __eq__(self, other):
        """Check if two CompositeSigPublicKeys are equal."""
        if not isinstance(other, AbstractCompositeSigPublicKey):
            return False

        return self.pq_key == other.pq_key and self.trad_key == other.trad_key

    @abstractmethod
    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""
        pass

    @abstractmethod
    def _get_hash_name(
        self, domain_oid: Optional[univ.ObjectIdentifier] = None, use_pss: bool = False, pre_hash: bool = False
    ) -> str:
        """Get the hash name for the given composite key combination."""
        pass

    def _verify_trad(
        self,
        data: bytes,
        signature: bytes,
        use_pss: bool = False,
    ) -> None:
        """Verify a traditional signature using the corresponding public key.

        :param data: The data that was signed.
        :param signature: The traditional signature to be verified.
        :param oid: The Object Identifier associated with the signature scheme.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :raises ValueError: If the key type is unsupported.
        :raises InvalidSignature: If the signature verification fails.
        """
        if isinstance(self.trad_key, rsa.RSAPublicKey):
            key_size_to_lg = {2048: "sha256", 3072: "sha256", 4096: "sha384"}
            hash_alg = key_size_to_lg.get(
                self.trad_key.key_size, "sha256" if self.trad_key.key_size < 3072 else "sha384"
            )

            hash_instance = hash_name_to_instance(hash_alg)

            rsa_padding = (
                padding.PSS(mgf=padding.MGF1(hash_instance), salt_length=hash_instance.digest_size)
                if use_pss
                else padding.PKCS1v15()
            )

            self.trad_key.verify(
                signature=signature,
                data=data,
                padding=rsa_padding,
                algorithm=hash_instance,
            )
        elif isinstance(self.trad_key, (ed448.Ed448PublicKey, ed25519.Ed25519PublicKey)):
            self.trad_key.verify(signature=signature, data=data)
        elif isinstance(self.trad_key, ec.EllipticCurvePublicKey):
            hash_alg = {
                "secp256r1": "sha256",
                "secp384r1": "sha384",
                "brainpoolP256r1": "sha256",
                "brainpoolP384r1": "sha384",
            }[self.trad_key.curve.name]

            hash_instance = hash_name_to_instance(hash_alg)
            self.trad_key.verify(signature=signature, data=data, signature_algorithm=ec.ECDSA(hash_instance))
        else:
            raise ValueError("Unsupported traditional public key type.")

    @abstractmethod
    def verify(self, data, signature, hash_alg: Optional[str] = None):
        """Verify a signature."""
        pass

    @abstractmethod
    def from_spki(self, spki: rfc5280.SubjectPublicKeyInfo):
        """
        Load a CompositePublicKey from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: CompositePublicKey instance.
        """
        pass


class AbstractCompositeSigPrivateKey(AbstractCompositePrivateKey, ABC):
    """Abstract class for Composite Signature private keys."""

    pq_key: MLDSAPrivateKey
    trad_key: TradPrivKeySig

    def _get_key_name(self) -> bytes:
        """Get the key name for the composite key, to set as the PEM header."""
        return b"ABSTRACT COMPOSITE SIG KEY"

    @staticmethod
    def prepare_composite_sig(pq_sig: bytes, trad_sig: bytes) -> bytes:
        """Prepare the composite signature.

        :param pq_sig: The post-quantum signature.
        :param trad_sig: The traditional signature.
        """
        vals = CompositeSignatureValue()
        vals.append(univ.BitString.fromOctetString(pq_sig))
        vals.append(univ.BitString.fromOctetString(trad_sig))
        return encoder.encode(vals)

    @abstractmethod
    def get_oid(self, used_padding: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""
        pass

    @abstractmethod
    def _get_hash_name(
        self, domain_oid: Optional[univ.ObjectIdentifier] = None, use_padding: bool = False, pre_hash: bool = False
    ) -> str:
        """Get the hash name for the given composite key combination."""
        pass

    @staticmethod
    def validate(pq_name: str, trad_param: Union[str, int]):
        """Validate the algorithm parameters."""
        raise NotImplementedError()

    def _sign_trad(self, data: bytes, use_pss: bool = False) -> bytes:
        """Generate a signature using the traditional private key.

        :param data: The data to be signed.
        :param oid: The Object Identifier representing the signature scheme.
        :param use_pss: Indicates whether RSA-PSS padding should be used.
        :return: The signature as bytes.
        :raises ValueError: If the key type is unsupported.
        """
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            size = self.trad_key.key_size
            if size >= 4096:
                hash_alg = "sha384"
            else:
                hash_alg = "sha256"

            hash_instance = hash_name_to_instance(hash_alg)

            if use_pss:
                rsa_padding = padding.PSS(mgf=padding.MGF1(hash_instance), salt_length=hash_instance.digest_size)
            else:
                rsa_padding = padding.PKCS1v15()
            return self.trad_key.sign(data=data, padding=rsa_padding, algorithm=hash_instance)
        elif isinstance(self.trad_key, (ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey)):
            return self.trad_key.sign(data)
        elif isinstance(self.trad_key, ec.EllipticCurvePrivateKey):
            hash_alg = {
                "secp256r1": "sha256",
                "secp384r1": "sha384",
                "brainpoolP256r1": "sha256",
                "brainpoolP384r1": "sha384",
            }[self.trad_key.curve.name]
            hash_instance = hash_name_to_instance(hash_alg)

            return self.trad_key.sign(data=data, signature_algorithm=ec.ECDSA(hash_instance))
        else:
            raise ValueError(
                f"CompositeSigPrivateKey: Unsupported traditional private key type.: {type(self.trad_key).__name__}"
            )

    @abstractmethod
    def sign(self, data: bytes, hash_alg: Optional[str] = None) -> bytes:
        """Sign data with a composite signature key."""
        pass

    @abstractmethod
    def public_key(self) -> AbstractCompositeSigPublicKey:
        """Return the corresponding public key class."""
        pass
