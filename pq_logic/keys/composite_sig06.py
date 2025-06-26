# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite Signature Implementation for Draft v04.

available at: https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-04.html
"""

import os
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from pq_logic.keys.abstract_wrapper_keys import (
    AbstractCompositePrivateKey,
    AbstractCompositePublicKey,
    HybridSigPrivateKey,
    HybridSigPublicKey,
)
from pq_logic.keys.serialize_utils import prepare_rsa_private_key
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.tmp_oids import (
    COMPOSITE_SIG06_INNER_HASH_OID_2_NAME,
    COMPOSITE_SIG06_NAME_TO_OID,
    COMPOSITE_SIG06_PREHASH_OID_2_HASH,
)
from resources.exceptions import InvalidKeyCombination
from resources.oid_mapping import hash_name_to_instance
from resources.typingutils import ECVerifyKey

_PREFIX = b"CompositeAlgorithmSignatures2025"


def _compute_hash(alg_name: str, data: bytes) -> bytes:
    """Return the digest for *data* using *alg_name*."""
    digest = hashes.Hash(hash_name_to_instance(alg_name))
    digest.update(data)
    return digest.finalize()


def _compute_prehash(oid: univ.ObjectIdentifier, data: bytes) -> bytes:
    """Compute the pre-hash of the data."""
    hash_alg = COMPOSITE_SIG06_PREHASH_OID_2_HASH[oid]
    return _compute_hash(alg_name=hash_alg, data=data)


class CompositeSig06PublicKey(AbstractCompositePublicKey, HybridSigPublicKey):
    """Composite Signature Implementation for Draft v06.

    https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-06.html
    """

    _pq_key: MLDSAPublicKey
    _trad_key: Union[
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
    ]
    _name = "composite-sig-06"

    def __init__(
        self,
        pq_key: MLDSAPublicKey,
        trad_key: Union[
            rsa.RSAPublicKey,
            ECVerifyKey,
        ],
    ) -> None:
        """Initialize the CompositeSig04PublicKey.

        :param pq_key: The ML-DSA public key.
        :param trad_key: The traditional public key.
        """
        super().__init__(pq_key, trad_key)
        self._pq_key = pq_key
        self._trad_key = trad_key

    def _export_public_key(self) -> bytes:
        _pq_export = self.pq_key.public_bytes_raw()
        return _pq_export + self.encode_trad_part()

    def public_bytes_raw(self) -> bytes:
        """Export the raw public key, starting with the length of the PQ key."""
        # Export the raw key.
        return self._export_public_key()

    @property
    def name(self) -> str:
        """Return the name of the composite signature."""
        return f"{self._name}-{self.pq_key.name}-{self._get_trad_key_name()}"

    def _get_name(self, use_pss: bool = False) -> str:
        """Retrieve the composite signature name."""
        trad_name = self._get_trad_key_name(use_pss=use_pss)
        return f"{self._name}-{self.pq_key.name}-{trad_name}"

    def get_oid(self, use_pss: bool = True) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        # Defaults to use PSS padding because ML-DSA-87 only supports the PSS padding.
        _name = self._get_name(use_pss=use_pss)
        if COMPOSITE_SIG06_NAME_TO_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite signature v6 combination: {_name}")
        return COMPOSITE_SIG06_NAME_TO_OID[_name]

    @property
    def pq_key(self) -> MLDSAPublicKey:
        """Return the PQ key."""
        return self._pq_key

    @property
    def trad_key(
        self,
    ) -> Union[
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
    ]:
        """Return the traditional key."""
        return self._trad_key

    def _prepare_input(self, data: bytes, ctx: bytes, use_pss: bool, rand: bytes) -> bytes:
        """Prepare the input for the composite signature.

        :param data: The data to be signed.
        :param ctx: The context for the signature.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :param rand: The random value to distinguish signatures, must be 32 bytes.
        :return: The prepared input.
        """
        if len(ctx) > 255:
            raise InvalidSignature("Context length exceeds 255 bytes")

        if len(rand) != 32:
            raise InvalidSignature("Random value must be 32 bytes long")

        domain_oid = self.get_oid(use_pss=use_pss)
        length_bytes = len(ctx).to_bytes(1, "little", signed=False)
        hashed_data = _compute_prehash(domain_oid, data=data)
        # Construct M' with pre-hashing
        # M':=  Prefix || Domain || len(ctx) || ctx || r
        # || PH( M )
        m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + rand
        m_prime += hashed_data
        return m_prime

    def _get_rsa_inner_hash(self, use_pss: bool) -> hashes.HashAlgorithm:
        """Get the inner hash algorithm for RSA signatures."""
        oid = self.get_oid(use_pss=use_pss)
        if oid not in COMPOSITE_SIG06_INNER_HASH_OID_2_NAME:
            raise InvalidKeyCombination(f"Unsupported OID for composite signature: {oid}")
        hash_alg_name = COMPOSITE_SIG06_INNER_HASH_OID_2_NAME[oid]
        if hash_alg_name is None:
            raise InvalidKeyCombination("No inner hash algorithm defined for this OID.")
        return hash_name_to_instance(hash_alg_name)

    def _verify_trad(self, data: bytes, signature: bytes, use_pss: bool = False) -> None:
        """Verify the traditional signature."""
        oid = self.get_oid(use_pss=use_pss)
        hash_alg = COMPOSITE_SIG06_INNER_HASH_OID_2_NAME[oid]
        if hash_alg is not None:
            hash_alg = hash_name_to_instance(hash_alg)

        if isinstance(self._trad_key, rsa.RSAPublicKey):
            if use_pss:
                padding_scheme = padding.PSS(
                    mgf=padding.MGF1(algorithm=hash_alg), salt_length=padding.PSS.DIGEST_LENGTH
                )
                self._trad_key.verify(
                    signature=signature,
                    data=data,
                    padding=padding_scheme,
                    algorithm=hash_alg,
                )
            else:
                self._trad_key.verify(
                    signature=signature,
                    data=data,
                    padding=padding.PKCS1v15(),
                    algorithm=hash_alg,
                )
        elif isinstance(self._trad_key, ec.EllipticCurvePublicKey):
            self._trad_key.verify(signature, data, ec.ECDSA(hash_alg))
        elif isinstance(self._trad_key, ed25519.Ed25519PublicKey):
            self._trad_key.verify(signature, data)
        elif isinstance(self._trad_key, ed448.Ed448PublicKey):
            self._trad_key.verify(signature, data)
        else:
            raise InvalidKeyCombination(
                f"Unsupported traditional key type for verification.Got: {type(self._trad_key)}"
            )

    def verify(
        self,
        data: bytes,
        signature: bytes,
        ctx: bytes = b"",
        use_pss: bool = False,
    ) -> None:
        """Verify the composite signature."""
        # Starts with the ML-DSA signature, followed by the traditional signature.
        rand = signature[:32]
        mldsa_sig = signature[32 : 32 + self.pq_key.sig_size]
        trad_sig = signature[32 + self.pq_key.sig_size :]
        domain_oid = self.get_oid(use_pss=use_pss)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, rand=rand)
        self.pq_key.verify(data=m_prime, signature=mldsa_sig, ctx=encoder.encode(domain_oid))
        self._verify_trad(data=m_prime, signature=trad_sig, use_pss=use_pss)

    @property
    def key_size(self) -> int:
        """Return the total size of the public key."""
        return len(self.public_bytes_raw())

    def to_spki(
        self,
        use_pss: bool = False,
    ) -> rfc5280.SubjectPublicKeyInfo:
        """Export the public key as SubjectPublicKeyInfo."""
        alg_id = rfc5280.SubjectPublicKeyInfo()
        alg_id["algorithm"]["algorithm"] = self.get_oid(use_pss=use_pss)
        alg_id["subjectPublicKey"] = univ.BitString.fromOctetString(self.public_bytes_raw())
        return alg_id


class CompositeSig06PrivateKey(AbstractCompositePrivateKey, HybridSigPrivateKey):
    """Composite Signature Implementation for Draft v04.

    https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-04.html
    """

    _pq_key: MLDSAPrivateKey
    _trad_key: Union[
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
    ]
    _name = "composite-sig-06"

    def _export_trad_key(self) -> bytes:
        """Export the traditional private key."""
        if isinstance(self._trad_key, rsa.RSAPrivateKey):
            return prepare_rsa_private_key(self._trad_key)
        if isinstance(self._trad_key, ec.EllipticCurvePrivateKey):
            return self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        return self._trad_key.private_bytes_raw()

    def public_key(self) -> CompositeSig06PublicKey:
        """Generate the public key corresponding to this composite private key."""
        return CompositeSig06PublicKey(self._pq_key.public_key(), self._trad_key.public_key())

    def _get_trad_key_name(self) -> str:
        """Retrieve the traditional key name."""
        if isinstance(self._trad_key, rsa.RSAPrivateKey):
            key_size = self._get_rsa_size(self._trad_key.key_size)
            return f"rsa{key_size}"
        if isinstance(self._trad_key, ec.EllipticCurvePrivateKey):
            return f"ecdsa-{self._trad_key.curve.name}"
        if isinstance(self._trad_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        raise InvalidKeyCombination(f"Unsupported traditional key type: {type(self._trad_key)}")

    def _get_name(self, use_pss: bool = False) -> str:
        """Retrieve the composite signature name."""
        trad_name = self._get_trad_key_name()
        if isinstance(self._trad_key, rsa.RSAPrivateKey) and use_pss:
            trad_name += "-pss"
        return f"{self._name}-{self.pq_key.name}-{trad_name}"

    @property
    def name(self) -> str:
        """Return the name of the composite signature."""
        return f"{self._name}-{self.pq_key.name}-{self._get_trad_key_name()}"

    def get_oid(self, use_pss: bool = True) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        _name = self._get_name(use_pss=use_pss)
        if COMPOSITE_SIG06_NAME_TO_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite signature combination: {_name}")
        return COMPOSITE_SIG06_NAME_TO_OID[_name]

    def _prepare_input(self, data: bytes, ctx: bytes, use_pss: bool, rand: bytes) -> bytes:
        """Prepare the input for the composite signature.

        :param data: The data to be signed.
        :param ctx: The context for the signature.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :param rand: Optional random value to distinguish signatures. Defaults to a random 32-byte.
        :return: The prepared input.
        """
        if len(ctx) > 255:
            raise InvalidSignature("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss)
        length_bytes = len(ctx).to_bytes(1, "little", signed=False)
        # M' :=  Prefix || Domain || len(ctx) || ctx || r
        # || PH( M )
        m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + rand
        m_prime += _compute_prehash(oid=domain_oid, data=data)
        return m_prime

    @staticmethod
    def _prepare_composite_sig04(pq_sig: bytes, trad_sig: bytes) -> bytes:
        """Prepare the composite signature for draft v04."""
        return pq_sig + trad_sig

    def _sign_trad(self, data: bytes, use_pss: bool = False) -> bytes:
        """Sign the traditional part of the composite signature.

        :param data: The data to sign.
        :param use_pss: Whether to use PSS padding for RSA signatures.
        :return: The traditional signature.
        """
        oid = self.get_oid(use_pss=use_pss)
        hash_alg = COMPOSITE_SIG06_INNER_HASH_OID_2_NAME[oid]
        if hash_alg is not None:
            hash_alg = hash_name_to_instance(hash_alg)

        if isinstance(self._trad_key, rsa.RSAPrivateKey):
            if use_pss:
                return self._trad_key.sign(
                    data=data,
                    padding=padding.PSS(
                        mgf=padding.MGF1(algorithm=hash_alg),
                        salt_length=padding.PSS.DIGEST_LENGTH,
                    ),
                    algorithm=hash_alg,
                )
            return self._trad_key.sign(
                data=data,
                padding=padding.PKCS1v15(),
                algorithm=hash_alg,
            )
        if isinstance(self._trad_key, ec.EllipticCurvePrivateKey):
            return self._trad_key.sign(data, ec.ECDSA(hash_alg))
        if isinstance(self._trad_key, ed25519.Ed25519PrivateKey):
            return self._trad_key.sign(data)
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return self._trad_key.sign(data)
        raise InvalidKeyCombination(f"Unsupported traditional key type for signing.Got: {type(self._trad_key)}")

    def sign(self, data: bytes, ctx: bytes = b"", use_pss: bool = False, rand: Optional[bytes] = None) -> bytes:
        """Sign data with optional pre-hashing and context.

        :param data: The data to sign.
        :param ctx: The context for the signature, must not exceed 255 bytes.
        :param use_pss: Whether to use padding.
        :param rand: Optional random value to distinguish signatures. Defaults to a random 32-byte value.
        :return: The encoded signature.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss)
        rand = rand or os.urandom(32)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, rand=rand)
        mldsa_sig = self._pq_key.sign(data=m_prime, ctx=encoder.encode(domain_oid))
        trad_sig = self._sign_trad(data=m_prime, use_pss=use_pss)
        return rand + mldsa_sig + trad_sig

    @property
    def key_size(self) -> int:
        """Return the total size of the private key."""
        return len(self._export_private_key())

    @property
    def pq_key(self) -> MLDSAPrivateKey:
        """Return the PQ key."""
        return self._pq_key

    @property
    def trad_key(
        self,
    ) -> Union[
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
    ]:
        """Return the traditional key."""
        return self._trad_key
