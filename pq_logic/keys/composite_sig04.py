# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite Signature Implementation for Draft v04.

available at: https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-04.html
"""

from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ

from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey, _compute_hash
from pq_logic.keys.serialize_utils import prepare_rsa_private_key
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.tmp_oids import COMP_SIG04_PREHASH_OID_2_HASH, COMPOSITE_SIG04_NAME_2_OID
from resources.exceptions import InvalidKeyCombination
from resources.oid_mapping import sha_alg_name_to_oid
from resources.typingutils import ECVerifyKey

_PREFIX = b"CompositeAlgorithmSignatures2025"


class CompositeSig04PublicKey(CompositeSig03PublicKey):
    """Composite Signature Implementation for Draft v04.

    https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-04.html
    """

    _pq_key: MLDSAPublicKey
    _trad_key: Union[
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
    ]
    _name = "composite-sig-04"

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
        _length = len(_pq_export).to_bytes(4, byteorder="little", signed=False)
        return _length + _pq_export + self.encode_trad_part()

    @property
    def name(self) -> str:
        """Return the name of the composite signature."""
        return f"{self._name}-{self.pq_key.name}-{self._get_trad_key_name()}"

    def _get_name(self, use_pss: bool = False, pre_hash: bool = False) -> str:
        """Retrieve the composite signature name."""
        to_add = "" if not pre_hash else "hash-"
        trad_name = self._get_trad_key_name(use_pss=use_pss)
        return f"{self._name}-{to_add}{self.pq_key.name}-{trad_name}"

    def get_oid(self, use_pss: bool = True, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        # Defaults to use PSS padding because ML-DSA-87 only supports the PSS padding.
        _name = self._get_name(use_pss=use_pss, pre_hash=pre_hash)

        if COMPOSITE_SIG04_NAME_2_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite signature v4 combination: {_name}")
        return COMPOSITE_SIG04_NAME_2_OID[_name]

    @property
    def pq_key(self) -> MLDSAPublicKey:
        """Return teh PQ key."""
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

    def _prepare_input(self, data: bytes, ctx: bytes, use_pss: bool, pre_hash: bool) -> bytes:
        """Prepare the input for the composite signature.

        :param data: The data to be signed.
        :param ctx: The context for the signature.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :param pre_hash: Indicates whether the data was pre-hashed before signing.
        :return: The prepared input.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        length_bytes = len(ctx).to_bytes(1, "little", signed=False)

        if pre_hash:
            hash_alg = COMP_SIG04_PREHASH_OID_2_HASH.get(domain_oid, "sha512")
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = _compute_hash(alg_name=hash_alg, data=data)
            # Construct M' with pre-hashing
            # Compute M' = Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)
            m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Prefix || Domain || len(ctx) || ctx || M
            m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + data
        return m_prime

    def verify(
        self,
        data: bytes,
        signature: bytes,
        ctx: bytes = b"",
        use_pss: bool = False,
        pre_hash: bool = False,
    ) -> None:
        """Verify the composite signature."""
        # currently unsure what the length is for
        # inside the pqc-certificates, the length is 2495
        # for HashMLDSA44-ECDSA-P256-SHA256-2.16.840.1.114027.80.8.1.83_ta.der
        _length = int.from_bytes(signature[:4], "little")
        signature = signature[4:]
        mldsa_sig = signature[: self._pq_key.sig_size]
        if self._pq_key.sig_size != len(mldsa_sig):
            raise InvalidSignature(
                f"The composite signature was invalid. Due to the {self.pq_key.name} sig size"
                f"Expected: {self.pq_key.sig_size}. Got: {len(mldsa_sig)}"
            )

        trad_sig = signature[self.pq_key.sig_size :]
        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, pre_hash=pre_hash)
        self._verify_trad(data=m_prime, signature=trad_sig, use_pss=use_pss)
        self.pq_key.verify(data=m_prime, signature=mldsa_sig, ctx=encoder.encode(domain_oid))


class CompositeSig04PrivateKey(CompositeSig03PrivateKey):
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
    _name = "composite-sig-04"

    def _export_trad_key(self) -> bytes:
        """Export the traditional private key."""
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            return prepare_rsa_private_key(self.trad_key)
        if isinstance(self.trad_key, ec.EllipticCurvePrivateKey):
            return self.trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        return self.trad_key.private_bytes_raw()

    def _export_private_key(self) -> bytes:
        """Export the private key."""
        # Export the private key as seed.
        pq_ele = univ.OctetString(self.pq_key._export_private_key())  # pylint: disable=protected-access
        pq_ele = encoder.encode(pq_ele)
        trad_ele = univ.OctetString(self._export_trad_key())
        _length = len(pq_ele).to_bytes(4, byteorder="little", signed=False)
        return _length + pq_ele + encoder.encode(trad_ele)

    def public_key(self) -> "CompositeSig04PublicKey":
        """Generate the public key corresponding to this composite private key."""
        return CompositeSig04PublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def get_oid(self, use_pss: bool = True, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        _name = self._get_name(use_pss=use_pss, pre_hash=pre_hash)
        if COMPOSITE_SIG04_NAME_2_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite signature combination: {_name}")
        return COMPOSITE_SIG04_NAME_2_OID[_name]

    def _prepare_input(self, data: bytes, ctx: bytes, use_pss: bool, pre_hash: bool) -> bytes:
        """Prepare the input for the composite signature.

        :param data: The data to be signed.
        :param ctx: The context for the signature.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :param pre_hash: Indicates whether the data was pre-hashed before signing.
        :return: The prepared input.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        length_bytes = len(ctx).to_bytes(1, "little", signed=False)

        if pre_hash:
            hash_alg = COMP_SIG04_PREHASH_OID_2_HASH.get(domain_oid, "sha512")
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = _compute_hash(alg_name=hash_alg, data=data)
            # Construct M' with pre-hashing
            # Compute M' = Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)
            m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Prefix || Domain || len(ctx) || ctx || M
            m_prime = _PREFIX + encoder.encode(domain_oid) + length_bytes + ctx + data
        return m_prime

    @staticmethod
    def _prepare_composite_sig04(pq_sig: bytes, trad_sig: bytes) -> bytes:
        """Prepare the composite signature for draft v04."""
        # Check length limits
        if len(pq_sig) > (2**32 - 1):
            raise ValueError("ML-DSA signature too long to encode in 4 bytes.")

        mldsa_length_encoded = len(pq_sig).to_bytes(4, byteorder="little")
        # the cryptography library directly returns the DER-encoded signature.
        # and the PQ signature is raw, so now additional encoding is needed.
        return mldsa_length_encoded + pq_sig + trad_sig

    def sign(self, data: bytes, ctx: bytes = b"", use_pss: bool = False, pre_hash: bool = False) -> bytes:
        """Sign data with optional pre-hashing and context.

        :param data: The data to sign.
        :param ctx: The context for the signature, must not exceed 255 bytes.
        :param use_pss: Whether to use padding.
        :param pre_hash: Whether to pre-hash the data before signing it.
        :return: The encoded signature.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, pre_hash=pre_hash)
        mldsa_sig = self.pq_key.sign(data=m_prime, ctx=encoder.encode(domain_oid))
        trad_sig = self._sign_trad(data=m_prime, use_pss=use_pss)
        return self._prepare_composite_sig04(mldsa_sig, trad_sig)
