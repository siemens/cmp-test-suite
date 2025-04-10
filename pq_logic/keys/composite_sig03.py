# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite Signature Implementation.

https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/03/

Composite ML-DSA For use in X.509 Public Key Infrastructure and CMS

"""

from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from resources import oid_mapping
from resources.exceptions import BadAsn1Data, InvalidKeyCombination
from resources.oid_mapping import sha_alg_name_to_oid
from resources.oidutils import (
    CMS_COMPOSITE03_NAME_2_OID,
    CMS_COMPOSITE_OID_2_NAME,
)
from robot.api.deco import not_keyword

from pq_logic.hybrid_structures import CompositeSignatureValue
from pq_logic.keys.abstract_wrapper_keys import (
    AbstractCompositePrivateKey,
    AbstractCompositePublicKey,
    ECSignKey,
    ECVerifyKey,
    HybridSigPrivateKey,
    HybridSigPublicKey,
)
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.tmp_oids import (
    CMS_COMPOSITE03_OID_2_HASH,
    COMP_SIG03_PREHASH_OID_2_HASH,
    COMPOSITE_SIG03_HASH_NAME_2_OID,
    PURE_COMPOSITE_SIG03_NAME_TO_OID,
)


# to avoid import conflicts will be removed in the future.
@not_keyword
def _compute_hash(alg_name: str, data: bytes) -> bytes:
    """Calculate the hash of data using an algorithm given by its name.

    :param alg_name: The Name of algorithm, e.g., 'sha256', see HASH_NAME_OBJ_MAP.
    :param data: The buffer we want to hash.
    :return: The resulting hash.
    """
    hash_class = oid_mapping.hash_name_to_instance(alg_name)
    digest = hashes.Hash(hash_class)
    digest.update(data)
    return digest.finalize()


def get_names_from_oid(oid: univ.ObjectIdentifier) -> Tuple[str, str]:
    """Retrieve the parameter_set of ML-DSA and the key type based on the given OID.

    :param oid: The Object Identifier (OID) to look up in the composite name mappings.
    :return: A tuple of two strings:
             - The ML-DSA parameter_set (e.g., "ml-dsa-44")
             - The key type (e.g., "rsa2048-pss", "ed25519", etc.)
    :raises ValueError: If the OID is not found in either PURE_COMPOSITE_NAME_TO_OID
                        or HASH_COMPOSITE_NAME_TO_OID.
    """

    def split_name(parsed_name: str, prefix: str = "") -> Tuple[str, str]:
        if prefix:
            parsed_name = parsed_name.replace(prefix, "")
        parts = parsed_name.split("-")
        parameter_set = "-".join(parts[:3])  # "ml-dsa-44", "ml-dsa-65", etc.
        key_type = "-".join(parts[3:])  # "rsa2048-pss", "ed25519", etc.
        return parameter_set, key_type

    for name, registered_oid in PURE_COMPOSITE_SIG03_NAME_TO_OID.items():
        if oid == registered_oid:
            return split_name(name, prefix="composite-sig-")

    for name, registered_oid in COMPOSITE_SIG03_HASH_NAME_2_OID.items():
        if oid == registered_oid:
            return split_name(name, prefix="composite-sig-hash-")

    raise ValueError(f"OID {oid} not found in the composite name mappings.")


def _get_trad_name(
    trad_key: Union[
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        rsa.RSAPrivateKey,
        rsa.RSAPublicKey,
        ed25519.Ed25519PrivateKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PrivateKey,
        ed448.Ed448PublicKey,
    ],
    use_pss: bool = False,
    curve: Optional[str] = None,
    length: Optional[int] = None,
    allow_bad_rsa: bool = False,
) -> str:
    """Retrieve the traditional algorithm name based on the key type.

    :param trad_key: The traditional key object.
    :param use_pss: Whether to use RSA-PSS padding. Defaults to `False`.
    :param curve: Optional curve name for EC keys. Defaults to `None`.
    :param length: Optional key length for RSA keys. Defaults to `None`.
    :param allow_bad_rsa: Allow the use of bad RSA key. Defaults to `False`.
    :return: The traditional algorithm name.
    :raise ValueError: If the composite key mapping is unsupported.
    """
    if isinstance(trad_key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        actual_curve = curve or trad_key.curve.name
        trad_name = f"ecdsa-{actual_curve}"
    elif isinstance(trad_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        key_size = length or trad_key.key_size
        if allow_bad_rsa and key_size not in [2048, 3072, 4096]:
            key_size = length or 2048

        trad_name = f"rsa{key_size}"
        if use_pss:
            trad_name += "-pss"
    elif isinstance(trad_key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        trad_name = "ed25519"
    elif isinstance(trad_key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        trad_name = "ed448"
    else:
        raise ValueError(f"Unsupported key type: {type(trad_key).__name__}.")
    return trad_name.lower().replace("_", "-")


def _prepare_composite_sig(pq_sig: bytes, trad_sig: bytes) -> bytes:
    """Prepare the composite signature.

    :param pq_sig: The post-quantum signature.
    :param trad_sig: The traditional signature.
    """
    vals = CompositeSignatureValue()
    vals.append(univ.BitString.fromOctetString(pq_sig))
    vals.append(univ.BitString.fromOctetString(trad_sig))
    return encoder.encode(vals)


def _get_hash(param: Union[str, int]) -> hashes.HashAlgorithm:
    """Retrieve the hash algorithm based on the given parameter."""
    if isinstance(param, int):
        return {
            2048: hashes.SHA256(),
            3072: hashes.SHA256(),
            4096: hashes.SHA384(),
        }[param]

    curve_to_hash = {
        "secp256r1": hashes.SHA256(),
        "secp384r1": hashes.SHA384(),
        "brainpoolP256r1": hashes.SHA256(),
        "brainpoolP384r1": hashes.SHA384(),
    }
    return curve_to_hash[param]


class CompositeSig03PublicKey(AbstractCompositePublicKey, HybridSigPublicKey):
    """Composite signature public key."""

    _pq_key: MLDSAPublicKey  # type: ignore
    _trad_key: Union[rsa.RSAPublicKey, ECVerifyKey]  # type: ignore

    def __init__(
        self,
        pq_key: MLDSAPublicKey,
        trad_key: Union[ECVerifyKey, rsa.RSAPublicKey],
    ) -> None:
        """Initialize the composite signature public key."""
        super().__init__(pq_key, trad_key)

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"COMPOSITE-SIG"

    def _get_name(self, use_pss: bool = False, pre_hash: bool = False) -> str:
        """Retrieve the composite signature name."""
        to_add = "" if not pre_hash else "hash-"
        trad_name = self._get_trad_key_name(use_pss=use_pss)
        return f"composite-sig-03-{to_add}{self.pq_key.name}-{trad_name}"

    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        _name = self._get_name(use_pss=use_pss, pre_hash=pre_hash)
        try:
            return CMS_COMPOSITE03_NAME_2_OID[_name]
        except KeyError as e:
            raise InvalidKeyCombination(f"Unsupported composite signature combination: {_name}") from e

    @property
    def name(self) -> str:
        """Return the name of the composite signature key."""
        return self._get_name(False, False)

    @property
    def pq_key(self) -> MLDSAPublicKey:
        """Return the post-quantum public key."""
        return self._pq_key

    @property
    def trad_key(
        self,
    ) -> Union[rsa.RSAPublicKey, ECVerifyKey]:
        """Return the traditional public key."""
        return self._trad_key

    def _verify_trad(
        self,
        data: bytes,
        signature: bytes,
        use_pss: bool = False,
    ) -> None:
        """Verify a traditional signature using the corresponding public key.

        :param data: The data that was signed.
        :param signature: The traditional signature to be verified.
        :param use_pss: Indicates whether RSA-PSS padding was used during signing.
        :raises ValueError: If the key type is unsupported.
        :raises InvalidSignature: If the signature verification fails.
        :raises ValueError: If the key type is unsupported.
        """
        if isinstance(self.trad_key, rsa.RSAPublicKey):
            hash_instance = _get_hash(self.trad_key.key_size)

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
            hash_instance = _get_hash(self.trad_key.curve.name)
            self.trad_key.verify(signature=signature, data=data, signature_algorithm=ec.ECDSA(hash_instance))
        else:
            raise ValueError("Unsupported traditional public key type.")

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
            hash_alg = CMS_COMPOSITE03_OID_2_HASH[domain_oid]
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = _compute_hash(alg_name=hash_alg, data=data)
            # Construct M' with pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || HashOID || PH(M)
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || M
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + data
        return m_prime

    def verify(
        self, data: bytes, signature: bytes, ctx: bytes = b"", use_pss: bool = False, pre_hash: bool = False
    ) -> None:
        """Verify a composite signature.

        :param data: The data that was signed.
        :param signature: The signature to verify.
        :param ctx: The context used during signing, must not exceed 255 bytes.
        :param use_pss: Whether RSA-PSS padding was used during signing.
        :param pre_hash: Whether the data was pre-hashed before signing.
        :return: True if the signature is valid, False otherwise.
        :raises ValueError: If the context length exceeds 255 bytes.
        :raises BadAsn1Data: If extra data is present after decoding the signature.
        :raises InvalidSignature: If the signature is invalid.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        decoded_signature, rest = decoder.decode(signature, asn1Spec=CompositeSignatureValue())

        if rest:
            raise BadAsn1Data("CompositeSignatureValue")

        mldsa_sig = decoded_signature[0].asOctets()
        trad_sig = decoded_signature[1].asOctets()

        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, pre_hash=pre_hash)
        self._pq_key.verify(data=m_prime, signature=mldsa_sig, ctx=encoder.encode(domain_oid))
        self._verify_trad(data=m_prime, signature=trad_sig, use_pss=use_pss)

    @staticmethod
    def validate_oid(oid: univ.ObjectIdentifier, key) -> None:
        """Validate that the given OID is compatible with the composite signature public key.

        :param oid: The object identifier to validate.
        :param key: The `CompositeSigCMSPublicKey` or `CompositeSigCMSPrivateKey` instance against which the
        validation is performed.
        :raises ValueError: If the OID is not compatible with the key.
        """
        CompositeSig03PrivateKey.validate_oid(oid, key)


class CompositeSig03PrivateKey(AbstractCompositePrivateKey, HybridSigPrivateKey):
    """Composite signature private key."""

    _pq_key: MLDSAPrivateKey
    _trad_key: Union[ECSignKey, RSAPrivateKey]
    _name = "composite-sig-03"

    @property
    def pq_key(self) -> MLDSAPrivateKey:
        """Return the post-quantum private key."""
        return self._pq_key

    @property
    def trad_key(self) -> Union[ECSignKey, RSAPrivateKey]:
        """Return the traditional private key."""
        return self._trad_key

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"COMPOSITE-SIG"

    @staticmethod
    def validate_oid(oid: univ.ObjectIdentifier, key: Union[CompositeSig03PublicKey, "CompositeSig03PrivateKey"]):
        """Validate that the given OID is compatible with the composite signature private key.

        :param oid: The object identifier to validate.
        :param key: The `CompositeSigCMSPrivateKey` or `CompositeSigCMSPublicKey` instance against which the
        validation is performed.
        :raises ValueError: If the OID is not compatible with the key.
        """
        if isinstance(key, CompositeSig03PrivateKey):
            key = key.public_key()

        name = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pre_hash = "hash-" in name
        use_pss = "-pss" in name
        loaded_oid = key.get_oid(use_pss=use_pss, pre_hash=use_pre_hash)
        if loaded_oid != oid:
            raise ValueError(f"OID mismatch. Got: {oid}. Key was:{loaded_oid}")

    def public_key(self) -> CompositeSig03PublicKey:
        """Generate the public key corresponding to this composite private key.

        :return: A `CompositeSigPublicKey` instance containing the public keys derived
             from the composite private key.
        """
        return CompositeSig03PublicKey(self._pq_key.public_key(), self.trad_key.public_key())

    def _get_trad_key_name(self, use_pss: bool = False) -> str:
        """Retrieve the traditional algorithm name based on the key type."""
        # to allow an invalid size for the RSA key.
        to_add = ""
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            to_add = "" if not use_pss else "-pss"
        return super()._get_trad_key_name() + to_add

    def _get_name(self, use_pss: bool = False, pre_hash: bool = False) -> str:
        """Retrieve the composite signature name."""
        to_add = "" if not pre_hash else "hash-"
        return f"{self._name}-{to_add}{self.pq_key.name}-{self._get_trad_key_name(use_pss=use_pss)}"

    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Get the OID for the composite signature."""
        _name = self._get_name(use_pss=use_pss, pre_hash=pre_hash)
        if CMS_COMPOSITE03_NAME_2_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite signature v4 combination: {_name}")
        return CMS_COMPOSITE03_NAME_2_OID[_name]

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
            hash_alg = COMP_SIG03_PREHASH_OID_2_HASH[domain_oid]
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = _compute_hash(alg_name=hash_alg, data=data)
            # Construct M' with pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || HashOID || PH(M)
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || M
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + data
        return m_prime

    def sign(self, data: bytes, ctx: bytes = b"", use_pss: bool = False, pre_hash: bool = False) -> bytes:
        """
        Sign data with optional pre-hashing and context.

        :param data: The data to sign.
        :param ctx: The context for the signature, must not exceed 255 bytes.
        :param use_pss: Whether to use padding.
        :param pre_hash: Whether to pre-hash the data before signing.
        :return: The encoded signature.
        """
        if len(ctx) > 255:
            raise ValueError("Context length exceeds 255 bytes")

        domain_oid = self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        m_prime = self._prepare_input(data=data, ctx=ctx, use_pss=use_pss, pre_hash=pre_hash)

        mldsa_sig = self.pq_key.sign(m_prime, ctx=encoder.encode(domain_oid))
        trad_sig = self._sign_trad(data=m_prime, use_pss=use_pss)

        return _prepare_composite_sig(mldsa_sig, trad_sig)

    def _sign_trad(self, data: bytes, use_pss: bool = False) -> bytes:
        """Generate a signature using the traditional private key.

        :param data: The data to be signed.
        :param use_pss: Indicates whether RSA-PSS padding should be used.
        :return: The signature as bytes.
        :raises ValueError: If the key type is unsupported.
        """
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            size = self._get_rsa_size(self.trad_key.key_size)
            hash_instance = _get_hash(size)

            if use_pss:
                rsa_padding = padding.PSS(mgf=padding.MGF1(hash_instance), salt_length=hash_instance.digest_size)
            else:
                rsa_padding = padding.PKCS1v15()
            return self.trad_key.sign(data=data, padding=rsa_padding, algorithm=hash_instance)
        if isinstance(self.trad_key, (ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey)):
            return self.trad_key.sign(data)  # type: ignore
        if isinstance(self.trad_key, ec.EllipticCurvePrivateKey):
            hash_instance = _get_hash(self.trad_key.curve.name)
            return self.trad_key.sign(data=data, signature_algorithm=ec.ECDSA(hash_instance))

        raise ValueError(
            f"CompositeSigPrivateKey: Unsupported traditional private key type.: {type(self.trad_key).__name__}"
        )

    @property
    def name(self) -> str:
        """Return the name of the composite signature."""
        return self.public_key().name
