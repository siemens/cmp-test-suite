# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite Signature Implementation.

https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03

Composite ML-DSA For use in X.509 Public Key Infrastructure and CMS

"""

from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280
from resources import oid_mapping
from resources.exceptions import BadAsn1Data, InvalidKeyCombination
from resources.oid_mapping import get_curve_instance, sha_alg_name_to_oid
from resources.oidutils import (
    ALL_POSS_COMBINATIONS,
    CMS_COMPOSITE_NAME_2_OID,
    CURVE_NAMES_TO_INSTANCES,
)

from pq_logic.hybrid_structures import CompositeSignaturePublicKeyAsn1, CompositeSignatureValue
from pq_logic.keys.abstract_composite import AbstractCompositeSigPrivateKey, AbstractCompositeSigPublicKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.tmp_oids import CMS_COMPOSITE_OID_2_HASH, HASH_COMPOSITE_NAME_TO_OID, PURE_COMPOSITE_NAME_TO_OID


def get_valid_comb(
    pq_name: Optional[str] = None,
    trad_name: Optional[str] = None,
    length: Optional[str] = None,
    curve: Optional[str] = None,
):
    """Get the valid combination of ML-DSA and traditional algorithm based on the given parameters.

    :param pq_name: The name of the PQ algorithm.
    :param trad_name: The traditional algorithm name.
    :param length: The key length for RSA keys.
    :param curve: The curve name for EC keys.
    :return: A dictionary with the matching combination, or None if no match is found.
    """
    if pq_name is None and trad_name is None:
        return {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"}

    for entry in ALL_POSS_COMBINATIONS:
        if pq_name and entry["pq_name"] == pq_name:
            return entry

        if entry["trad_name"] == trad_name:
            if length is None and curve is None and pq_name is None:
                return entry

            if "length" in entry and length and entry["length"] == length:
                return entry
            if "curve" in entry and curve and entry["curve"] == curve:
                return entry
            if "length" not in entry and "curve" not in entry:
                return entry

    raise ValueError(
        f"No valid combination found for pq_name={pq_name}, trad_name={trad_name}, length={length}, curve={curve}"
    )


def compute_hash(alg_name: str, data: bytes) -> bytes:
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
    """
    Retrieve the version of ML-DSA and the key type based on the given OID.

    :param oid: The Object Identifier (OID) to look up in the composite name mappings.
    :return: A tuple of two strings:
             - The ML-DSA version (e.g., "ml-dsa-44")
             - The key type (e.g., "rsa2048-pss", "ed25519", etc.)
    :raises ValueError: If the OID is not found in either PURE_COMPOSITE_NAME_TO_OID
                        or HASH_COMPOSITE_NAME_TO_OID.
    """
    def split_name(name: str, prefix: str = "") -> Tuple[str, str]:
        if prefix:
            name = name.replace(prefix, "")
        parts = name.split("-")
        version = "-".join(parts[:3])  # "ml-dsa-44", "ml-dsa-65", etc.
        key_type = "-".join(parts[3:])  # "rsa2048-pss", "ed25519", etc.
        return version, key_type

    for name, registered_oid in PURE_COMPOSITE_NAME_TO_OID.items():
        if oid == registered_oid:
            return split_name(name)

    for name, registered_oid in HASH_COMPOSITE_NAME_TO_OID.items():
        if oid == registered_oid:
            return split_name(name, prefix="hash-")

    raise ValueError(f"OID {oid} not found in the composite name mappings.")

def _prepare_sig_vals(sigs: List[bytes]) -> CompositeSignatureValue:
    """Prepare a CompositeSignatureValue object from a list of individual signatures.

    :param sigs: List of byte representations of individual signatures.
    :return: A CompositeSignatureValue object containing the encoded signatures.
    """
    sig_vals = CompositeSignatureValue()

    for x in sigs:
        val = univ.BitString.fromOctetString(x)
        sig_vals.append(val)

    return sig_vals


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
    use_padding: bool = False,
    curve: Optional[str] = None,
    length: Optional[int] = None,
) -> str:
    """Retrieve the traditional algorithm name based on the key type.

    :param trad_key: The traditional key object.
    :param use_padding: Whether to use RSA-PSS padding.
    :param curve: Optional curve name for EC keys.
    :param length: Optional key length for RSA keys.
    :return: The traditional algorithm name.
    :raise ValueError: If the composite key mapping is unsupported.
    """
    if isinstance(trad_key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        actual_curve = curve or trad_key.curve.name
        trad_name = f"ecdsa-{actual_curve}"
    elif isinstance(trad_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        key_size = length or trad_key.key_size
        trad_name = f"rsa{key_size}"
        if use_padding:
            trad_name += "-pss"
        else:
            trad_name += "-pkcs15"
    elif isinstance(trad_key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        trad_name = "ed25519"
    elif isinstance(trad_key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        trad_name = "ed448"
    else:
        raise ValueError(f"Unsupported key type: {type(trad_key).__name__}.")
    return trad_name.lower().replace("_", "-")


def get_oid_cms_composite_signature(
    ml_dsa_name: str,
    trad_key: Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    use_pss: bool = False,
    pre_hash: bool = False,
    length: Optional[int] = None,
) -> univ.ObjectIdentifier:
    """Retrieve the OID for a composite signature, using a stringified version of the key name.

    :param ml_dsa_name: The ML-DSA name, such as 'ml-dsa-65'.
    :param trad_key: The traditional key object.
    :param use_pss: Indicates whether RSA-PSS padding is used.
    :param pre_hash: Indicates if the data is pre-hashed before signing.
    :return: The OID representing the composite signature configuration.
    :raises KeyError: If the OID cannot be resolved.
    """
    stringified_trad_name = _get_trad_name(trad_key, use_padding=use_pss, length=length)
    to_add = "" if not pre_hash else "hash-"
    oid_base = f"{to_add}{ml_dsa_name}-{stringified_trad_name}"
    oid = CMS_COMPOSITE_NAME_2_OID.get(oid_base)
    if oid is None:
        raise InvalidKeyCombination(f"Invalid composite signature combination: {oid_base}")

    return oid


class CompositeSigCMSPublicKey(AbstractCompositeSigPublicKey):
    """Composite signature public key."""

    pq_key: MLDSAPublicKey
    trad_key: Union[rsa.RSAPublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey]

    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature."""
        return get_oid_cms_composite_signature(
            self.pq_key.name,
            self.trad_key,  # type: ignore
            use_pss=use_pss,
            pre_hash=pre_hash,
        )

    def get_name(self, use_pss: bool = False, pre_hash: bool = False) -> str:
        """Return the name of the composite signature."""
        stringified_trad_name = _get_trad_name(self.trad_key, use_padding=use_pss)
        to_add = "" if not pre_hash else "hash-"
        oid_base = f"{to_add}{self.pq_key.name}-{stringified_trad_name}"
        return oid_base

    def _get_hash_name(
        self, domain_oid: Optional[univ.ObjectIdentifier] = None, use_pss: bool = False, pre_hash: bool = False
    ) -> str:
        """Retrieve the hash algorithm name for the given composite signature combination."""
        domain_oid = domain_oid or self.get_oid(use_pss=use_pss, pre_hash=pre_hash)
        return CMS_COMPOSITE_OID_2_HASH[domain_oid]

    @staticmethod
    def from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Parse a Composite Signature Public key from a `SubjectPublicKeyInfo` object.

        :param spki: The `SubjectPublicKeyInfo` object to parse.
        :return: The parsed `CompositeSigCMSPublicKey` instance.
        :raises ValueError: If the public key cannot be parsed.
        :raises ValueError: If extra data is present after decoding the public key.
        """
        obj, rest = decoder.decode(spki["subjectPublicKey"].asOctets(), CompositeSignaturePublicKeyAsn1())
        if rest != b"":
            raise ValueError("Extra data after decoding public key")

        pq_pub_bytes = obj[0].asOctets()
        trad_pub_bytes = obj[1].asOctets()

        ml_dsa_name, trad_name = get_names_from_oid(spki["algorithm"]["algorithm"])

        pq_pub = MLDSAPublicKey(public_key=pq_pub_bytes, sig_alg=ml_dsa_name.upper())

        if trad_name.startswith("ecdsa"):
            curve_name = trad_name.split("-")[1]
            curve = get_curve_instance(curve_name)
            trad_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, trad_pub_bytes)
        elif trad_name == "ed448":
            trad_pub = ed448.Ed448PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "ed25519":
            trad_pub = ed25519.Ed25519PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name.startswith("rsa"):
            trad_pub = serialization.load_der_public_key(trad_pub_bytes)
        else:
            raise ValueError(f"Unsupported traditional public key type: {trad_name}")
        return CompositeSigCMSPublicKey(pq_pub, trad_pub)

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

        # Determine the domain OID and hashing algorithm
        domain_oid = get_oid_cms_composite_signature(
            self.pq_key.name,
            self.trad_key,  # type: ignore
            use_pss=use_pss,
            pre_hash=pre_hash,
        )
        length_bytes = len(ctx).to_bytes(1, "big", signed=False)


        if pre_hash:
            hash_alg = CMS_COMPOSITE_OID_2_HASH[domain_oid]
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = compute_hash(alg_name=hash_alg, data=data)

            # Construct M' with pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || DERHashOID || PH(M)
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || M
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + data

        self.pq_key.verify(data=m_prime, signature=mldsa_sig, ctx=encoder.encode(domain_oid))
        self._verify_trad(data=m_prime, signature=trad_sig, use_pss=use_pss)

    @staticmethod
    def validate_oid(oid: univ.ObjectIdentifier, key) -> None:
        """Validate that the given OID is compatible with the composite signature public key.

        :param oid: The object identifier to validate.
        :param key: The `CompositeSigCMSPublicKey` or `CompositeSigCMSPrivateKey` instance against which the
        validation is performed.
        :raises ValueError: If the OID is not compatible with the key.
        """
        CompositeSigCMSPrivateKey.validate_oid(oid, key)


class CompositeSigCMSPrivateKey(AbstractCompositeSigPrivateKey):
    """Composite signature private key."""

    pq_key: MLDSAPrivateKey
    trad_key: Union[rsa.RSAPrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]

    @staticmethod
    def validate_oid(oid: univ.ObjectIdentifier, key: Union[CompositeSigCMSPublicKey, "CompositeSigCMSPrivateKey"]):
        """Validate that the given OID is compatible with the composite signature private key.

        :param oid: The object identifier to validate.
        :param key: The `CompositeSigCMSPrivateKey` or `CompositeSigCMSPublicKey` instance against which the
        validation is performed.
        :raises ValueError: If the OID is not compatible with the key.
        """
        try:
            pq_name, trad_name = get_names_from_oid(oid)
        except ValueError:
            raise ValueError(f"Invalid OID: {oid}")

        if not pq_name.startswith(key.pq_key.name):
            raise ValueError(f"OID's PQ name '{pq_name}' does not match the key's PQ name '{key.pq_key.name}'")

        expected_trad_name = _get_trad_name(key.trad_key)
        if isinstance(key.trad_key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            if trad_name.startswith(f"rsa{key.trad_key.key_size}"):
                return
            raise ValueError(
                f"OID's traditional name '{trad_name}' does not match the key's traditional name '{expected_trad_name}'"
            )

        if trad_name != expected_trad_name:
            raise ValueError(
                f"OID's traditional name '{trad_name}' does not match the key's traditional name '{expected_trad_name}'"
            )

    @staticmethod
    def generate(
        pq_name: str = "ml-dsa-65", trad_param: Optional[Union[int, str]] = 3072
    ) -> "CompositeSigCMSPrivateKey":
        """Generate a new composite private key, consisting of a pq and traditional private key.

        :param pq_name: The name of the post-quantum algorithm (default: "ml-dsa-65").
        :param trad_param: The parameter for the traditional key generation. For RSA,
                           this is the key size (e.g., 2048, 3072). For ECDSA, this is
                           the curve name (e.g., "secp256r1"). Default is 3072 for RSA.
        :return: A CompositeSigPrivateKey instance containing both private keys.
        :raises ValueError: If the provided parameters are invalid.
        """
        if isinstance(trad_param, int) or trad_param.isdigit():
            pq_name = pq_name or "ml-dsa-65"
            trad_private_key = rsa.generate_private_key(public_exponent=65537, key_size=int(trad_param))
        elif isinstance(trad_param, str):
            if trad_param in ["ec", "ecc", "ecdsa"]:
                pq_name = pq_name or "ml-dsa-44"
                trad_private_key = ec.generate_private_key(ec.SECP256R1())

            elif trad_param == "ed448":
                pq_name = pq_name or "ml-dsa-87"
                trad_private_key = ed448.Ed448PrivateKey.generate()
            elif trad_param == "ed25519":
                pq_name = pq_name or "ml-dsa-65"
                trad_private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                curve = CURVE_NAMES_TO_INSTANCES[trad_param]
                trad_private_key = ec.generate_private_key(curve)
        else:
            raise ValueError("trad_param must be an integer (RSA key size) or a string (EC curve name).")

        pq_private_key = MLDSAPrivateKey.generate(name=pq_name)
        return CompositeSigCMSPrivateKey(pq_key=pq_private_key, trad_key=trad_private_key)

    def public_key(self) -> CompositeSigCMSPublicKey:
        """Generate the public key corresponding to this composite private key.

        :return: A `CompositeSigPublicKey` instance containing the public keys derived
             from the composite private key.
        """
        return CompositeSigCMSPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def get_oid(self, use_padding: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature."""

        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            length = min(max(self.trad_key.key_size, 2048), 4096)

        return get_oid_cms_composite_signature(
            self.pq_key.name,
            self.trad_key,  # type: ignore
            use_pss=use_padding,
            pre_hash=pre_hash,
            length=length,
        )

    def _get_hash_name(
        self, domain_oid: Optional[univ.ObjectIdentifier] = None, use_padding: bool = False, pre_hash: bool = False
    ) -> str:
        """Retrieve the hash algorithm name for the given composite signature combination."""
        domain_oid = domain_oid or get_oid_cms_composite_signature(
            self.pq_key.name, self.trad_key, use_pss=use_padding, pre_hash=pre_hash
        )
        return CMS_COMPOSITE_OID_2_HASH[domain_oid]

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

        domain_oid = self.get_oid(use_padding=use_pss, pre_hash=pre_hash)
        length_bytes = len(ctx).to_bytes(1, "big", signed=False)

        if pre_hash:
            hash_alg = CMS_COMPOSITE_OID_2_HASH[domain_oid]
            hash_oid = encoder.encode(sha_alg_name_to_oid(hash_alg))
            hashed_data = compute_hash(alg_name=hash_alg, data=data)
            # Construct M' with pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || HashOID || PH(M)
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + hash_oid + hashed_data
        else:
            # Construct M' without pre-hashing
            # Compute M' = Domain || len(ctx) || ctx || M
            m_prime = encoder.encode(domain_oid) + length_bytes + ctx + data

        mldsa_sig = self.pq_key.sign(m_prime, ctx=encoder.encode(domain_oid))
        trad_sig = self._sign_trad(data=m_prime, use_pss=use_pss)

        return self.prepare_composite_sig(mldsa_sig, trad_sig)
