# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""
Wrapper classes for Post-Quantum signature Keys.

Classes in this file follow the `cryptography` library style. This ensures seamless integration
and allows the classes to be easily swapped out or extended in the future.

APIs are:

### Public Keys:
- `public_bytes(encoding: Encoding, format: PublicFormat)`: Serialize the public key into the specified encoding
and format.
- `_check_name(name: str)`: Validate the provided algorithm name.

### Private Keys:
- `public_key()`: Derive the corresponding public key from the private key.
- `generate(kem_alg: str)`: Generate a new private key for the specified algorithm.
- `_check_name(name: str)`: Validate the provided algorithm name.
"""

import importlib.util
import logging
import os
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder

from pq_logic.fips import fips204, fips205
from pq_logic.fips.fips204 import ML_DSA
from pq_logic.fips.fips205 import SLH_DSA, integer_to_bytes
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from resources.exceptions import InvalidKeyData
from resources.oid_mapping import compute_hash, sha_alg_name_to_oid
from resources.oidutils import SLH_DSA_PRE_HASH_NAME_2_OID

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error # type: ignore[import]
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name

FALCON_NAMES = ["falcon-512", "falcon-1024", "falcon-padded-512", "falcon-padded-1024"]
ML_DSA_NAMES = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]

# Mapping of SLH-DSA algorithm names to their liboqs counterparts.
SLH_DSA_LIBOQS_NAME_MAP = {
    "slh-dsa-sha2-128s": "SLH_DSA_PURE_SHA2_128S",
    "slh-dsa-sha2-128f": "SLH_DSA_PURE_SHA2_128F",
    "slh-dsa-sha2-192s": "SLH_DSA_PURE_SHA2_192S",
    "slh-dsa-sha2-192f": "SLH_DSA_PURE_SHA2_192F",
    "slh-dsa-sha2-256s": "SLH_DSA_PURE_SHA2_256S",
    "slh-dsa-sha2-256f": "SLH_DSA_PURE_SHA2_256F",
    "slh-dsa-shake-128s": "SLH_DSA_PURE_SHAKE_128S",
    "slh-dsa-shake-128f": "SLH_DSA_PURE_SHAKE_128F",
    "slh-dsa-shake-192s": "SLH_DSA_PURE_SHAKE_192S",
    "slh-dsa-shake-192f": "SLH_DSA_PURE_SHAKE_192F",
    "slh-dsa-shake-256s": "SLH_DSA_PURE_SHAKE_256S",
    "slh-dsa-shake-256f": "SLH_DSA_PURE_SHAKE_256F",
    # Pre-hash variants
    "slh-dsa-sha2-128s-sha256": "SLH_DSA_SHA2_256_PREHASH_SHA2_128S",
    "slh-dsa-sha2-128f-sha256": "SLH_DSA_SHA2_256_PREHASH_SHA2_128F",
    "slh-dsa-sha2-192s-sha512": "SLH_DSA_SHA2_512_PREHASH_SHA2_192S",
    "slh-dsa-sha2-192f-sha512": "SLH_DSA_SHA2_512_PREHASH_SHA2_192F",
    "slh-dsa-sha2-256s-sha512": "SLH_DSA_SHA2_512_PREHASH_SHA2_256S",
    "slh-dsa-sha2-256f-sha512": "SLH_DSA_SHA2_512_PREHASH_SHA2_256F",
    "slh-dsa-shake-128s-shake128": "SLH_DSA_SHAKE_128_PREHASH_SHAKE_128S",
    "slh-dsa-shake-128f-shake128": "SLH_DSA_SHAKE_128_PREHASH_SHAKE_128F",
    "slh-dsa-shake-192s-shake256": "SLH_DSA_SHAKE_256_PREHASH_SHAKE_192S",
    "slh-dsa-shake-192f-shake256": "SLH_DSA_SHAKE_256_PREHASH_SHAKE_192F",
    "slh-dsa-shake-256s-shake256": "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256S",
    "slh-dsa-shake-256f-shake256": "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F",
}


class MLDSAPublicKey(PQSignaturePublicKey):
    """Represent an ML-DSA public key."""

    def _initialize_key(self) -> None:
        """Initialize the ML-DSA public key."""
        self.ml_class = ML_DSA(self.name)
        if oqs is not None:
            self._sig_method = oqs.Signature(self._other_name)

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        sig_size = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}
        return sig_size[self.name]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        key_size = {"ml-dsa-44": 1312, "ml-dsa-65": 1952, "ml-dsa-87": 2592}
        return key_size[self.name]

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        """
        if len(ctx) > 255:
            raise ValueError(f"The context length is longer than 255 bytes. Got: {len(ctx)}")

        hash_alg = self.check_hash_alg(hash_alg=hash_alg, allow_failure=False)

        if hash_alg is None and not is_prehashed and oqs is not None:
            return super().verify(signature=signature, data=data, ctx=ctx)

        ml_ = fips204.ML_DSA(self.name)
        if hash_alg is None:
            sig = ml_.verify(pk=self.public_bytes_raw(), sig=signature, m=data, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                data = compute_hash(hash_alg, data)

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + data
            sig = ml_.verify_internal(pk=self._public_key_bytes, mp=mp, sig=signature)

        if not sig:
            raise InvalidSignature()

        return None

    def check_hash_alg(
        self, hash_alg: Optional[Union[str, hashes.HashAlgorithm]], allow_failure: bool = True
    ) -> Optional[str]:
        """Check if the hash algorithm is valid.

        :param hash_alg: The hash algorithm to check.
        :param allow_failure: Whether to allow failure or not.
        """
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.SHA512):
            return "sha512"

        if hash_alg != "sha512":
            if not allow_failure:
                raise ValueError(f"The provided hash algorithm is not supported for ML-DSA. Provided: {hash_alg}")
            logging.info("%s does not support the hash algorithm: %s", self.name, hash_alg)
            return None

        return hash_alg  # type: ignore

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the parsed name is valid.

        :param name: The name to check.
        """
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided: {name}.")

        return name, name.upper()

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "MLDSAPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The name of the signature algorithm.
        """
        key = MLDSAPublicKey(alg_name=name, public_key=data)
        if key.key_size != len(data):
            raise InvalidKeyData(
                f"Invalid public key size, for: {key.name}. Expected: {key.key_size}, got: {len(data)}"
            )
        return key

    @property
    def nist_level(self) -> int:
        """Return the NIST security level of the ML-DSA algorithm."""
        nist_levels = {"ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5}
        return nist_levels[self.name]


ML_DSA_PRIVATE_KEY_SIZE = {"ml-dsa-44": 2560, "ml-dsa-65": 4032, "ml-dsa-87": 4896}


class MLDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an ML-DSA private key."""

    def _derive_public_key(self, sk: bytes) -> bytes:
        """Derive the public key from the given ML-DSA secret key.

        The secret key is encoded as:
          sk = sk_encode(rho, kk, tr, s1, s2, t0)

        The public key is computed as:
          pk = pk_encode(rho, t1)
        where (t1, _) = power2round(t) and t is computed as:
          t = [ add(ntt_inverse(w_i), s2[i])
                for i, w_i in enumerate(matrix_vector_ntt(ah, s1h)) ]
        with:
          ah   = expand_a(rho)
          s1h  = [ ntt(v) for v in s1 ]

        :param sk: The ML-DSA secret key as bytes.
        :return: The corresponding public key as bytes.
        """
        # Decode the secret key to retrieve its components.
        rho, _, _, s1, s2, _ = self.ml_class.sk_decode(sk)
        # Compute the matrix a from rho.
        ah = self.ml_class.expand_a(rho)
        # Compute the NTT of each s1 vector.
        s1h = [self.ml_class.ntt(v) for v in s1]
        # Multiply the matrix a with s1 in the NTT domain.
        t = self.ml_class.matrix_vector_ntt(ah, s1h)
        # Add s2 (after applying the inverse NTT) component wise.
        t = [self.ml_class.add(self.ml_class.ntt_inverse(t_i), s2[i]) for i, t_i in enumerate(t)]
        # Compute (t1, t0) via power 2 round (we only need t1 for the public key).
        t1, _ = self.ml_class.power2round(t)
        # Encode and return the public key using rho and t1.
        pk = self.ml_class.pk_encode(rho, t1)
        return pk

    def private_numbers(self) -> bytes:
        """Return the private key seed, if available.

        :return: The private key seed as bytes.
        :raises ValueError: If the private key seed is not available.
        """
        if self._seed is None:
            raise ValueError("The private key seed is not available.")
        return self._seed

    def _initialize_key(self) -> None:
        """Initialize the ML-DSA private key."""
        self.ml_class = ML_DSA(self.name)

        if self._private_key_bytes is None and self._public_key_bytes is None:
            self._seed = self._seed or os.urandom(32)
            self._public_key_bytes, self._private_key_bytes = self.ml_class.keygen_internal(xi=self._seed)

        elif self._public_key_bytes is None and self._private_key_bytes is not None:
            self._public_key_bytes = self._derive_public_key(sk=self._private_key_bytes)

        elif self._public_key_bytes is not None and self._private_key_bytes is not None:
            pass
        else:
            raise ValueError(
                "Invalid key initialization for ML-DSA.Either provide a private key or a seed to generate a new key."
            )

        if oqs is not None:
            self._sig_method = oqs.Signature(self._other_name, secret_key=self._private_key_bytes)

    @staticmethod
    def _from_seed(alg_name: str, seed: Optional[bytes]) -> Tuple[bytes, bytes, bytes]:
        """Generate a ML-DSA private key from the seed."""
        _ml_class = ML_DSA(alg_name)
        if seed is None:
            seed = os.urandom(32)

        _public_key, _private_key = ML_DSA(alg_name).keygen_internal(xi=seed)
        return _private_key, _public_key, seed

    @classmethod
    def from_seed(cls, alg_name: str, seed: Optional[bytes] = None) -> "MLDSAPrivateKey":
        """Generate a MLDSAPrivateKey.

        :param alg_name: The name of the ML-DSA parameter set (e.g., "ml-dsa-44").
        :param seed: The seed to use for the key generation. Defaults to `None`.
        (will generate a random 32-bytes, seed if not provided).
        :return: The generated MLDSAPrivateKey.
        """
        if seed is None:
            seed = os.urandom(32)
        return cls(alg_name=alg_name, seed=seed)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "MLDSAPrivateKey":
        """Create a private key from the given byte string.

        :param data: The byte string to create the private key from.
        :param name: The name of the signature algorithm.
        :return: The loaded MLDSAPrivateKey.
        :raises ValueError: If the key name is not supported.
        :raises InvalidKeyData: If the private key data is invalid.
        """
        if len(data) == 32:
            return cls.from_seed(alg_name=name, seed=data)

        key_size = ML_DSA_PRIVATE_KEY_SIZE[name]

        if len(data) == key_size:
            key = cls(alg_name=name, private_bytes=data)
            return key

        if len(data) == key_size + 32:
            seed = data[:32]
            seed_key = cls.from_seed(alg_name=name, seed=seed)
            data = data[32:]

            if seed_key.private_bytes_raw() != data:
                raise InvalidKeyData("The ML-DSA private key does not match the seed.")

            return seed_key

        raise InvalidKeyData(f"Invalid private key size. Expected: {key_size}, got: {len(data)}")

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"ML-DSA"

    @classmethod
    def generate(cls, name: str):
        """Generate a MLDSAPrivateKey."""
        return cls(name)

    def _check_name(self, name: str):
        """Check if the name is valid."""
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided.: {name}")

        return name, name.upper()

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        return ML_DSA_PRIVATE_KEY_SIZE[self.name]

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        sig_size = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}
        return sig_size[self.name]

    def public_key(self) -> MLDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `MLDSAPublicKey` instance.
        """
        return MLDSAPublicKey(alg_name=self.name, public_key=self._public_key_bytes)

    def sign(
        self,
        data: bytes,
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        ctx: bytes = b"",
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign the data with ML-DSA private key.

        :param data: The data to sign.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        :return: The computed signature.
        """
        if len(ctx) > 255:
            raise ValueError(f"The context length is longer then 255 bytes.Got: {len(ctx)}")

        hash_alg = self.check_hash_alg(hash_alg)

        if hash_alg is None and not is_prehashed and oqs is not None:
            return super().sign(data=data, hash_alg=hash_alg, ctx=ctx)

        if hash_alg is None:
            ml_ = fips204.ML_DSA(self.name)
            sig = ml_.sign(sk=self._private_key_bytes, m=data, ctx=ctx)
        else:
            ml_ = fips204.ML_DSA(self.name)
            hash_alg = self.check_hash_alg(hash_alg=hash_alg)
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))  # type: ignore

            if hash_alg is None:
                raise ValueError(f"The provided hash algorithm is not supported for ML-DSA. Provided: {hash_alg}")

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.sign_internal(self._private_key_bytes, mp, os.urandom(32))

        if not sig:
            raise ValueError("Could not sign the data with ML-DSA")

        return sig

    @staticmethod
    def _seed_size(name: str) -> int:
        """Return the size of the seed used for ML-DSA key generation."""
        return 32

    @property
    def seed_size(self) -> int:
        """Return the size of the seed used for ML-DSA key generation."""
        return self._seed_size(name=self.name)


##########################
# SLH-DSA
##########################


def _get_liboqs_slh_dsa_name(alg_name: str, hash_alg: Optional[str]) -> str:
    """Get the SLH-DSA algorithm name based on the base algorithm and hash algorithm.

    :param alg_name: The base SLH-DSA algorithm name (e.g., "slh-dsa-sha2-128s").
    :param hash_alg: The optional hash algorithm name (e.g., "sha256").
    :return: The combined SLH-DSA algorithm name.
    """
    alg_name = alg_name.lower()

    if alg_name not in SLH_DSA_LIBOQS_NAME_MAP:
        raise ValueError(f"Invalid SLH-DSA algorithm name provided: {alg_name}.")

    if hash_alg is None:
        return SLH_DSA_LIBOQS_NAME_MAP[alg_name]

    hash_alg = hash_alg.lower()

    if hash_alg in ["sha256", "sha512", "shake128", "shake256"]:
        combined_name = f"{alg_name}-{hash_alg}"
        if combined_name in SLH_DSA_PRE_HASH_NAME_2_OID:
            return SLH_DSA_LIBOQS_NAME_MAP[combined_name]
        raise ValueError(f"Invalid combination of SLH-DSA and hash algorithm: {combined_name}.")

    raise ValueError(f"Invalid hash algorithm for SLH-DSA: {hash_alg}.")


class SLHDSAPublicKey(PQSignaturePublicKey):
    """Represent an SLH-DSA public key."""

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        return self._slh_class.n * 2

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"SLH-DSA"

    def _initialize_key(self) -> None:
        """Initialize the SLH-DSA public key."""
        _other = self.name.replace("_", "-")
        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[_other]

        if oqs is not None:
            oqs_name = SLH_DSA_LIBOQS_NAME_MAP.get(self.name)
            if oqs_name is not None:
                try:
                    self._sig_method = oqs.Signature(oqs_name)
                except Exception:  # pragma: no cover - liboqs not available pylint: disable=broad-exception-caught
                    self._sig_method = None

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the name is valid."""
        return name, name.replace("_", "-")

    def check_hash_alg(self, hash_alg: Union[None, str, hashes.HashAlgorithm]) -> Optional[str]:
        """Check if the hash algorithm is valid to be used with SLH-DSA.

        :param hash_alg: The hash algorithm to check.
        :return: The hash algorithm name or None.
        """
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.HashAlgorithm):
            hash_alg = hash_alg.name.lower()

        alg = self.name + "-" + hash_alg
        if SLH_DSA_PRE_HASH_NAME_2_OID.get(alg):
            return hash_alg
        logging.info("%s does not support the hash algorithm: %s", self.name, hash_alg)
        return None

    def _verify_oqs_signature(self, signature: bytes, data: bytes, ctx: bytes, hash_alg: Optional[str]) -> bool:
        """Verify the signature using liboqs.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :return: True if the signature is valid, False otherwise.
        :raises `InvalidSignature`: If the signature method is not initialized.
        """
        if self._sig_method is None:
            raise ValueError("liboqs signature method is not initialized.")
        try:
            tmp_name = _get_liboqs_slh_dsa_name(alg_name=self.name, hash_alg=hash_alg)
            with oqs.Signature(tmp_name) as _sig_method:
                result = _sig_method.verify_with_ctx_str(data, signature, ctx, self._public_key_bytes)

        except RuntimeError as exc:
            raise InvalidSignature() from exc
        return result

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        :raises InvalidSignature: If the signature is invalid.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)
        msg = "SLH-DSA Signature verification failed."

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer than 255 bytes. Got: {len(ctx)}")

        if not is_prehashed and getattr(self, "_sig_method", None):
            logging.info("Verify SLH-DSA signature with `liboqs`.")

            try:
                self._verify_oqs_signature(signature, data, ctx, hash_alg)
            except (RuntimeError, InvalidSignature) as exc:
                raise InvalidSignature(msg) from exc

        if hash_alg is None:
            sig = self._slh_class.slh_verify(m=data, sig=signature, pk=self._public_key_bytes, ctx=ctx)
        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                data = compute_hash(hash_alg, data)

            mp = b"\x01" + integer_to_bytes(len(ctx), 1) + ctx + oid + data
            sig = self._slh_class.slh_verify_internal(m=mp, sig=signature, pk=self._public_key_bytes)

        if not sig:
            raise InvalidSignature(msg)

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "SLHDSAPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The name of the signature algorithm.
        """
        key = SLHDSAPublicKey(alg_name=name, public_key=data)
        _n = key._slh_class.n * 2
        if _n != len(data):
            raise ValueError(f"Invalid public key size. Expected: {_n}, got: {len(data)}")
        return key

    @property
    def nist_level(self) -> int:
        """Return the nist level."""
        if oqs is not None:
            return super().nist_level
        if self.name.endswith("128s") or self.name.endswith("128f"):
            return 1
        if self.name.endswith("192s") or self.name.endswith("192f"):
            return 3
        if self.name.endswith("256s") or self.name.endswith("256f"):
            return 5
        raise ValueError(f"Cannot determine NIST level for SLH-DSA algorithm: {self.name}")


class SLHDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an SLH-DSA private key."""

    _other_name: str  # type: ignore

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        return self._slh_class.n * 4

    def _derive_public_key(self, private_key: bytes) -> bytes:
        """Derive the public key from the SLH-DSA private key.

        The private key is structured as (each part is n bytes-long):
        private_key = sk_seed || sk_prf || pk_seed || pk_root

        The public key is: public_key = pk_seed || pk_root

        :param private_key: The SLH-DSA private key as bytes.
        :return: The corresponding public key as bytes.
        """
        _n = self._slh_class.n
        if len(private_key) < 4 * _n:
            raise ValueError("Invalid private key length")

        pk_seed = private_key[2 * _n : 3 * _n]
        pk_root = private_key[3 * _n : 4 * _n]
        return pk_seed + pk_root

    def private_numbers(self) -> bytes:
        """Return the private key seed, if available."""
        if self._seed is None:
            raise ValueError("The private key seed is not available.")
        return self._seed

    @staticmethod
    def _from_seed(alg_name: str, seed: Optional[bytes]) -> Tuple[bytes, bytes, bytes]:
        """Generate a SLH-DSA private key from the seed."""
        _slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[alg_name.replace("_", "-")]
        _n = _slh_class.n
        if seed is None:
            seed = os.urandom(3 * _n)

        if len(seed) != 3 * _n:
            raise ValueError(f"Invalid seed size. Expected: {3 * _n}. Got: {len(seed)}")

        sk_seed = seed[:_n]
        sk_prf = seed[_n : 2 * _n]
        pk_seed = seed[2 * _n :]
        pub_key, priv_key = _slh_class.slh_keygen_internal(sk_seed, sk_prf, pk_seed)
        return priv_key, pub_key, seed

    def _initialize_key(self) -> None:
        """Initialize the SLH-DSA private key."""
        try:
            if oqs is not None:
                self._sig_method = oqs.Signature(SLH_DSA_LIBOQS_NAME_MAP[self.name], secret_key=self._private_key_bytes)
                if self._private_key_bytes is None and self._seed is None:
                    logging.info("Generate SLH-DSA keypair with `liboqs`")
                    self._public_key_bytes = self._sig_method.generate_keypair()
                    self._private_key_bytes = self._sig_method.export_secret_key()
                    seed_size = self._seed_size(self.name)
                    self._seed = self._private_key_bytes[:seed_size]

        except Exception:  # pragma: no cover - liboqs not available pylint: disable=broad-exception-caught
            self._sig_method = None

        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[self._other_name]
        if self._private_key_bytes is None and self._public_key_bytes is None:
            priv_key, pub_key, seed = self._from_seed(self.name, self._seed)
            self._private_key_bytes = priv_key
            self._public_key_bytes = pub_key
            self._seed = seed

        if self._private_key_bytes is not None and self._public_key_bytes is None:
            self._public_key_bytes = self._derive_public_key(private_key=self._private_key_bytes)

    def _export_private_key(self) -> bytes:
        """Export the private key."""
        return self._seed or self._private_key_bytes

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"SLH-DSA"

    def _check_name(self, name: str):
        """Check if the name is valid."""
        return name, name.replace("_", "-")

    def check_hash_alg(self, hash_alg: Union[None, str, hashes.HashAlgorithm]) -> Optional[str]:
        """Check if the hash algorithm is valid for the SLH-DSA key.

        :param hash_alg: The hash algorithm to check.
        :return: The hash algorithm name or None.
        """
        return self.public_key().check_hash_alg(hash_alg=hash_alg)

    def public_key(self) -> SLHDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `SLHDSAPublicKey` instance.
        """
        return SLHDSAPublicKey(alg_name=self.name, public_key=self._public_key_bytes)

    def _sign_with_oqs(self, data: bytes, ctx: bytes, hash_alg: Optional[str]) -> bytes:
        """Sign the data using liboqs.

        :param data: The data to sign.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The optional hash algorithm to use for the pre-hashing of the data.
        :return: The computed signature.
        :raises ValueError: If the signature method is not initialized.
        """
        if self._sig_method is None:
            raise ValueError("liboqs signature method is not initialized.")
        try:
            tmp_name = _get_liboqs_slh_dsa_name(alg_name=self.name, hash_alg=hash_alg)
            logging.info("Sing data with: %s", tmp_name)
            with oqs.Signature(tmp_name, secret_key=self._private_key_bytes) as _sig_method:
                sig = _sig_method.sign_with_ctx_str(data, ctx)
        except RuntimeError as exc:
            raise ValueError("Could not sign the data with SLH-DSA") from exc
        return sig

    def sign(
        self,
        data: bytes,
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        ctx: bytes = b"",
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign the data with SLH-DSA private key.

        :param data: The data to sign.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        Defaults to `None`.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param is_prehashed: Whether the data is prehashed. Defaults to False.
        :return: The computed signature.
        :raises ValueError: If the context is too long (255), or if the signature cannot be computed.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer than 255 bytes. Got: {len(ctx)}")

        if not is_prehashed and getattr(self, "_sig_method", None):
            logging.info("Sign SLH-DSA signature with `liboqs`.")
            return self._sign_with_oqs(data=data, ctx=ctx, hash_alg=hash_alg)

        if hash_alg is None:
            sig = self._slh_class.slh_sign(m=data, sk=self._private_key_bytes, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                data = compute_hash(hash_alg, data)

            mp = b"\x01" + integer_to_bytes(len(ctx), 1) + ctx + oid + data
            sig = self._slh_class.slh_sign_internal(m=mp, sk=self._private_key_bytes)

        if not sig:
            raise ValueError("Could not sign the data with SLH-DSA")

        return sig

    @classmethod
    def from_seed(cls, alg_name: str, seed: bytes) -> "SLHDSAPrivateKey":
        """Create a SLH-DSA private key from the seed."""
        private_bytes, public_bytes, seed = cls._from_seed(alg_name=alg_name, seed=seed)
        return SLHDSAPrivateKey(alg_name=alg_name, private_bytes=private_bytes, public_key=public_bytes, seed=seed)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "SLHDSAPrivateKey":
        """Create a private key from the given byte string.

        :param data: The byte string to create the private key from.
        :param name: The name of the signature algorithm.
        :return: The loaded SLHDSAPrivateKey.
        :raises ValueError: If the key name is not supported.
        :raises InvalidKeyData: If the key data is invalid.
        """
        obj = cls(alg_name=name)
        _n = obj._slh_class.n

        if len(data) == 3 * _n:
            # 3 * n is the length of the seed: sk_seed, sk_prf, pk_seed.
            s_key = cls.from_seed(alg_name=name, seed=data)

        elif len(data) == 7 * _n:
            # 7 * n is the length of the seed + private_key
            seed = data[: 3 * _n]
            private_key = data[3 * _n : 7 * _n]
            s_key = cls.from_seed(alg_name=name, seed=seed)
            if s_key.private_bytes_raw() != private_key:
                raise InvalidKeyData("The private key does not match the seed.")

        elif _n * 4 != len(data):
            raise InvalidKeyData(f"Invalid private key size. Expected: {4 * _n}, got: {len(data)}")

        else:
            # private_key = sk_seed || sk_prf || pk_seed || pk_root
            # Which is 4 * n bytes long.
            s_key = SLHDSAPrivateKey(alg_name=name, private_bytes=data)

        return s_key

    @classmethod
    def _verify_loaded_key(cls, alg_name: str, data: bytes, public_key: Optional[bytes] = None) -> "SLHDSAPrivateKey":
        """Verify the loaded key."""
        obj = cls(alg_name=alg_name)
        _n = obj._slh_class.n

        if len(data) == 3 * _n:
            s_key = cls.from_seed(alg_name=alg_name, seed=data)

        elif len(data) != 4 * _n:
            raise ValueError(f"Invalid private key size. Expected: {4 * _n}, got: {len(data)}")
        else:
            s_key = SLHDSAPrivateKey(alg_name=alg_name, private_bytes=data, public_key=public_key)

        if public_key is not None:
            if len(public_key) != 2 * _n:
                raise ValueError(f"Invalid public key size. Expected: {2 * _n}, got: {len(public_key)}")

            if s_key.public_key().public_bytes_raw() != public_key:
                raise ValueError("The provided public key does not match the private key.")

        return s_key

    @staticmethod
    def _seed_size(name: str) -> int:
        """Return the size of the seed used for SLH-DSA key generation."""
        _slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[name.replace("_", "-")]
        return 3 * _slh_class.n

    @property
    def seed_size(self) -> int:
        """Return the size of the seed used for SLH-DSA key generation."""
        return self._seed_size(name=self.name)


##########################
# Falcon
##########################


# TODO remove if FN-DSA is available.
class FalconPublicKey(PQSignaturePublicKey):
    """Represent a Falcon public key."""

    def _get_header_name(self) -> bytes:
        """Return the algorithm name, for the PEM header."""
        return b"FALCON"

    def _check_name(self, name: str):
        """Check if the parsed name is valid."""
        if name not in FALCON_NAMES:
            names = ", ".join(f"`{name}`" for name in FALCON_NAMES)
            raise ValueError(f"Invalid `Falcon` signature algorithm name provided.: {name} Supported names: {names}")

        return name, name.capitalize()

    def check_hash_alg(
        self,
        hash_alg: Union[None, str, hashes.HashAlgorithm],
    ) -> Optional[str]:
        """Check if the hash algorithm is valid.

        Falcon does not support any hash algorithms, so always return `None`.

        :param hash_alg: The hash algorithm to check.
        :return: The hash algorithm name or None.
        """
        if hash_alg is not None:
            logging.info("%s does not support the hash algorithm: %s", self.name, hash_alg)


class FalconPrivateKey(PQSignaturePrivateKey):
    """Represent a Falcon private key."""

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"FALCON"

    def public_key(self) -> FalconPublicKey:
        """Derive the corresponding public key."""
        return FalconPublicKey(alg_name=self.name, public_key=self._public_key_bytes)

    def _check_name(self, name: str):
        """Check if the name is valid.

        :param name: The name to check.
        """
        names = ", ".join(f"`{name}`" for name in FALCON_NAMES)
        if name not in FALCON_NAMES:
            raise ValueError(f"Invalid `Falcon` signature algorithm name provided.: {name} Supported names: {names}")
        return name, name.capitalize()
