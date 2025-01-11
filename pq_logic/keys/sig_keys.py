# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the classes for the public and private keys of the supported post-quantum signature algorithms."""

import logging
import os
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder

from pq_logic.fips.fips204 import ML_DSA
from resources.oid_mapping import compute_hash, sha_alg_name_to_oid

from pq_logic.fips import fips204, fips205
from pq_logic.fips.fips205 import SLH_DSA
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from resources.oidutils import SLH_DSA_NAME_2_OID_PRE_HASH

##########################
# ML-DSA
##########################

try:
    import oqs
except ImportError:
    logging.info("PQ support is disabled.")
    oqs = None


class MLDSAPublicKey(PQSignaturePublicKey):
    """Represent an ML-DSA public key.

    This wrapper class provides support for ML-DSA public keys, which are not currently natively supported by the
    `cryptography` library. Provides functionality to manage, serialize, and use ML-DSA private keys. Methods in
    this class are modeled after the `cryptography` library for consistency.

    Available methods:
        - `public_bytes(encoding, format)`: Serialize the public key in the specified encoding and format.
        - `verify(signature, data)`: Verify a signature for provided data.

    """

    def _init(self, sig_alg: str, public_key: bytes) -> None:
        """Initialize the ML-DSA public key.

        :param sig_alg: The signature algorithm name.
        :param public_key: The public key bytes.
        :return: The initialized ML-DSA public key.
        """

        self._check_name(sig_alg)
        self.ml_class = ML_DSA(sig_alg)
        self._public_key_bytes = public_key

    def verify(
        self,
        signature: bytes,
        data: bytes,
        ctx: bytes = b"",
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
    ) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        """
        logging.info("ctx is currently not supported, possible in liboqs version 13.")

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer then 255 bytes.Got: {len(ctx)}")

        # disabled liboqs, because the signatures did not verify correctly for pqc-certificates!
        #if hash_alg is None and ctx == b"":
        #    super().verify(signature=signature, data=data)
        #    return

        hash_alg = self.check_hash_alg(hash_alg=hash_alg, allow_failure=False)
        ml_ = fips204.ML_DSA(self.name)
        if hash_alg is None:
            sig = ml_.verify(pk=self.public_bytes_raw(), sig=signature, m=data, ctx=ctx)


        elif hash_alg is not None:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.verify_internal(pk=self._public_key_bytes, mp=mp, sig=signature)

        if not sig:
            raise InvalidSignature()

    def _validate_hash_alg(self, hash_alg: Union[None, str, hashes.HashAlgorithm] = None):
        if isinstance(hash_alg, hashes.SHA512):
            pass
        elif hash_alg in ["sha512", None]:
            pass

        else:
            raise ValueError(f"Invalid hash algorithm for {self.name}: {hash_alg}")

    @property
    def name(self) -> str:
        """Return the name of the algorithm."""
        return self.sig_alg.lower()

    def check_hash_alg(self, hash_alg: Optional[str], allow_failure: bool = True) -> Optional[str]:
        """Check if the hash algorithm is valid."""
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.SHA512):
            return "sha512"

        if hash_alg not in [None, "sha512"]:
            if not allow_failure:
                raise ValueError(f"The provided hash algorithm is not supported for ML-DSA. Provided: {hash_alg}")
            return None

        return hash_alg

    def _check_name(self, name: str):
        name = name.upper()
        if name not in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            raise ValueError(f"Invalid signature algorithm name provided.: {name}")

        self.sig_alg = name


class MLDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an ML-DSA private key."""

    def _get_key_name(self) -> bytes:
        """Return the name of the key, to save it in a file as PEM-header."""
        return b"ML-DSA"

    @classmethod
    def generate(cls, name: str):
        """Generate a MLDSAPrivateKey."""
        return cls(name)

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _check_name(self, name: str):
        """Check if the name is valid."""
        name = name.upper()
        if name not in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            raise ValueError(f"Invalid signature algorithm name provided.: {name}")

        self.sig_alg = name

    def public_key(self) -> MLDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `MLDSAPublicKey` instance.
        """
        return MLDSAPublicKey(sig_alg=self.sig_alg, public_key=self._public_key)

    def sign(
        self,
        data: bytes,
        ctx: bytes = b"",
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign the data with ML-DSA private key.

        :param data: The data to sign.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        :return: The computed signature.
        """
        logging.info("ctx is currently not supported, possible in liboqs version 13.")

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer then 255 bytes.Got: {len(ctx)}")

        #if hash_alg is None and ctx == b"":
        #    return super().sign(data=data)

        elif hash_alg is None:
            ml_ = fips204.ML_DSA(self.name)
            sig = ml_.sign(sk=self.private_bytes_raw(), m=data, ctx=ctx)
        else:
            ml_ = fips204.ML_DSA(self.name)
            hash_alg = self.check_hash_alg(hash_alg=hash_alg)
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.sign_internal(self._private_key, mp, os.urandom(32))

        if not sig:
            raise ValueError("Could not sign the data with ML-DSA")

        return sig


##########################
# SLH-DSA
##########################


class SLHDSAPublicKey(PQSignaturePublicKey):
    """Represent an SLH-DSA public key."""

    def _init(self, sig_alg: str, public_key: bytes) -> None:
        """Initialize the SLH-DSA public key.

        :param sig_alg: The signature algorithm name.
        :param public_key: The public key bytes.
        :return: The initialized SLH-DSA public key.
        """
        self.sig_alg = sig_alg.replace("_", "-")
        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[self.sig_alg]
        self._public_key_bytes = public_key

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg

    def _check_name(self, name: str):
        """Check if the parsed name is valid."""
        pass

    def check_hash_alg(self, hash_alg: Optional[str] = None) -> Optional[str]:
        """Check if the hash algorithm is valid to be used with SLH-DSA."""
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.HashAlgorithm):
            hash_alg = hash_alg.name.lower()

        alg = self.name + "-" + hash_alg
        if SLH_DSA_NAME_2_OID_PRE_HASH.get(alg):
            return hash_alg
        return None



    def _validate_hash_alg(self, hash_alg: Optional[str] = None):
        if hash_alg not in [None, "sha512", "sha256", "shake128", "shake256"]:
            raise ValueError(f"The provided hash algorithm is not supported for SLH-DSA. Provided: {hash_alg}")

    def verify(self, signature: bytes, data: bytes, ctx: bytes = b"", hash_alg: Optional[str] = None) -> None:
        """Verify the signature of the data."""



        return self._slh_class.slh_verify(m=data, sig=signature, pk=self._public_key_bytes, ctx=ctx)


class SLHDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an SLH-DSA private key.

    This wrapper class provides support for SLH-DSA private keys, which are not currently natively supported by the
    `cryptography` library. Provides functionality to manage, serialize, and use SLH-DSA private keys. Methods in this
     class are modeled after the `cryptography` library for consistency.

    """

    def _init(self, sig_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None) -> None:
        self.sig_alg = sig_alg.replace("_", "-")

        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[self.sig_alg]

        if private_bytes is None:
            self._private_key, self._public_key = self._slh_class.slh_keygen()
        else:
            self._private_key = private_bytes
            self._public_key = public_key

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg

    def _get_key_name(self) -> bytes:
        """Return the name of the key, to save it in a file as PEM-header."""
        return b"SLH-DSA"

    def _check_name(self, name: str):
        """Check if the name is valid."""
        pass

    def check_hash_alg(self, hash_alg: Union[None, hashes.HashAlgorithm, str]) -> Optional[str]:
        """Check if the hash algorithm is valid."""

        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.HashAlgorithm):
            hash_alg = hash_alg.name.lower()

        alg = self.name + "-" + hash_alg
        if SLH_DSA_NAME_2_OID_PRE_HASH.get(alg):
            return hash_alg
        return None


    def public_key(self) -> SLHDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `SLHDSAPublicKey` instance.
        """
        return SLHDSAPublicKey(sig_alg=self.sig_alg, public_key=self._public_key)

    def sign(self, data: bytes, hash_alg: Optional[str] = None, ctx: bytes = b"", is_prehashed: bool = False) -> bytes:
        """Sign the data with SLH-DSA private key.

        :param data: The data to sign.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        Defaults to `None`.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param is_prehashed: Whether the data is prehashed. Defaults to False.
        :return: The computed signature.
        :raises ValueError: If the data is and no hash algorithm is specified.
        ValueError: If the context is too long (255).
        ValueError: If the signature cannot be computed.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)
        if hash_alg is None:
            sig = self._slh_class.slh_sign(m=data, sk=self._private_key, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + self._slh_class.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = self._slh_class.slh_sign_internal(self._private_key, mp)

        if not sig:
            raise ValueError("Could not sign the data with SLH-DSA")

        return sig


##########################
# Falcon
##########################


# TODO remove if FN-DSA is available.
class FalconPublicKey(PQSignaturePublicKey):
    """Represent a Falcon public key."""

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _check_name(self, name: str):
        """Check if the parsed name is valid."""
        if name not in ["falcon-512", "falcon-1024", "falcon-padded-512", "falcon-padded-1024"]:
            raise ValueError(
                f"Invalid `Falcon` signature algorithm name provided.: {name} "
                f"Supported names: 'falcon-512', 'falcon-1024', 'falcon-padded-512', 'falcon-padded-1024'"
            )

        self.sig_alg = name.capitalize()

    def check_hash_alg(self, hash_alg: Optional[str] = None) -> None:
        """Check if the hash algorithm is valid to be used with Falcon."""
        return None


class FalconPrivateKey(PQSignaturePrivateKey):
    """Represent a Falcon private key."""

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _get_key_name(self) -> bytes:
        """Return the name of the key, to save it in a file as PEM-header."""
        return b"Falcon"

    def public_key(self) -> FalconPublicKey:
        """Derive the corresponding public key."""
        return FalconPublicKey(sig_alg=self.name, public_key=self._public_key)

    def _check_name(self, name: str):
        """Check if the name is valid."""
        if name not in ["falcon-512", "falcon-1024", "falcon-padded-512", "falcon-padded-1024"]:
            raise ValueError(
                f"Invalid `Falcon` signature algorithm name provided.: {name} "
                f"Supported names: 'falcon-512', 'falcon-1024', 'falcon-padded-512', 'falcon-padded-1024'"
            )

        self.sig_alg = name.capitalize()

