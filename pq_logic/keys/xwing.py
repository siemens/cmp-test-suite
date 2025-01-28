# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""XWing key classes."""

import base64
import logging
import os
import textwrap
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5958

from pq_logic.fips import fips203
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey, MLKEMPublicKey
from pq_logic.trad_key_factory import generate_trad_key
from pq_logic.trad_typing import ECDHPrivateKey

##################################
# XWing Keys
##################################

# TODO fix XWing serialization

_XWingLabel = bytes.fromhex("5c2e2f2f5e5c")  # Hex representation of "\.//^\"
_XWING_OID_STR = "1.3.6.1.4.1.62253.25722"


class XWingPublicKey(AbstractHybridRawPublicKey):
    """Class representing a XWing public key."""

    pq_key: MLKEMPublicKey
    trad_key: x25519.X25519PublicKey

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the key."""
        return univ.ObjectIdentifier(_XWING_OID_STR)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "XWingPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :return: The public key.
        """
        if len(data) != 1216:
            raise ValueError(f"Public key must be 1216 bytes in total, but got: {len(data)}.")

        pk_M = data[:1184]
        pk_X = data[1184:]
        trad_key = x25519.X25519PublicKey.from_public_bytes(pk_X)
        pq_key = MLKEMPublicKey(kem_alg="ml-kem-768", public_key=pk_M)
        return cls(pq_key=pq_key, trad_key=trad_key)

    def public_bytes_raw(self) -> bytes:
        """Serialize the public keys into a concatenated byte string."""
        return self.pq_key.public_bytes_raw() + self.trad_key.public_bytes_raw()

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
            "Unsupported combination of encoding and format. Only Raw-Raw, DER-SPKI, and PEM-SPKI are supported."
        )

    @property
    def key_size(self) -> int:
        """Return the size of the key in bits."""
        return self.pq_key.key_size + 32

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.pq_key.ct_length + 32

    def encaps(self, private_key: ECDHPrivateKey) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and ciphertext for the given private key.

        :param private_key: The private key to encapsulate the shared secret for.
        :return: The shared secret and ciphertext.
        """

        if not isinstance(private_key, x25519.X25519PrivateKey):
            private_key = x25519.X25519PrivateKey.generate()

        pk_X = self.trad_key.public_bytes_raw()
        ss_X = private_key.exchange(self.trad_key)
        ss_M, ct_M = self.pq_key.encaps()
        ct_X = private_key.public_key().public_bytes_raw()
        ss = XWingPrivateKey.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct


class XWingPrivateKey(AbstractHybridRawPrivateKey):
    """Class representing a XWing private key."""

    pq_key: MLKEMPrivateKey
    trad_key: x25519.X25519PrivateKey

    def _get_key_name(self) -> bytes:
        """Return the key name for the key, for saving the key to a file."""
        return b"XWING"

    @classmethod
    def from_private_bytes(cls, data: bytes):
        """Create a private key from the given byte string.

        :param data: The byte string to create the private key from.
        :return: The private key.
        """
        if len(data) != 2400 + 32:
            raise ValueError("The private key must be 2400 bytes for ML-KEM and 32 bytes for X25519.")

        trad_key = x25519.X25519PrivateKey.from_private_bytes(data[2400:])
        pq_key = MLKEMPrivateKey.from_private_bytes(data[:2400], "ml-kem-768")
        return cls(pq_key, trad_key)

    @staticmethod
    def kem_combiner(mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine shared secrets and other parameters into a final shared secret.

        :param mlkem_ss: Shared secret from ML-KEM.
        :param trad_ss: Shared secret from X25519.
        :param trad_ct: Ciphertext from X25519.
        :param trad_pk: Serialized X25519 public key.
        :return: The combined shared secret.
        """
        hash_function = hashes.Hash(hashes.SHA3_256())
        hash_function.update(mlkem_ss + trad_ss + trad_ct + trad_pk + _XWingLabel)
        ss = hash_function.finalize()
        logging.info("XWing ss: %s", ss)
        return ss

    def _to_one_asym_key(self) -> bytes:
        """Convert the private key into a `OneAsymmetricKey` object.

        To write the private key in the PKCS#8 format, the `OneAsymmetricKey` object is used.
        (formerly known as `PrivateKeyInfo`)

        :return: The `OneAsymmetricKey` object.
        """
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = 0
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = univ.ObjectIdentifier(_XWING_OID_STR)
        one_asym_key["privateKey"] = univ.OctetString(self.private_bytes_raw())
        # The publicKey component MUST be absent
        # as of https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html
        # Section 5.8.2. Private key
        return encoder.encode(one_asym_key)

    def encaps(self, public_key: XWingPublicKey) -> (bytes, bytes):
        """Encapsulate a shared secret and ciphertext for the given public key.

        :param public_key: The public key to encapsulate the shared secret for.
        :return: The shared secret and ciphertext.
        """
        pk_X = public_key.trad_key.public_bytes_raw()
        ss_X = self.trad_key.exchange(public_key.trad_key)
        ss_M, ct_M = public_key.pq_key.encaps()
        ct_X = self.trad_key.public_key().public_bytes_raw()
        ss = self.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct

    def decaps(self, ct: bytes):
        """Decapsulate a shared secret from the given ciphertext.

        :param ct: The ciphertext to decapsulate the shared secret from.
        :return: The shared secret.
        """
        ct_M = ct[:1088]
        ct_X = ct[1088:1120]
        ss_M = self.pq_key.decaps(ct_M)
        ss_X = self.trad_key.exchange(x25519.X25519PublicKey.from_public_bytes(ct_X))
        pk_X = self.trad_key.public_key().public_bytes_raw()
        ss = self.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        return ss

    @staticmethod
    def generate(**params):
        """Generate a new private key."""
        return XWingPrivateKey(MLKEMPrivateKey(kem_alg="ml-kem-768"), generate_trad_key("x25519"))  # type: ignore

    def public_key(self) -> XWingPublicKey:
        """Return the corresponding public key class."""
        return XWingPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def private_bytes_raw(self) -> bytes:
        """Serialize the private keys into a concatenated byte string."""
        return self.pq_key.private_bytes_raw() + self.trad_key.private_bytes_raw()

    @staticmethod
    def ml_kem_keygen_internal(d: bytes, z: bytes) -> MLKEMPrivateKey:
        """Generate the ML-KEM key pair.

        :param d: The randomness d.
        :param z: The randomness z.
        :return: The ML-KEM private key.
        """
        ek, dk = fips203.ML_KEM("ml-kem-768").keygen_internal(d, z)
        return MLKEMPrivateKey(kem_alg="ml-kem-768", public_key=ek, private_bytes=dk)

    @classmethod
    def expand(cls, sk: Optional[bytes] = None):
        """Expand the 32-byte secret seed into its components.

        :param sk: A 32-byte secret seed to derive the keys from.
        :return: The created private key.
        """
        sk = sk or os.urandom(32)
        shake = hashes.SHAKE256(digest_size=96)
        hasher = hashes.Hash(shake)
        hasher.update(sk)
        expanded = hasher.finalize()
        seed1 = expanded[:32]
        seed2 = expanded[32:64]

        ml_kem_key = XWingPrivateKey.ml_kem_keygen_internal(seed1, seed2)
        x25519_key = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
        return cls(ml_kem_key, x25519_key)

    @property
    def key_size(self) -> int:
        """Return the size of the key in bits."""
        return self.pq_key.key_size + 32

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.public_key().ct_length

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return "xwing"
