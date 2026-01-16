# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite KEM 07 implementation.

Based on:https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-kem-07.html
"""

import logging
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import NoEncryption
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.codec.der import encoder
from pyasn1.type import univ

from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.keys.abstract_wrapper_keys import (
    AbstractCompositePrivateKey,
    AbstractCompositePublicKey,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    TradKEMPrivateKey,
    TradKEMPublicKey,
)
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey, RSADecapKey, RSAEncapKey
from pq_logic.tmp_oids import COMPOSITE_KEM_NAME_2_OID
from resources.exceptions import InvalidKeyCombination
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey


def _get_kdf_algorithm(pq_name: str, trad_key: TradKEMPublicKey) -> str:
    """Get the KDF algorithm based on the post-quantum and traditional key names."""
    trad_name = trad_key.get_trad_name
    if pq_name in ["ml-kem-768", "frodokem-976-aes", "frodokem-976-shake"] and trad_name == "x25519":
        return "sha3_256"
    if pq_name in ["ml-kem-768", "frodokem-976-aes", "frodokem-976-shake"]:
        return "hmac-sha256"
    if trad_name == "x448":
        return "sha3_256"
    return "hmac-sha512"


class CompositeKEMPublicKey(HybridKEMPublicKey, AbstractCompositePublicKey):
    """A Composite KEM public key for the Composite KEM 07."""

    _trad_key: TradKEMPublicKey
    _pq_key: PQKEMPublicKey
    _name = "composite-kem07"

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Union[TradKEMPublicKey, ECDHPublicKey, RSAPublicKey]):
        """Initialize the composite KEM public key."""
        super().__init__(pq_key, trad_key)

        if isinstance(trad_key, TradKEMPublicKey):
            self._trad_key = trad_key
        elif isinstance(trad_key, ECDHPublicKey):
            self._trad_key = DHKEMPublicKey(trad_key, use_rfc9180=False)
        elif isinstance(trad_key, RSAPublicKey):
            self._trad_key = RSAEncapKey(trad_key)
        else:
            raise ValueError(f"Unsupported trad_key type: {type(trad_key)}")

    @property
    def key_size(self) -> int:
        """Return the key size of the composite KEM public key."""
        return self.pq_key.key_size + self.trad_key.key_size

    @property
    def pq_key(self) -> PQKEMPublicKey:
        """Return the post-quantum KEM public key."""
        return self._pq_key

    @property
    def trad_key(self) -> TradKEMPublicKey:
        """Return the traditional KEM public key."""
        return self._trad_key

    @property
    def name(self) -> str:
        """Return the name of the composite KEM."""
        return self._name + "-" + self.pq_key.name + "-" + self.trad_key.get_trad_name

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if COMPOSITE_KEM_NAME_2_OID.get(self.name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {self.name}")
        return COMPOSITE_KEM_NAME_2_OID[self.name]

    def kem_combiner(
        self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes, use_in_cms: bool = False
    ) -> bytes:
        """Combine the shared secrets from the post-quantum and traditional parts.

        :param mlkem_ss: The shared secret from the post-quantum part.
        :param trad_ss: The shared secret from the traditional part.
        :param trad_ct: The traditional ciphertext.
        :param trad_pk: The traditional public key.
        :param use_in_cms: Whether to use the combined secret in a CMS context.
        :return: The combined shared secret.
        """
        der_oid = encoder.encode(self.get_oid())
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk + der_oid
        logging.info("CompositeKEM concatenated inputs: %s", concatenated_inputs.hex())
        kdf_name = _get_kdf_algorithm(self.pq_key.name, self.trad_key)
        logging.debug("KDF Name: %s", kdf_name)

        if use_in_cms:
            if kdf_name.startswith("hkdf-"):
                hash_alg = kdf_name.split("-")[1]
                if hash_alg == "sha512":
                    h = hashes.SHA512()
                elif hash_alg == "sha256":
                    h = hashes.SHA256()
                else:
                    raise NotImplementedError(f"Unsupported hash algorithm for KDF: {hash_alg}")

                hkdf = HKDF(algorithm=h, length=32, salt=None, info=None)
                hashed_output = hkdf.derive(concatenated_inputs)
                logging.debug("COMPOSITE KEM HKDF output: %s", hashed_output.hex())
                return hashed_output

        elif kdf_name.startswith("hmac-"):
            hash_alg = kdf_name.split("-")[1]
            if hash_alg == "sha256":
                h = hashes.SHA256()
                zero_bytes = b"\x00" * 32
            elif hash_alg == "sha512":
                h = hashes.SHA512()
                zero_bytes = b"\x00" * 64
            else:
                raise NotImplementedError(f"Unsupported hash algorithm for KDF: {hash_alg}")

            hmac_inst = HMAC(key=zero_bytes, algorithm=h)
            hmac_inst.update(concatenated_inputs)
            hashed_output = hmac_inst.finalize()[:32]  # Use the first 32 bytes
            logging.debug("COMPOSITE KEM HMAC output: %s", hashed_output.hex())
            return hashed_output

        h = hashes.Hash(hashes.SHA3_256())
        h.update(concatenated_inputs)
        ss = h.finalize()
        logging.debug("COMPOSITE KEM SHA3-256 output: %s", ss.hex())
        return ss

    def _trad_encaps(self, private_key: Optional[ECDHPrivateKey]) -> Tuple[bytes, bytes]:
        """Perform traditional key encapsulation using the specified KEM mechanism.

        :param private_key: The private key to use for encapsulation.
        :return: The shared secret and encapsulated ciphertext.
        """
        if isinstance(self.trad_key, RSAEncapKey):
            ss, ct = self.trad_key.encaps(use_oaep=True, hash_alg="sha256")
        else:
            ss, ct = self.trad_key.encaps(private_key=private_key)

        logging.info("Traditional KEM encaps ss: %s", ss.hex())
        logging.info("Traditional KEM encaps ct: %s", ct.hex())
        return ss, ct

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None, use_in_cms: bool = True) -> Tuple[bytes, bytes]:
        """Encapsulate the key encapsulation mechanism.

        :param private_key: The ECC private key to use for encapsulation.
        :param use_in_cms: Whether to use the combined secret in a CMS context.
        :return: A tuple containing the shared secret and the ciphertext.
        """
        mlkem_ss, mlkem_ct = self.pq_key.encaps()
        trad_ss, trad_ct = self._trad_encaps(private_key)
        combined_ss = self.kem_combiner(mlkem_ss, trad_ss, trad_ct, self.encode_trad_part(), use_in_cms=use_in_cms)
        return combined_ss, mlkem_ct + trad_ct

    def _export_public_key(self) -> bytes:
        """Export the public key."""
        return self.pq_key.public_bytes_raw() + self._trad_key.encode()

    def public_bytes_raw(self) -> bytes:
        """Export the raw public key, starting with the length of the PQ key."""
        return self._export_public_key()


class CompositeKEMPrivateKey(HybridKEMPrivateKey, AbstractCompositePrivateKey):
    """A Composite KEM private key for the Composite KEM 07."""

    _trad_key: TradKEMPrivateKey
    _pq_key: PQKEMPrivateKey
    _name = "composite-kem07"

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[TradKEMPrivateKey, ECDHPrivateKey, RSAPrivateKey]):
        """Initialize the composite KEM private key."""
        super().__init__(pq_key, trad_key)
        if isinstance(trad_key, TradKEMPrivateKey):
            self._trad_key = trad_key
        elif isinstance(trad_key, ECDHPrivateKey):
            self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=False)
        elif isinstance(trad_key, RSAPrivateKey):
            self._trad_key = RSADecapKey(trad_key)
        else:
            raise ValueError(f"Unsupported trad_key type: {type(trad_key)}")

    @property
    def pq_key(self) -> PQKEMPrivateKey:
        """Return the post-quantum KEM public key."""
        return self._pq_key

    @property
    def trad_key(self) -> TradKEMPrivateKey:
        """Return the traditional KEM public key."""
        return self._trad_key

    @property
    def name(self) -> str:
        """Return the name of the composite KEM."""
        return self._name + "-" + self.pq_key.name + "-" + self.trad_key.get_trad_name

    def _export_trad_private_key(self) -> bytes:
        """Export the traditional part of the private key."""
        name = self._trad_key.get_trad_name

        if name.startswith("ecdh"):
            return self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption(),
            )

        return super()._export_trad_private_key()

    def _export_private_key(self) -> bytes:
        """Export the private key."""
        if hasattr(self._pq_key, "private_numbers"):
            _pq_export = self._pq_key.private_numbers()
        else:
            _pq_export = self.pq_key.private_bytes_raw()
        return _pq_export + self._export_trad_private_key()

    def private_bytes_raw(self) -> bytes:
        """Export the raw private key, starting with the length of the PQ key."""
        return self._export_private_key()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if isinstance(self._trad_key, RSADecapKey):
            value = self._get_rsa_size(self._trad_key._private_key.key_size)  # pylint:disable=protected-access
            name = f"{self._name}-{self.pq_key.name}-rsa{value}"
        else:
            name = self.name
        if COMPOSITE_KEM_NAME_2_OID.get(name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {name}")
        return COMPOSITE_KEM_NAME_2_OID[name]

    def public_key(self) -> CompositeKEMPublicKey:
        """Return the public key associated with this private key."""
        return CompositeKEMPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def kem_combiner(
        self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes, use_in_cms: bool = False
    ) -> bytes:
        """Combine the shared secrets from the post-quantum and traditional parts.

        :param mlkem_ss: The shared secret from the post-quantum part.
        :param trad_ss: The shared secret from the traditional part.
        :param trad_ct: The traditional ciphertext.
        :param trad_pk: The traditional public key.
        :param use_in_cms: Whether to use the combined secret in a CMS context.
        :return: The combined shared secret.
        """
        return self.public_key().kem_combiner(mlkem_ss, trad_ss, trad_ct, trad_pk, use_in_cms)

    def encode_trad_part(self) -> bytes:
        """Encode the traditional part of the key."""
        return self.trad_key.public_key().encode()

    def decaps(self, ct: bytes, use_in_cms: bool = True) -> bytes:
        """Decapsulate the key encapsulation mechanism.

        :param ct: The ciphertext to decapsulate.
        :param use_in_cms: Whether to use the combined secret in a CMS context, uses HKDF instead of HMAC.
        :return: The shared secret.
        """
        mlkem_ct = ct[: self.pq_key.ct_length]
        trad_ct = ct[self.pq_key.ct_length :]
        mlkem_ss = self.pq_key.decaps(mlkem_ct)
        trad_ss = self._trad_key.decaps(trad_ct)
        combined_ss = self.kem_combiner(mlkem_ss, trad_ss, trad_ct, self.encode_trad_part(), use_in_cms=use_in_cms)
        return combined_ss


class CompositeDHKEMRFC9180PublicKey(CompositeKEMPublicKey):
    """Composite DHKEMRFC9180 public key."""

    _name = "composite-dhkem"
    _trad_key: DHKEMPublicKey

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Union[DHKEMPublicKey, ECDHPublicKey]):
        """Initialize the composite KEM private key."""
        super().__init__(pq_key, trad_key)
        self._trad_key = DHKEMPublicKey(trad_key, use_rfc9180=True)


class CompositeDHKEMRFC9180PrivateKey(CompositeKEMPrivateKey):
    """Composite DHKEMRFC9180 private key."""

    _name = "composite-dhkem"
    _trad_key: DHKEMPrivateKey

    @property
    def trad_key(self) -> DHKEMPrivateKey:
        """Return the traditional key."""
        return self._trad_key

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[DHKEMPrivateKey, ECDHPrivateKey]):
        """Initialize the composite KEM private key."""
        super().__init__(pq_key, trad_key)
        self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=True)

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"COMPOSITE-DHKEM"

    def public_key(self) -> CompositeDHKEMRFC9180PublicKey:
        """Return the public key of the composite KEM."""
        return CompositeDHKEMRFC9180PublicKey(self.pq_key.public_key(), self.trad_key.public_key())
