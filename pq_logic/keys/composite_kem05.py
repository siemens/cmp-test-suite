# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite ML-KEM for use in X.509 Public Key Infrastructure and CMS.

https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/

If there are changes wanted or changes need to be done,
please contact me on GitHub.

This is a work in progress, which means there is nothing finalized yet.
So changes are incurable to have a better implementation.

Known differences to Draft.

This implementation is currently not testes against test vectors,
but I am working on it, to get some.
For HPKE DKHEM are some available, so as soon as Test vectors are available
this implementation should also be valid for the different implementations.

Issues: Use HPKE DHKEM instead of custom DHKEM #98
Issues: No composite is currently compatible with CNSA 2.0 #102 (Does not support extra OIDs for now.)

"""

import logging
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ

from pq_logic.hybrid_structures import CompositeCiphertextValue
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
from pq_logic.tmp_oids import COMPOSITE_KEM05_NAME_2_OID
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey
from resources.exceptions import BadAsn1Data, InvalidKeyCombination


def _get_composite_kem_hash_alg(pq_name: str, trad_key, alternative: bool = False) -> str:
    """Return the hash algorithm for a composite KEM.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key algorithm.
    :param alternative: Whether to use an alternative hash algorithm.
    (addresses the issue:  No composite is currently compatible with CNSA 2.0 #102 )
    (to use HKDF-SHA2-512)
    :return: The hash algorithm.
    """
    # TODO maybe do directly by claimed NIST level ?

    if pq_name in ["ml-kem-1024", "frodokem-1344-aes", "frodokem-1344-shake"]:
        return "sha3-256"

    if pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"] and isinstance(
        trad_key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)
    ):
        return "sha3-256"

    if pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"]:
        return "hkdf-sha256" if not alternative else "hkdf-sha512"

    raise InvalidKeyCombination(f"Unsupported composite KEM: {pq_name} with {trad_key}")


class CompositeKEMPublicKey(HybridKEMPublicKey, AbstractCompositePublicKey):
    """A composite key for a KEM public key."""

    _trad_key: TradKEMPublicKey
    _alternative_hash: bool = False
    _name = "composite-kem-05"

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
    def name(self) -> str:
        """Return the name of the composite KEM."""
        return f"{self._name}-{self.pq_key.name}-{self.trad_key.get_trad_name}"

    @property
    def key_size(self) -> int:
        """Return the key size of the composite KEM."""
        return len(self._export_public_key())

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if COMPOSITE_KEM05_NAME_2_OID.get(self.name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {self.name}")
        return COMPOSITE_KEM05_NAME_2_OID[self.name]

    @property
    def trad_key(self) -> TradKEMPublicKey:
        """Return the traditional KEM public key."""
        return self._trad_key  # type: ignore

    @property
    def pq_key(self) -> PQKEMPublicKey:
        """Return the post-quantum KEM public key."""
        return self._pq_key  # type: ignore

    def kem_combiner(self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine the shared secrets and encapsulation artifacts into a single shared secret.

        :param mlkem_ss: Shared secret generated from the ML-KEM encapsulation.
        :param trad_ss: Shared secret generated from the traditional KEM encapsulation.
        :param trad_ct: Ciphertext from the traditional KEM encapsulation.
        :param trad_pk: Serialized public key of the traditional KEM.
        :return: A combined shared secret as bytes, derived using a KDF (HKDF or SHA3-256).

        :raises KeyError: If the OID mapping for the specified keys is not found.
        """
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk + encoder.encode(self.get_oid())
        logging.info("CompositeKEM concatenated inputs: %s", concatenated_inputs)
        kdf_name = _get_composite_kem_hash_alg(self.pq_key.name, self.trad_key)

        if "hkdf" in kdf_name:
            hash_instance = hashes.SHA256() if not self._alternative_hash else hashes.SHA512()
            hkdf = HKDF(algorithm=hash_instance, length=32, salt=None, info=None)
            return hkdf.derive(concatenated_inputs)

        h = hashes.Hash(hashes.SHA3_256())
        h.update(concatenated_inputs)
        return h.finalize()

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

    def _prepare_ct_vals(self, mlkem_ct: bytes, trad_ct: bytes) -> bytes:
        """Prepare the composite ciphertext values for encoding."""
        ct_vals = CompositeCiphertextValue()
        ct_vals.append(univ.OctetString(mlkem_ct))
        ct_vals.append(univ.OctetString(trad_ct))
        return encoder.encode(ct_vals)

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the composite KEM algorithm.

        :param private_key: The private key to use for encapsulation.
        :return: The shared secret and encapsulated ciphertext.
        """
        mlkem_ss, mlkem_ct = self.pq_key.encaps()
        trad_ss, trad_ct = self._trad_encaps(private_key)
        trad_pk = self.trad_key.encode()
        combined_ss = self.kem_combiner(
            mlkem_ss,
            trad_ss,
            trad_ct,
            trad_pk,
        )
        return combined_ss, self._prepare_ct_vals(mlkem_ct, trad_ct)


class CompositeKEMPrivateKey(HybridKEMPrivateKey, AbstractCompositePrivateKey):
    """A composite key for a KEM private key."""

    _trad_key: TradKEMPrivateKey
    _pq_key: PQKEMPrivateKey
    _alternative_hash: bool = False
    _name = "composite-kem-05"

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"COMPOSITE-KEM"

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[TradKEMPrivateKey, ECDHPrivateKey, RSAPrivateKey]):
        """Initialize the composite KEM private key.

        :param pq_key: The post-quantum KEM private key.
        :param trad_key: The traditional KEM private key.
        """
        super().__init__(pq_key, trad_key)
        if isinstance(trad_key, TradKEMPrivateKey):
            self._trad_key = DHKEMPrivateKey(trad_key._private_key, use_rfc9180=False)  # type: ignore
        elif isinstance(trad_key, ECDHPrivateKey):
            self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=False)
        elif isinstance(trad_key, RSAPrivateKey):
            self._trad_key = RSADecapKey(trad_key)
        else:
            raise ValueError(f"Unsupported trad_key type: {type(trad_key)}")

    @property
    def trad_key(self) -> TradKEMPrivateKey:
        """Return the traditional KEM private key."""
        return self._trad_key

    @property
    def pq_key(self) -> PQKEMPrivateKey:
        """Return the post-quantum KEM private key."""
        return self._pq_key

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        if isinstance(self.trad_key, RSADecapKey):
            size = self._get_rsa_size(self.trad_key._private_key.key_size)  # pylint: disable=protected-access
            trad_name = f"rsa{size}"

        elif isinstance(self.trad_key, DHKEMPrivateKey):
            trad_name = self.trad_key.get_trad_name

        else:
            trad_name = super()._get_trad_key_name()
        _name = f"{self._name}-{self.pq_key.name}-{trad_name}"

        if COMPOSITE_KEM05_NAME_2_OID.get(_name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {_name}")

        return COMPOSITE_KEM05_NAME_2_OID[_name]

    def public_key(self) -> CompositeKEMPublicKey:
        """Return the public key of the composite KEM."""
        return CompositeKEMPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def kem_combiner(self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine the shared secrets and encapsulation artifacts into a single shared secret.

        :param mlkem_ss: Shared secret generated from the ML-KEM encapsulation.
        :param trad_ss: Shared secret generated from the traditional KEM encapsulation.
        :param trad_ct: Ciphertext from the traditional KEM encapsulation.
        :param trad_pk: Serialized public key of the traditional KEM.
        :return: A combined shared secret as bytes, derived using a KDF (HKDF or SHA3-256).

        :raises KeyError: If the OID mapping for the specified keys is not found.
        """
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk + encoder.encode(self.get_oid())
        logging.info("CompositeKEM concatenated inputs: %s", concatenated_inputs)
        kdf_name = _get_composite_kem_hash_alg(self.pq_key.name, self.trad_key)

        if "hkdf" in kdf_name:
            hash_instance = hashes.SHA256() if not self._alternative_hash else hashes.SHA512()
            hkdf = HKDF(algorithm=hash_instance, length=32, salt=None, info=None)
            return hkdf.derive(concatenated_inputs)

        h = hashes.Hash(hashes.SHA3_256())
        h.update(concatenated_inputs)
        return h.finalize()

    def _perform_trad_decaps(self, trad_ct: bytes) -> bytes:
        """Perform traditional key decapsulation using the specified KEM mechanism."""
        if isinstance(self.trad_key, RSADecapKey):
            return self.trad_key.decaps(trad_ct, use_oaep=True, hash_alg="sha256")
        return self.trad_key.decaps(trad_ct)

    def encode_trad_part(self) -> bytes:
        """Encode the traditional part of the composite key."""
        return self.trad_key.public_key().encode()

    def decaps(self, ct: bytes) -> bytes:
        """Perform key decapsulation to compute the combined shared secret.

        :param ct: The DER-encoded encapsulated composite ciphertext, both ML-KEM and traditional KEM.
        :return: The computed combined shared secret as bytes.
        :raises BadAsn1Data: If the ciphertext structure is invalid or cannot be decoded.
        """
        ct_val, rest = decoder.decode(ct, CompositeCiphertextValue())  # type: ignore
        if rest:
            raise BadAsn1Data("CompositeCiphertextValue")

        ct_val: CompositeCiphertextValue

        mlkem_ct = ct_val[0].asOctets()
        trad_ct = ct_val[1].asOctets()
        mlkem_ss = self.pq_key.decaps(mlkem_ct)
        trad_ss = self._perform_trad_decaps(trad_ct)
        trad_pk = self.encode_trad_part()
        combined_ss = self.kem_combiner(
            mlkem_ss,
            trad_ss,
            trad_ct,
            trad_pk,
        )
        return combined_ss

    @property
    def name(self) -> str:
        """Return the name of the composite KEM key."""
        return self.public_key().name

    @property
    def key_size(self) -> int:
        """Return the key size of the composite KEM."""
        return len(self._export_private_key())
