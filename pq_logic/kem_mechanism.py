# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import random
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from resources.cryptoutils import perform_ecdh
from resources.oid_mapping import hash_name_to_instance

from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey

#####################################
# KemMechanism Interface
#####################################


class KemMechanism(ABC):
    """Abstract class for different KEM mechanisms (e.g., RSA- or -ECDH KEM)."""

    @abstractmethod
    def encaps(self, public_key) -> (bytes, bytes):
        """Encapsulate a shared secret using the given public key.

        :raise: The public key of the recipient.
        :return: (shared_secret, ciphertext_or_serialized_public_data).
        """
        pass

    @abstractmethod
    def decaps(self, private_key, ciphertext_or_public_data) -> bytes:
        """Decapsulate to recover the shared secret using the given private key and ciphertext/public data.

        :return: The Shared_secret.
        """
        pass


#####################################
# Separate ECDH KEM Class
#####################################


class ECDHKEM(KemMechanism):
    """ECDH-KEM mechanism. Uses ephemeral ECDH to generate a shared secret."""

    def __init__(self, private_key: Optional = None):
        """Initialize the ECDH-KEM instance.

        :param private_key: The private key to use for the instance. If none is provided,
        a new key will be generated, during the encapsulation process.
        """
        self.private_key = private_key

    @staticmethod
    def encode_public_key(pubkey) -> bytes:
        """Encode a public key to a standardized byte format.

        :param pubkey: The public key to encode.
        :return: The encoded public key as bytes.
        """
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            return pubkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)
        elif isinstance(pubkey, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return pubkey.public_bytes_raw()
        else:
            raise TypeError("Unsupported public key type for encoding.")

    @staticmethod
    def generate_matching_private_key(peer_pubkey: ECDHPublicKey) -> ECDHPrivateKey:
        """Generate a private key matching the type of a given peer public key.

        :param peer_pubkey: The public key of the peer.
        :return: A generated private key matching the type of the peer public key.
        """
        if isinstance(peer_pubkey, ec.EllipticCurvePublicKey):
            return ec.generate_private_key(peer_pubkey.curve)
        elif isinstance(peer_pubkey, x25519.X25519PublicKey):
            return x25519.X25519PrivateKey.generate()
        elif isinstance(peer_pubkey, x448.X448PublicKey):
            return x448.X448PrivateKey.generate()
        else:
            raise TypeError("Unsupported peer public key type.")

    def encaps(self, receiver_public_key) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the ephemeral ECDH private key and the receiver's public key.

        :param receiver_public_key: The public key of the receiver.
        :return: The shared secret and the serialized ephemeral public key as bytes.
        """
        if not self.private_key:
            self.private_key = self.generate_matching_private_key(receiver_public_key)

        shared_secret = perform_ecdh(self.private_key, receiver_public_key)
        ephemeral_public_key = self.private_key.public_key()
        return shared_secret, ECDHKEM.encode_public_key(ephemeral_public_key)

    def decaps(self, serialized_public_key: bytes) -> bytes:
        """Decapsulate the shared secret using the serialized public key.

        :param serialized_public_key: The serialized public key of the sender.
        :return: The shared secret as bytes.
        """
        shared_secret = self._exchange_from_bytes(serialized_public_key)
        return shared_secret

    def _exchange_from_bytes(self, enc: Union[bytes, ECDHPublicKey]) -> bytes:
        """Recreate a shared secret from an encapsulated key.

        :param enc: Encapsulated key as bytes or object.
        :return: The shared secret as bytes.
        """
        if not isinstance(enc, ECDHPublicKey):
            if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                enc_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(self.private_key.curve, enc)
            elif isinstance(self.private_key, x25519.X25519PrivateKey):
                enc_pub_key = x25519.X25519PublicKey.from_public_bytes(enc)
            else:
                enc_pub_key = x448.X448PublicKey.from_public_bytes(enc)
        else:
            enc_pub_key = enc
        return perform_ecdh(self.private_key, enc_pub_key)


KEY_TYPE_TO_ID = {
    "secp256r1": 0x0010,
    "brainpoolP256": 0x0010,  # not specified!
    "secp384r1": 0x0011,
    "brainpoolP384": 0x0011,  # not specified!
    "secp521r1": 0x0012,  # # currently not considered in Chempat.
    "x25519": 0x0020,
    "x448": 0x0021,
}

ID_TO_SHA = {
    0x0010: hashes.SHA256(),
    0x0020: hashes.SHA256(),
    0x0011: hashes.SHA384(),
    0x0012: hashes.SHA512(),  # currently not considered in Chempat
    0x0021: hashes.SHA512(),
}


def _get_key_id(key: Union[ECDHPrivateKey, ECDHPublicKey]) -> int:
    """Return the key algorithm ID used in the key derivation.

    :param key: The key used to extract the matching ID.
    :return: The correct cipher ID.
    """
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        curve_name = key.curve.name.lower()
        return KEY_TYPE_TO_ID.get(curve_name)
    elif isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return KEY_TYPE_TO_ID["x448"]
    else:
        return KEY_TYPE_TO_ID["x25519"]


def _i2osp(num: int, size: int) -> bytes:
    """Convert an integer to a byte array of a specified size.

    :param num: The integer to convert.
    :param size: The size of the resulting byte array.
    :return: The byte array representation of the integer.
    """
    return num.to_bytes(size, byteorder="big", signed=False)


class DHKEMRFC9180:
    """Class implementing a Diffie-Hellman Key Encapsulation Mechanism (DHKEM) as per RFC 9180."""

    def __init__(self, context: str = "HPKE-v1", private_key: Optional[ECDHPrivateKey] = None):
        """Initialize a DHKEM instance.

        :param context: A string representing the application-specific context.
        :param private_key: An optional ECDH private key for the instance.
        """
        self.context = bytes(context, "utf-8")
        self.private_key = private_key
        self.hash_algorithm = hashes.SHA256()

    def _get_hash_length(self) -> int:
        """Retrieve the length of the output for the current hash algorithm.

        :return: The digest size of the hash algorithm in bytes.
        """
        return self.hash_algorithm.digest_size

    @staticmethod
    def encode_public_key(pubkey: ec.EllipticCurvePublicKey) -> bytes:
        """Encode a public key to a standardized byte format.

        :param pubkey: The public key to encode.
        :return: The encoded public key as bytes.
        """
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            return pubkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)
        elif isinstance(pubkey, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return pubkey.public_bytes_raw()
        else:
            raise TypeError("Unsupported public key type for encoding.")

    def _extract_and_expand(self, dh: bytes, kem_context: bytes, cipher_id: int) -> bytes:
        """Perform HKDF extract-and-expand for key derivation.

        :param dh: The EC-Diffie-Hellman shared secret as bytes.
        :param kem_context: The KEM-specific context information as bytes. (public key)
        :param cipher_id: The algorithm identifier as an integer.
        :return: The derived shared secret as bytes.
        """
        suite_id = b"KEM" + _i2osp(cipher_id, 2)
        labeled_ikm = self.context + suite_id + b"eae_prk" + dh

        length_bytes = _i2osp(self._get_hash_length(), 2)
        labeled_info = length_bytes + self.context + suite_id + b"shared_secret" + kem_context

        hkdf = HKDF(algorithm=self.hash_algorithm, length=self._get_hash_length(), salt=b"", info=labeled_info)

        shared_secret = hkdf.derive(labeled_ikm)
        logging.info("DHKEM ss: %s", shared_secret.hex())

        return shared_secret

    def encaps(self, peer_pubkey: ECDHPublicKey) -> tuple[bytes, bytes]:
        """Perform key encapsulation to derive a shared secret and encapsulated key.

        :param peer_pubkey: The public key of the peer.
        :return: A tuple containing the derived shared secret and the encapsulated key.
        """
        if self.private_key is None:
            self.private_key = ECDHKEM.generate_matching_private_key(peer_pubkey)

        shared_tmp = self._perform_exchange(peer_pubkey=peer_pubkey)

        enc = self.encode_public_key(self.private_key.public_key())
        key_id = _get_key_id(self.private_key)
        self.hash_algorithm = ID_TO_SHA[key_id]

        kem_context = enc + self.encode_public_key(peer_pubkey)
        shared_secret = self._extract_and_expand(shared_tmp, kem_context, key_id)
        return shared_secret, enc

    def _perform_exchange(self, peer_pubkey: ECDHPublicKey) -> bytes:
        """Perform a Diffie-Hellman exchange with the peer public key.

        :param peer_pubkey: The public key of the peer.
        :return: The shared secret as bytes.
        """
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            shared_key = self.private_key.exchange(ec.ECDH(), peer_pubkey)
        else:
            shared_key = self.private_key.exchange(peer_pubkey)

        return shared_key

    def _exchange_from_bytes(self, enc: Union[bytes, ECDHPublicKey]) -> bytes:
        """Recreate a shared secret from an encapsulated key.

        :param enc: Encapsulated key as bytes or object.
        :return: The shared secret as bytes.
        """
        if not isinstance(enc, ECDHPublicKey):
            if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                enc_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(self.private_key.curve, enc)
            elif isinstance(self.private_key, x25519.X25519PrivateKey):
                enc_pub_key = x25519.X25519PublicKey.from_public_bytes(enc)
            else:
                enc_pub_key = x448.X448PublicKey.from_public_bytes(enc)
        else:
            enc_pub_key = enc
        return self._perform_exchange(enc_pub_key)

    def decaps(self, enc: Union[bytes, ECDHPublicKey]) -> bytes:
        """Perform key decapsulation to derive the shared secret.

        :param enc: The encapsulated key as bytes or object.
        :return: The derived shared secret as bytes.
        """
        shared_tmp = self._exchange_from_bytes(enc=enc)
        key_id = _get_key_id(self.private_key)
        self.hash_algorithm = ID_TO_SHA[key_id]
        kem_context = enc + self.encode_public_key(self.private_key.public_key())
        shared_secret = self._extract_and_expand(shared_tmp, kem_context, key_id)
        return shared_secret


#####################################
# RSA KEM
#####################################


class RSAKem(KemMechanism):
    """RSA-based KEM mechanism."""

    def encaps(self, public_key: rsa.RSAPublicKey, rand: Optional[int] = None) -> (bytes, bytes):
        """Encapsulate a shared secret using the RSA public key.

        :param public_key: The RSA public key.
        :param rand: An optional random value to use for encapsulation.
        :return: The shared secret and the ciphertext.
        """
        pub_num = public_key.public_numbers()
        e, n = pub_num.e, pub_num.n
        shared_secret = rand or random.randint(2, n - 1)  # MUST always be random.
        ct = pow(shared_secret, e, n)
        return shared_secret, ct

    def decaps(self, private_key: rsa.RSAPrivateKey, ct_or_public_data: bytes) -> bytes:
        """Decapsulate a shared secret using the RSA private key and the ciphertext.

        :param private_key: The RSA private key.
        :param ct_or_public_data: The ciphertext or public data.
        :return: The shared secret.
        """
        ct = int.from_bytes(ct_or_public_data, "big")
        n, d = private_key.private_numbers().public_numbers.n, private_key.private_numbers().d
        z = pow(ct, d, n)
        # convert large int to bytes
        return z.to_bytes((z.bit_length() + 7) // 8, "big")


class RSAOaepKem(KemMechanism):
    """RSA-OAEP based KEM mechanism."""

    def __init__(self, hash_alg: str = "sha256", ss_len: int = 32):
        """Initialize the RSA-OAEP KEM mechanism.

        :param hash_alg: The hash algorithm to use.
        :param ss_len: The shared secret length.
        """
        self.hash_alg = hash_name_to_instance(hash_alg)
        self.ss_len = ss_len

    def encaps(self, public_key: rsa.RSAPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using RSA-OAEP.

        :param public_key: The public key to use for the encapsulation.
        :return: The shared secret and the ciphertext.
        """
        shared_secret = os.urandom(self.ss_len)
        ciphertext = public_key.encrypt(
            shared_secret, padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_alg), algorithm=self.hash_alg, label=None)
        )
        return shared_secret, ciphertext

    def decaps(self, private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using RSA-OAEP.

        :param private_key: The private key to use for the decryption.
        :param ciphertext: The ciphertext to decrypt.
        :return: The shared secret.
        """
        shared_secret = private_key.decrypt(
            ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_alg), algorithm=self.hash_alg, label=None)
        )
        return shared_secret
