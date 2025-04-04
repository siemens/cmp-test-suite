# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for handling keys in PyASN1 format."""

import base64
import os
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958, rfc9481
from robot.api.deco import not_keyword

from pq_logic.hybrid_structures import CompositeSignaturePrivateKeyAsn1
from pq_logic.keys.abstract_pq import PQPrivateKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey
from pq_logic.keys.kem_keys import FrodoKEMPrivateKey, McEliecePrivateKey, MLKEMPrivateKey, Sntrup761PrivateKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey, SLHDSAPrivateKey
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.tmp_oids import FRODOKEM_OID_2_NAME, MCELIECE_OID_2_NAME, id_sntrup761_str
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    CMS_COMPOSITE_OID_2_NAME,
    ML_DSA_OID_2_NAME,
    ML_KEM_OID_2_NAME,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    SLH_DSA_OID_2_NAME,
    TRAD_STR_OID_TO_KEY_NAME,
    XWING_OID_STR,
)

RawKeyType = Union[
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
    XWingPrivateKey,
    PQPrivateKey,
]


def compute_aes_cbc(key: bytes, data: bytes, iv: bytes, decrypt: bool = True) -> bytes:
    """Perform AES encryption or decryption in CBC mode.

    :param key: The AES key to be used for encryption/decryption.
    :param data: The plaintext (for encryption) or ciphertext (for decryption).
    :param iv: The initialization vector (IV) to be used in CBC mode.
    :param decrypt: A boolean indicating whether to decrypt (True) or encrypt (False).
    :return: The encrypted or decrypted data as bytes.
    :raises ValueError: If the key size is invalid or the input data is not a multiple of the block size.
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long for AES-CBC.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    if decrypt:
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        # Remove padding after decryption
        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()  # type: ignore
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data

    # Apply padding before encryption
    padder = aes_padding.PKCS7(algorithms.AES.block_size).padder()  # type: ignore
    padded_data = padder.update(data) + padder.finalize()

    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


# alternative approach.
def _prepare_enc_key(password: str, one_asym_key: bytes) -> rfc5958.EncryptedPrivateKeyInfo:
    """Prepare an `EncryptedPrivateKeyInfo` structure.

    :param password: Password for encryption.
    :param one_asym_key: Key to encrypt as DER-encoded `OneAsymmetricKey`.
    :return: The populated `EncryptedPrivateKeyInfo`.
    """
    iv = os.urandom(16)
    enc_algo = rfc5280.AlgorithmIdentifier()
    enc_algo["algorithm"] = rfc9481.id_aes256_CBC
    enc_algo["parameters"] = univ.OctetString(iv)

    enc_data = derive_and_encrypt_key(password=password, iv=iv, decrypt=False, data=one_asym_key)

    enc_key_info = rfc5958.EncryptedPrivateKeyInfo()
    enc_key_info["encryptionAlgorithm"] = enc_algo
    enc_key_info["encryptedData"] = univ.OctetString(enc_data)
    return enc_key_info


supported_keys = [
    b"X25519",
    b"X448",
    b"ED25519",
    b"ED448",
    b"RSA",
    b"EC",
]

CUSTOM_KEY_TYPES = [
    b"SNTRUP761",
    b"McEliece",
    b"SLH-DSA",
    b"COMPOSITE-SIG",
    b"COMPOSITE-KEM",
    b"FrodoKEM",
    b"XWING",
    b"ML-DSA",
    b"ML-KEM",
]


supported_keys += CUSTOM_KEY_TYPES


def _get_pem_header(key) -> bytes:
    """Get the name of the key type as an uppercase string using the class name.

    :param key: A private key instance.
    :return: The uppercase string identifier for the key type.

    """
    key_name = type(key).__name__
    key_map = {
        "RSAPrivateKey": "RSA",
        "EllipticCurvePrivateKey": "EC",
        "Ed25519PrivateKey": "ED25519",
        "Ed448PrivateKey": "ED448",
        "X25519PrivateKey": "X25519",
        "X448PrivateKey": "X448",
        "XWingPrivateKey": "XWING",
        "MLKEMPrivateKey": "ML-KEM",
        "MLDSAPrivateKey": "ML-DSA",
        "McEliecePrivateKey": "McEliece",
        "Sntrup761PrivateKey": "SNTRUP761",
    }
    if key_name in key_map:
        return key_map[key_name].encode("utf-8")
    raise ValueError(f"Unsupported key type: {key_name}")

@not_keyword
def load_enc_key(password: str, data: bytes) -> bytes:
    """Load PEM formatted encrypted key.

    :param password: Password for decryption.
    :param data: PEM encoded encrypted key.
    :return: The decrypted_key in DER-encoded `OneAsymmetricKey` bytes.
    """
    lines = data.split(b"\n")
    key_name_line = lines[0]
    if not key_name_line.startswith(b"-----BEGIN") or not key_name_line.endswith(b"PRIVATE KEY-----"):
        raise ValueError(f"Invalid PEM format found: {key_name_line}")

    key_name = key_name_line.replace(b"-----BEGIN ", b"").replace(b" PRIVATE KEY-----", b"").strip()

    if key_name not in supported_keys:
        raise ValueError(f"Unsupported key type: {key_name.decode('utf-8')}")

    dek_info_line = lines[2]
    if not dek_info_line.startswith(b"DEK-Info:"):
        raise ValueError("Missing DEK-Info header")

    _, dek_info = dek_info_line.split(b": ", 1)
    algo, iv_hex = dek_info.split(b",")
    if algo not in [b"AES-256-CBC", b"AES-196-CBC", b"AES-128-CBC"]:
        raise ValueError("Unsupported encryption algorithm")

    iv = bytes.fromhex(iv_hex.decode("utf-8"))
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long")
    enc_data = base64.b64decode(b"".join(lines[4:-2]))
    key_data, _ = derive_and_encrypt_key(password=password, data=enc_data, decrypt=True, iv=iv)

    return key_data


# TODO fix for all keys.
# missing are Chempat, sntrup761, McEliece, old-CompositeSig, CompositeKEM

@not_keyword
def parse_key_from_one_asym_key(data: bytes):
    """Parse and load a private key from its OneAsymmetricKey encoding.

    :param data: The OneAsymmetricKey encoded key data.
    :return: The parsed private key object.
    """
    obj, rest = decoder.decode(data, rfc5958.OneAsymmetricKey())
    if rest:
        raise ValueError("Found remainder after decoding `OneAsymmetricKey`.")

    alg_oid = str(obj["privateKeyAlgorithm"]["algorithm"])

    univ_oid = univ.ObjectIdentifier(alg_oid)

    public_bytes = obj["publicKey"].asOctets() if obj["publicKey"].isValue else None

    if univ_oid in CMS_COMPOSITE_OID_2_NAME:
        name = CMS_COMPOSITE_OID_2_NAME[univ_oid]
        obj, rest = decoder.decode(obj["privateKey"].asOctets(), asn1Spec=CompositeSignaturePrivateKeyAsn1())
        if rest:
            raise ValueError("Found remainder after decoding `CompositeSignaturePrivateKeyAsn1`.")

        # TODO fix if other algorithms are used for CompositeSig.

        pq_name = "-".join(name.split("-")[0:3])
        if public_bytes is not None:
            obj, rest = decoder.decode(public_bytes, asn1Spec=CompositeSignaturePrivateKeyAsn1())
            if rest:
                raise ValueError("Found remainder after decoding `CompositeSignaturePublicKey`.")

        obj[0]["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[pq_name]
        pq_key = parse_key_from_one_asym_key(data=encoder.encode(obj[0]))
        trad_key = serialization.load_der_private_key(encoder.encode(obj[1]), password=None)
        return CompositeSigCMSPrivateKey(pq_key=pq_key, trad_key=trad_key)

    if alg_oid in TRAD_STR_OID_TO_KEY_NAME:
        return serialization.load_der_private_key(data=data, password=None)

    if alg_oid == XWING_OID_STR:
        private_key = XWingPrivateKey.from_private_bytes(obj["privateKey"].asOctets())

    elif univ_oid in ML_DSA_OID_2_NAME:
        name = PQ_OID_2_NAME[univ_oid]
        private_key = MLDSAPrivateKey(sig_alg=name, private_bytes=obj["privateKey"].asOctets(), public_key=public_bytes)

    elif univ_oid in ML_KEM_OID_2_NAME:
        name = PQ_OID_2_NAME[univ_oid]
        private_key = MLKEMPrivateKey(
            kem_alg=name,
            private_bytes=obj["privateKey"].asOctets(),
            public_key=public_bytes,
        )

    elif alg_oid in MCELIECE_OID_2_NAME:
        name = PQ_OID_2_NAME[alg_oid]
        private_key = McEliecePrivateKey(
            kem_alg=name,
            private_bytes=obj["privateKey"].asOctets(),
            public_key=public_bytes,
        )

    elif univ_oid in SLH_DSA_OID_2_NAME:
        name = SLH_DSA_OID_2_NAME[univ_oid]
        private_key = SLHDSAPrivateKey(
            sig_alg=name, private_bytes=obj["privateKey"].asOctets(), public_key=public_bytes
        )

    elif alg_oid in FRODOKEM_OID_2_NAME:
        name = PQ_OID_2_NAME[alg_oid]
        private_key = FrodoKEMPrivateKey(
            kem_alg=name,
            private_bytes=obj["privateKey"].asOctets(),
            public_key=public_bytes,
        )
    elif alg_oid in id_sntrup761_str:
        private_key = Sntrup761PrivateKey(
            kem_alg="sntrup761", private_bytes=obj["privateKey"].asOctets(), public_key=public_bytes
        )

    else:
        oid = obj["privateKeyAlgorithm"]["algorithm"]

        raise NotImplementedError(f"Parsing for this key type is not implemented: {may_return_oid_to_name(oid=oid)}.")

    return private_key

@not_keyword
def derive_and_encrypt_key(password: str, data: bytes, decrypt: bool, iv: Optional[bytes] = None) -> (bytes, bytes):
    """Derive an encryption key using PBKDF2 and encrypts data using AES-CBC.

    :param password: Password to derive the encryption key.
    :param data: Data to encrypt.
    :param decrypt: Whether to decrypt or encrypt the data.
    :param iv: Optional initialization vector (IV). If None, a random IV is generated.
    :return: Tuple of (enc_data, iv).
    """
    if iv is None and decrypt:
        raise ValueError("For decryption must a `iv` be parsed.")

    elif iv is None:
        iv = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        iterations=100_000,
    )
    enc_key = kdf.derive(password.encode("utf-8"))

    enc_data = compute_aes_cbc(key=enc_key, data=data, iv=iv, decrypt=decrypt)

    return enc_data, iv
