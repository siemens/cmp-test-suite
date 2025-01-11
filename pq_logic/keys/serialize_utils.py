# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for serializing keys."""

import base64
import os
import textwrap
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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


def prepare_enc_key_pem(password: str, one_asym_key: bytes, key_name: bytes) -> bytes:
    """Prepare PEM formatted encrypted key.

    :param password: Password for encryption.
    :param one_asym_key: Key to encrypt.
    :param key_name: Name of the key.
    :return: PEM formatted encrypted key.
    """
    enc_data, iv = derive_and_encrypt_key(password=password, data=one_asym_key, decrypt=False)

    dek_info = f"DEK-Info: AES-256-CBC,{iv.hex().upper()}\n\n".encode("utf-8")
    b64_encoded = base64.b64encode(enc_data).decode("utf-8")
    b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64)).encode("utf-8")

    pem_data = (
        b"-----BEGIN "
        + key_name
        + b" PRIVATE KEY-----\n"
        + b"Proc-Type: 4,ENCRYPTED\n"
        + dek_info
        + b64_encoded
        + b"\n-----END "
        + key_name
        + b" PRIVATE KEY-----\n"
    )

    return pem_data
