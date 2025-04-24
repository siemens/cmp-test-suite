"""Utility functions for FIPS compliance."""
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives import hashes

def _compute_hash(algorithm: str, data: bytes) -> bytes:
    """Compute hash of the input data."""
    if algorithm == 'sha256':
        hasher = hashes.Hash(hashes.SHA256())

    elif algorithm == 'sha512':
        hasher = hashes.Hash(hashes.SHA512())

    elif algorithm  == 'sha3_256':
        hasher = hashes.Hash(hashes.SHA3_256())

    elif algorithm == 'sha3_512':
        hasher = hashes.Hash(hashes.SHA3_512())

    elif algorithm == 'shake128':
        hasher = hashes.Hash(hashes.SHAKE128(32))

    elif algorithm == 'shake256':
        hasher = hashes.Hash(hashes.SHAKE256(64))

    else:
        raise ValueError(f"Unsupported algorithm got: {algorithm}")

    hasher.update(data)
    return hasher.finalize()

def _compute_shake(algorithm: str, data: bytes, length: int) -> bytes:
    """Compute SHAKE128 or SHAKE256 hash of the input data."""
    if algorithm not in ['shake128', 'shake256']:
        raise ValueError("Unsupported algorithm. Use 'shake128' or 'shake256'.")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes.")
    if length < 0:
        raise ValueError("Length must be non-negative integer.")
    if algorithm == 'shake128':
        hasher = hashes.Hash(hashes.SHAKE128(length))
    else:
        hasher = hashes.Hash(hashes.SHAKE256(length))
    hasher.update(data)
    return hasher.finalize()

class XOFHash:
    """XOF hash object for SHAKE128 and SHAKE256."""
    _hasher: hashes.Hash
    def __init__(self, algorithm: str, digest_length: int = 1000000):
        """Initialize the XOF hash object."""
        # because inside the `cmputils` is the maxsize increased, which will
        # create an overflow error, so we need to change the default value to 1000000
        # or a smaller value.
        if algorithm not in ['shake128', 'shake256']:
            raise ValueError("Unsupported algorithm. Use 'shake128' or 'shake256'.")
        self.algorithm = algorithm
        self._output_buffer = bytearray()
        self._squeezed_length = 0
        self._finalized = False
        self._initialize_hasher(digest_length)

    def _initialize_hasher(self, digest_length: int):
        if self.algorithm == 'shake128':
            self._hasher = hashes.Hash(hashes.SHAKE128(digest_length))
        elif self.algorithm == 'shake256':
            self._hasher = hashes.Hash(hashes.SHAKE256(digest_length))

    def update(self, data: bytes):
        """Update the XOF hash with the input data."""
        if self._finalized:
            raise ValueError("Cannot update after squeezing.")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes.")
        self._hasher.update(data)

    def _finalize(self, extra_bytes: int):
        """Finalize and store extra squeezed bytes if needed."""
        if not self._finalized:
            # Finalize hash function and squeeze a large buffer
            squeezed = self._hasher.finalize()
            self._output_buffer.extend(squeezed)
            self._finalized = True
        # Extend output buffer if more bytes requested than we already have
        if len(self._output_buffer) < self._squeezed_length + extra_bytes:
            # SHAKE allows you to squeeze as many as needed
            needed = (self._squeezed_length + extra_bytes) - len(self._output_buffer)
            # Use the same hasher again to get more bytes
            # Unfortunately, cryptography doesn't allow true incremental squeeze,
            # so we need to restart hash and squeeze up to desired length
            raise RuntimeError("cryptography backend doesn't allow further incremental squeezing."
                               f"Need to restart the hasher: {needed} bytes needed.")

    def squeeze(self, length: int) -> bytearray:
        """Squeeze the XOF hash and return the specified number of bytes.

        `.update` cannot be called after this method.
        """
        if length < 0:
            raise ValueError("Length must be non-negative integer.")
        self._finalize(length)
        result = self._output_buffer[self._squeezed_length:self._squeezed_length + length]
        self._squeezed_length += length
        return result

    def read(self, length: int):
        """Alias for squeeze."""
        return self.squeeze(length)
