# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Functions and classes for cryptographic operations.

Provided primitives are: key generation, signing data, computing hashes, generating Certificate Signing Requests (CSRs),
signing CSRs, performing Diffie-Hellman (DH) key exchanges, and generating x509 certificates. The module leverages the
`cryptography` library to support various cryptographic primitives including RSA,
Elliptic Curve (EC), Ed25519, Ed448, DSA, and DH key types. Additionally, it offers functions for
hash-based message authentication codes (HMAC), Galois Message Authentication Codes (GMAC),
and password-based key derivation (PBKDF2).
"""

import logging
import os
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey
from pyasn1_alt_modules import rfc8018, rfc9480, rfc9481
from robot.api.deco import not_keyword

from resources import convertutils, keyutils, oid_mapping
from resources.oid_mapping import compute_hash, get_hash_from_oid, hash_name_to_instance
from resources.typingutils import ECDHPrivKeyTypes, ECDHPubKeyTypes, PrivateKeySig, PublicKeySig


# TODO fix doc
def sign_data(  # noqa D417 undocumented-param
    data: bytes,
    key: PrivateKeySig,
    hash_alg: Union[str, None, hashes.HashAlgorithm] = None,
    use_rsa_pss: bool = False,
) -> bytes:
    """Sign `data` with a private key, using a specified hashing algorithm. Supports ECDSA, ED448, ED25519, RSA, DSA.

    Arguments:
    ---------
        - `data`: The data to be signed.
        - `key`: The private key object used to sign the data.
        - `hash_alg`: Hash algorithm for signing (e.g., "sha256"). If not given, use default algorithm for the key type.

    Key Types and Signing:
        - `EllipticCurvePrivateKey`: ECDSA
        - `RSAPrivateKey`: RSA with PKCS1v15 padding
        - `Ed25519PrivateKey` and `Ed448PrivateKey`: No hashing algorithm needs to be provided
        - `DSAPrivateKey`: DSA

    Returns:
    -------
        - The signed data as a byte sequence.

    Raises:
    ------
        - `ValueError` if an unsupported key type is provided or if the required hash algorithm is not specified.

    Example:
    -------
    | Sign Data | ${data} | ${private_key} | sha256 |

    """
    if isinstance(hash_alg, hashes.HashAlgorithm):
        pass
    elif hash_alg is not None:
        hash_alg = hash_name_to_instance(hash_alg)  # type: ignore

    if isinstance(key, CompositeSigCMSPrivateKey):
        return key.sign(data=data, use_pss=use_rsa_pss)

    if isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            dsa.DSAPrivateKey,
        ),
    ):
        return _sign_traditional_key(data, key, hash_alg, use_rsa_pss)
    if isinstance(key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
        raise ValueError(f"Key type '{type(key).__name__}' is not used for signing. It is used for key exchange.")

    if isinstance(key, PQSignaturePrivateKey):
        # TODO maybe think about a better solution.
        hash_alg = key.check_hash_alg(hash_alg)
        return key.sign(data, hash_alg=hash_alg)

    raise ValueError(f"Unsupported private key type: {type(key).__name__}.")


def _sign_traditional_key(
    data: bytes,
    key: Union[
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
        dsa.DSAPrivateKey,
    ],
    hash_alg: Optional[hashes.HashAlgorithm],
    use_pss: bool,
) -> bytes:
    """Sign data using a standalone private key."""
    if isinstance(key, rsa.RSAPrivateKey):
        if use_pss:
            return sign_data_rsa_pss(key, data, hash_alg)
        return key.sign(data, padding.PKCS1v15(), hash_alg)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hash_alg))
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(data)
    if isinstance(key, ed448.Ed448PrivateKey):
        return key.sign(data)
    if isinstance(key, dsa.DSAPrivateKey):
        if not hash_alg:
            raise ValueError("DSA signatures require a hash algorithm.")
        return key.sign(data, hash_alg)

    raise ValueError(f"Unsupported standalone key type: {type(key).__name__}.")


@not_keyword
def sign_data_rsa_pss(
    private_key: rsa.RSAPrivateKey, data: bytes, hash_alg: Optional[str] = None, salt_length: Optional[int] = None
):
    """Sigs data using RSASSA-PSS with the specified hash algorithm and salt length.

    :param private_key: The RSA private key used for signing.
    :param data: The data to be signed.
    :param hash_alg: The name of the hash algorithm. Defaults to 'sha256'.
    :param salt_length: The length of the salt. Defaults to None.
    :return: The signature as a byte string.
    :raises ValueError: If the hash algorithm name is not supported.
    """
    if hash_alg is None:
        hash_alg = "sha256"

    hash_algorithm = hash_name_to_instance(hash_alg)
    pss_padding = padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=salt_length or hash_algorithm.digest_size)
    return private_key.sign(data=data, padding=pss_padding, algorithm=hash_algorithm)


@not_keyword
def compute_hmac(data: bytes, key: bytes, hash_alg: str = "sha256") -> bytes:
    """Compute HMAC for the given data using specified key.

    :param data: The data to be hashed.
    :param key: The key to use for the HMAC.
    :param hash_alg: The hash algorithm name to use. Defaults to "sha256".
    :return: The HMAC signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if isinstance(key, str):
        key = key.encode("utf-8")

    h = hmac.HMAC(key, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
    logging.info("HMAC Result: %s", signature.hex())
    return signature


@not_keyword
def compute_gmac(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Compute the AES-GMAC (Galois Message Authentication Code) for given data.

    :param key: The encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
    :param iv: Initialization vector (must be 12 bytes for GCM mode)
    :param data: Data to authenticate
    :return: The computed MAC (authentication tag)
    """
    aes_gcm = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

    # Authenticate data and return the authentication tag
    aes_gcm.authenticate_additional_data(data)
    aes_gcm.finalize()
    return aes_gcm.tag


# TODO maybe remove or change import


@not_keyword
def compute_kmac_from_alg_id(
    alg_id: rfc9480.AlgorithmIdentifier, data: bytes, key: bytes, ignore_params_check: bool = False
) -> bytes:
    """Compute KMAC for the given data using specified key and shake function.

    :param alg_id: The AlgorithmIdentifier specifying the KMAC algorithm.
    :param data: The data to be hashed.
    :param key: The key to use for the KMAC.
    :param ignore_params_check: If True, the check for the `parameters` field is ignored. Defaults to `False`.
    (**MUST** be absent for KMAC)
    :return: The KMAC signature
    :raises ValueError: If the algorithm identifier is not allowed or the `parameters` are not absent.
    """
    try:
        from Crypto.Hash import KMAC128, KMAC256  # pylint: disable=import-outside-toplevel
    except ImportError:
        raise ValueError("The 'Cryptodome' library is required for KMAC calculations.")  # pylint: disable=raise-missing-from

    if alg_id["parameters"].isValue and not ignore_params_check:
        raise ValueError("For `KMAC` the `parameters` field must be absent!")

    if alg_id["algorithm"] == rfc9481.id_KMACWithSHAKE128:
        kmac = KMAC128.new(data=data, custom=b"", mac_len=32, key=key)
        digest = kmac.digest()

    elif alg_id["algorithm"] == rfc9481.id_KMACWithSHAKE256:
        kmac = KMAC256.new(data=data, custom=b"", mac_len=64, key=key)
        digest = kmac.digest()

    else:
        raise ValueError("Unsupported algorithm identifier")

    logging.info("KMAC Result: %s", digest.hex())
    return digest


@not_keyword
def compute_pbkdf2_from_parameter(parameters: rfc8018.PBKDF2_params, key: bytes) -> bytes:
    """Compute the derived key using PBKDF2 based on the provided parameters.

    :param parameters: PBKDF2 parameters object from RFC8018
    :param key: The password or key to use in the derivation process
    :return: The derived key as bytes
    """
    salt = parameters["salt"]["specified"].asOctets()
    iterations = int(parameters["iterationCount"])
    key_length = int(parameters["keyLength"])
    prf_algorithm = parameters["prf"]["algorithm"]

    alg_name = get_hash_from_oid(prf_algorithm, only_hash=True)
    hash_alg_instance = hash_name_to_instance(alg_name)

    kdf = PBKDF2HMAC(
        algorithm=hash_alg_instance,
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(key)
    logging.info("Derived key: %s", derived_key)
    return derived_key


@not_keyword
def compute_pbmac1(
    data: bytes,
    key: Union[str, bytes],
    iterations: int = 262144,
    salt: bytes = None,
    length: int = 32,
    hash_alg: str = "sha256",
):
    """Compute HMAC for the given data using specified key.

    :param length: Output length of PBKDF2.
    :param iterations: Number of iterations for PBKDF2
    :param data: Data to be hashed.
    :param key: Key to use for the HMAC.
    :param salt: Salt value for PBKDF2.
    :param hash_alg: Optional name of the hash algorithm to use.

    :returns: bytes, the HMAC signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if isinstance(key, str):
        key = key.encode("utf-8")

    salt = salt or os.urandom(16)

    # step 1, derive key
    kdf = PBKDF2HMAC(
        algorithm=hash_alg_instance,
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(key)
    logging.info("Derived key: %s", derived_key.hex())

    signature = compute_hmac(key=derived_key, hash_alg=hash_alg, data=data)
    logging.info("Signature: %s", signature.hex())
    return signature


@not_keyword
def compute_password_based_mac(
    data: bytes, key: bytes, iterations: int = 1000, salt: bytes = None, hash_alg: str = "sha256"
):
    """Implement the password-based MAC algorithm defined in RFC 4210 Sec. 5.1.3.1. The MAC is always HMAC_hash_alg.

    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param iterations: optional int, the number of times to do the hash iterations
    :param salt: optional bytes, salt to use; if not given, a random 16-byte salt will be generated
    :param hash_alg: optional str, name of the hash algorithm to use, e.g., 'sha256'

    :returns: bytes, the HMAC signature
    """
    salt = salt or os.urandom(16)

    if isinstance(key, str):
        key = key.encode("utf-8")

    initial_input = key + salt
    for _ in range(iterations):
        initial_input = compute_hash(hash_alg, initial_input)

    signature = compute_hmac(data=data, key=initial_input, hash_alg=hash_alg)
    logging.info("Signature: %s", signature.hex())
    return signature


def _generate_private_dh_from_key(password: bytes, peer_key: Union[dh.DHPrivateKey, dh.DHPublicKey]) -> dh.DHPrivateKey:
    """Generate a `cryptography.hazmat.primitives.asymmetric.dh DHPrivateKey` based on the password.

    :param password: bytes password which one of the parties uses as secret DH-Key.
    :param peer_key: `cryptography.hazmat.primitives.asymmetric.dh DHPrivateKey or DHPublicKey
    :return: `cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey` object
    """
    parameters = peer_key.parameters().parameter_numbers()

    private_key: dh.DHPrivateKey = keyutils.generate_key(
        algorithm="dh",
        p=parameters.p,
        g=parameters.g,
        secret_scalar=int.from_bytes(password, byteorder="big"),
    )  # type: ignore
    return private_key


def do_dh_key_exchange_password_based(  # noqa: D417
    password: Union[str, bytes], peer_key: Union[dh.DHPrivateKey, dh.DHPublicKey]
) -> bytes:
    """Perform a Diffie-Hellman key exchange to derive a shared secret key based on a password.

    Arguments:
    ---------
    - `password`: A string or bytes used to derive the DH private key for the server or local party.
    - `peer_key`: A `cryptography` `dh.DHPrivateKey` or `dh.DHPublicKey` object representing the other party's key.

    Returns:
    -------
    - `bytes`: Shared secret key derived from the Diffie-Hellman key exchange.

    Example:
    -------
    | ${shared_secret} = | Do DH Key Exchange Password Based | password=my_password | peer_key=${public_key} |

    """
    secret = convertutils.str_to_bytes(password)
    private_key = _generate_private_dh_from_key(secret, peer_key)

    if isinstance(peer_key, dh.DHPublicKey):
        shared_key = private_key.exchange(peer_key)
    else:
        other_public_key = private_key.public_key()
        shared_key = private_key.exchange(other_public_key)
    logging.info("DH shared secret: %s", shared_key.hex())
    return shared_key


@not_keyword
def compute_dh_based_mac(
    data: bytes, password: Union[str, dh.DHPublicKey], key: dh.DHPrivateKey, hash_alg: str = "sha1"
) -> bytes:
    """Compute a Message Authentication Code (MAC) using a Diffie-Hellman (DH) based shared secret.

    :param data: The input data to be authenticated, given as a byte sequence.
    :param password: A string used to generate the server's secret key or a provided public key.
    :param key: A `cryptography.dh.DHPrivateKey` object, which represents the client's secret.
    :param hash_alg: Name of the hash algorithm for key derivation and HMAC computation. Defaults to "sha1".
    :return: The computed HMAC of the input data using the derived key.
    """
    if isinstance(password, str):
        shared_key = do_dh_key_exchange_password_based(password=password, peer_key=key)
    else:
        shared_key = key.exchange(password)

    key = compute_hash(data=shared_key, alg_name=hash_alg)  # type: ignore
    return compute_hmac(data=data, key=key, hash_alg=hash_alg)


@not_keyword
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


@not_keyword
def perform_ecdh(private_key: ECDHPrivKeyTypes, public_key: ECDHPubKeyTypes) -> bytes:
    """Derive a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key exchange.

    Supports `ec`, `x25519`, and `x448` curves.

    :param private_key: The private key for generating the shared secret.
    :param public_key: The public key to perform the exchange with.
    :return: The derived shared secret as bytes.
    :raises ValueError: If `public_key` or `private_key` are not compatible.
    """
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(public_key, ec.EllipticCurvePublicKey):
        return private_key.exchange(ec.ECDH(), public_key)

    if isinstance(private_key, x25519.X25519PrivateKey) and isinstance(public_key, x25519.X25519PublicKey):
        return private_key.exchange(public_key)

    if isinstance(private_key, x448.X448PrivateKey) and isinstance(public_key, x448.X448PublicKey):
        return private_key.exchange(public_key)

    raise ValueError(
        f"Incompatible key types for ECDH key exchange: "
        f"private_key is {type(private_key).__name__}, "
        f"public_key is {type(public_key).__name__}"
    )


@not_keyword
def compute_ansi_x9_63_kdf(
    shared_secret: bytes,
    key_length: int,
    other_info: bytes,
    hash_alg: str = "sha256",
    use_version_2: bool = True,
) -> bytes:
    """Generate keying material using the ANSI X9.63 KDF.

    KDF2: K(i) = Hash (Z || D || otherInfo)
    KDF3: K(i) = Hash (D || Z || otherInfo)

    :param shared_secret: Shared secret from ECDH or KEM, as bytes.
    :param key_length: Desired length of the KEK in bytes.
    :param other_info: The other info field as bytes.
    :param hash_alg: Hash algorithm to use. Defaults to "sha256".
    :param use_version_2: Whether to use version 2 or 3 of the KDF. Defaults to True.
    :return: Derived ContentEncryptionKey as bytes.
    """
    hash_algorithm = hash_name_to_instance(hash_alg)
    hasher = hashes.Hash(hash_algorithm)
    counter = 1
    keying_material = b""

    while len(keying_material) < key_length:
        counter_bytes = counter.to_bytes(4, byteorder="big")

        if use_version_2:
            hasher.update(shared_secret + counter_bytes + other_info)
        else:
            hasher.update(counter_bytes + shared_secret + other_info)

        keying_material += hasher.finalize()
        hasher = hashes.Hash(hash_algorithm)
        counter += 1

    return keying_material[:key_length]


def compute_hkdf(hash_alg: str, key_material: bytes, ukm: Optional[bytes] = None, length: int = 32) -> bytes:
    """Compute the HKDF output for the given hash algorithm, key material, and optional user key material (UKM).

    :param hash_alg: The hash algorithm name to use for HKDF (e.g.,"sha256").
    :param key_material: The input key material (IKM) used for key derivation.
    :param ukm: Optional user key material (salt) for HKDF. Defaults to None.
    :param length: The desired length of the output key in bytes. Defaults to 32 bytes.
    :return: The derived key as bytes.
    """
    hash_instance = hash_name_to_instance(hash_alg)
    hkdf = HKDF(
        algorithm=hash_instance,
        length=length,
        salt=ukm,
        info=None,  # as specified.
    )
    return hkdf.derive(key_material)


def verify_signature(  # noqa D417 undocumented-param
    public_key: PublicKeySig,
    signature: bytes,
    data: bytes,
    hash_alg: Optional[Union[str, hashes.HashAlgorithm]] = None,
) -> None:
    """Verify a digital signature using the provided public key, data and hash algorithm.

    Supports: (ECDSA, ED448, ED25519, RSA, DSA).

    Arguments:
    ---------
        - `public_key`: The public key used to verify the signature.
        - `signature`: signature data.
        - `data`: The original data that was signed.
        - `hash_alg`: Name of the hash algorithm used for verification (e.g., "sha256"). If not specified, the default
                      algorithm for the given key type is used.

    Key Types and Verification:
        - `RSAPublicKey`: Verifies using PKCS1v15 padding and the provided hash algorithm.
        - `EllipticCurvePublicKey`: Verifies using ECDSA with the provided hash algorithm.
        - `Ed25519PublicKey` and `Ed448PublicKey`: Verifies without a hash algorithm.
        - `DSAPublicKey`: Verifies using the provided hash algorithm.
        - Unsupported key types (e.g., `X25519PublicKey`, `X448PublicKey`): Raises an error.

    Raises:
    ------
        - `InvalidSignature`: If the signature is invalid.
        - `ValueError`: If an unsupported key type is provided.

    Examples:
    --------
    | Verify Signature | ${public_key} | ${signature} | ${data} | sha256 |
    | Verify Signature | ${public_key} | ${signature} | ${data} |

    """
    if isinstance(hash_alg, hashes.HashAlgorithm):
        pass
    elif hash_alg is not None:
        hash_alg = oid_mapping.hash_name_to_instance(hash_alg)

    # isinstance(ed448.Ed448PrivateKey.generate(), EllipticCurvePrivateKey) → False
    # so can check in this Order.
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding=padding.PKCS1v15(), algorithm=hash_alg)  # type: ignore
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_alg))  # type: ignore
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, data)
    elif isinstance(public_key, ed448.Ed448PublicKey):
        public_key.verify(signature, data)  # type: ignore
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, data, hash_alg)  # type: ignore
    elif isinstance(public_key, (x25519.X25519PublicKey, x448.X448PublicKey)):
        raise ValueError(
            f"Key type '{type(public_key).__name__}' is not used for signing or verifying signatures."
            f"It is used for key exchange."
        )

    elif isinstance(public_key, PQSignaturePublicKey):
        # TODO maybe think about a better solution.
        hash_alg = public_key.check_hash_alg(hash_alg)
        public_key.verify(data=data, hash_alg=hash_alg, signature=signature)

    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")
