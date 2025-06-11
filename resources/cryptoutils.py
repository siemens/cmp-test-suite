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
import math
import os
from typing import Optional, Tuple, Union

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc8018, rfc9480, rfc9481
from pyasn1_alt_modules.rfc5084 import GCMParameters
from robot.api.deco import not_keyword
from tinyec import registry
from tinyec.ec import Inf, Point

from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pq_logic.keys.abstract_wrapper_keys import AbstractHybridRawPublicKey, KEMPrivateKey, KEMPublicKey
from pq_logic.keys.composite_kem05 import CompositeKEMPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.trad_kem_keys import RSADecapKey, RSAEncapKey
from resources import convertutils, envdatautils, keyutils, oid_mapping
from resources.asn1_structures import KemCiphertextInfoAsn1
from resources.data_objects import FixedSHAKE128, FixedSHAKE256
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyCombination
from resources.oid_mapping import compute_hash, get_hash_from_oid, hash_name_to_instance
from resources.oidutils import AES_CBC_OID_2_NAME, AES_GCM_OID_2_NAME, CURVE_2_COFACTORS, KM_KW_ALG
from resources.typingutils import ECDHPrivateKey, ECDHPublicKey, SignKey, VerifyKey


def sign_data(  # noqa D417 undocumented-param
    data: bytes,
    key: SignKey,
    hash_alg: Union[str, None, hashes.HashAlgorithm] = None,
    use_rsa_pss: bool = False,
    ctx: Union[bytes, str] = b"",
    *,
    use_pre_hash: bool = False,
) -> bytes:
    """Sign `data` with a private key, using a specified hashing algorithm. Supports ECDSA, ED448, ED25519, RSA, DSA.

    Arguments:
    ---------
        - `data`: The data to be signed.
        - `key`: The private key object used to sign the data.
        - `hash_alg`: Hash algorithm for signing (e.g., "sha256"). If not given, use default algorithm for the key type.
        - `use_rsa_pss`: Whether to use RSA-PSS padding for RSA keys. Defaults to `False`.
        - `ctx`: Context data for the signature. Defaults to an empty byte sequence.
        (If a string begins with "0x", it will be interpreted as a hex.)
        - `use_pre_hash`: Whether to use the pre-hash version for the composite key. Defaults to `False`.

    Returns:
    -------
        - The computed signature as bytes.

    Raises:
    ------
        - `ValueError` if an unsupported key type is provided or if the required hash algorithm is not specified.

    Examples:
    --------
    | ${sig}= | Sign Data | ${data} | ${private_key} | sha256 |
    | ${sig}= | Sign Data | ${data} | ${private_key} | sha256 | use_rsa_pss=True |
    | ${sig}= | Sign Data | ${data} | ${private_key} | sha256 | use_rsa_pss=True | ctx=0x1234 |

    """
    ctx = convertutils.str_to_bytes(ctx)

    if isinstance(hash_alg, hashes.HashAlgorithm):
        pass
    elif hash_alg is not None:
        hash_alg = hash_name_to_instance(hash_alg)  # type: ignore

    if isinstance(key, CompositeSig03PrivateKey):
        return key.sign(data=data, use_pss=use_rsa_pss, ctx=ctx, pre_hash=use_pre_hash)  # type: ignore

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

    if isinstance(key, PQHashStatefulSigPrivateKey):
        return key.sign(data)

    if isinstance(key, PQSignaturePrivateKey):
        # TODO maybe think about a better solution.
        hash_alg = key.check_hash_alg(hash_alg)
        return key.sign(data, hash_alg=hash_alg, ctx=ctx)

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
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.sign(data)

    if not hash_alg:
        raise ValueError(f"The {type(key).__name__} requires a hash algorithm.")

    if isinstance(key, rsa.RSAPrivateKey):
        if use_pss:
            return sign_data_rsa_pss(key, data, hash_alg.name.lower())
        return key.sign(data, padding.PKCS1v15(), hash_alg)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hash_alg))
    if isinstance(key, dsa.DSAPrivateKey):
        return key.sign(data, hash_alg)

    raise ValueError(f"Unsupported standalone key type: {type(key).__name__}.")


@not_keyword
def sign_data_rsa_pss(
    private_key: rsa.RSAPrivateKey,
    data: bytes,
    hash_alg: Optional[str] = None,
    salt_length: Optional[int] = None,
    second_hash_alg: Optional[str] = None,
) -> bytes:
    """Sign data using RSASSA-PSS with the specified hash algorithm and salt length.

    :param private_key: The RSA private key used for signing.
    :param data: The data to be signed.
    :param hash_alg: The name of the hash algorithm to use for PSS-Padding. Defaults to 'sha256'.
    :param salt_length: The length of the salt. Defaults to None.
    :param second_hash_alg: The name of the hash algorithm to use for the signature. Defaults to `None`.
    :return: The signature as a byte string.
    :raises ValueError: If the hash algorithm name is not supported.
    """
    if hash_alg in ["shake128", "shake256"]:
        return _sign_data_rsa_pss_shake(private_key, data, hash_alg, salt_length)

    hash_alg = "sha256" if hash_alg is None else hash_alg
    hash_algorithm = hash_name_to_instance(hash_alg)
    second_hash_algorithm = hash_name_to_instance(second_hash_alg) if second_hash_alg else hash_algorithm
    pss_padding = padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=salt_length or hash_algorithm.digest_size)
    return private_key.sign(data=data, padding=pss_padding, algorithm=second_hash_algorithm)


def _sign_data_rsa_pss_shake(
    private_key: rsa.RSAPrivateKey,
    data: bytes,
    hash_alg: Optional[str] = None,
    salt_length: Optional[int] = None,
) -> bytes:
    """Sign data using RSASSA-PSS with the specified hash algorithm and salt length.

    :param private_key: The RSA private key used for signing.
    :param data: The data to be signed.
    :param hash_alg: The name of the hash algorithm to use for PSS-Padding. Defaults to 'sha256'.
    :param salt_length: The length of the salt. Defaults to None.
    :return: The signature as a byte string.
    :raises ValueError: If the hash algorithm name is not supported.
    """
    if hash_alg is None:
        hash_alg = "shake256"

    if hash_alg not in ["shake128", "shake256"]:
        raise ValueError(f"Unsupported hash algorithm: {hash_alg}. Only 'shake128' and 'shake256' are supported.")

    if hash_alg == "shake128":
        hash_for_signing = FixedSHAKE128.new(data)
    else:
        hash_for_signing = FixedSHAKE256.new(data)

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    if salt_length is None:
        salt_length = hash_for_signing.digest_size

    pycrypto_key = RSA.import_key(pem_data)
    signer = pss.new(pycrypto_key, salt_bytes=salt_length)
    signature = signer.sign(hash_for_signing)  # type: ignore
    logging.info("RSA-PSS-%s Signature: %s", hash_alg, signature.hex())
    return signature


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
    if alg_id["parameters"].isValue and not ignore_params_check:
        raise ValueError("For `KMAC` the `parameters` field must be absent!")

    if alg_id["algorithm"] == rfc9481.id_KMACWithSHAKE128:
        hash_alg = "shake128"

    elif alg_id["algorithm"] == rfc9481.id_KMACWithSHAKE256:
        hash_alg = "shake256"
    else:
        raise ValueError("Unsupported algorithm identifier")

    digest = compute_kmac(hash_alg=hash_alg, key=key, data=data)
    return digest


@not_keyword
def compute_kmac(hash_alg: str, key: bytes, data: bytes) -> bytes:
    """Compute KMAC for the given data using specified key and shake function.

    :param hash_alg: The hash algorithm name to use. Defaults to "sha256".
    :param key: The key to use for the KMAC.
    :param data: The data to be hashed.
    :return: The KMAC signature
    """
    try:
        from Crypto.Hash import KMAC128, KMAC256  # pylint: disable=import-outside-toplevel
    except ImportError:
        raise ValueError("The 'Cryptodome' library is required for KMAC calculations.")  # pylint: disable=raise-missing-from

    if hash_alg == "shake128":
        kmac = KMAC128.new(data=data, custom=b"", mac_len=32, key=key)
        digest = kmac.digest()
    elif hash_alg == "shake256":
        kmac = KMAC256.new(data=data, custom=b"", mac_len=64, key=key)
        digest = kmac.digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_alg}. Only 'shake128' and 'shake256' are supported.")

    logging.info("KMAC-%s Result: %s", hash_alg, digest.hex())
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

    if alg_name is None:
        raise BadAlg(f"Unsupported hash algorithm: {prf_algorithm}")

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
    salt: Optional[bytes] = None,
    length: int = 32,
    hash_alg: str = "sha256",
    *,
    mac_hash_alg: Optional[str] = None,
) -> bytes:
    """Compute HMAC for the given data using specified key.

    :param length: Output length of PBKDF2.
    :param iterations: Number of iterations for PBKDF2
    :param data: Data to be hashed.
    :param key: Key to use for the HMAC.
    :param salt: Salt value for PBKDF2.
    :param hash_alg: Optional name of the hash algorithm to use.
    :param mac_hash_alg: Optional name of the hash algorithm to use for the `HMAC` algorithm.
    Defaults to the same as `hash_alg`.
    :return: The HMAC signature.
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

    signature = compute_hmac(key=derived_key, hash_alg=mac_hash_alg or hash_alg, data=data)
    logging.info("Signature: %s", signature.hex())
    return signature


@not_keyword
def compute_password_based_mac(
    data: bytes,
    key: bytes,
    iterations: int = 1000,
    salt: Optional[bytes] = None,
    hash_alg: str = "sha256",
    *,
    mac_hash_alg: Optional[str] = None,
):
    """Implement the password-based MAC algorithm defined in RFC 4210 Sec. 5.1.3.1. The MAC is always HMAC_hash_alg.

    :param data: The data to be hashed.
    :param key: The key to use for the HMAC.
    :param iterations: The number of times to do the hash iterations
    :param salt: The salt to use; if not given, a random 16-byte salt will be generated
    :param hash_alg: The name of the hash algorithm to use, e.g., 'sha256'
    :param mac_hash_alg: The name of the hash algorithm to use for the `HMAC` algorithm.
    Defaults to the same as `hash_alg`.
    :returns: The HMAC signature
    """
    salt = salt or os.urandom(16)

    if isinstance(key, str):
        key = key.encode("utf-8")

    initial_input = key + salt
    for _ in range(iterations):
        initial_input = compute_hash(hash_alg, initial_input)

    signature = compute_hmac(data=data, key=initial_input, hash_alg=mac_hash_alg or hash_alg)
    logging.info("Signature: %s", signature.hex())
    return signature


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


def _compute_ss_plus_cofactor(
    private_key: ec.EllipticCurvePrivateKey, public_key: ec.EllipticCurvePublicKey, cofactor: int
) -> bytes:
    """Compute shared secret plus cofactor.

    :param private_key: The private key to use for the computation.
    :param public_key: The public key to use for the computation.
    :param cofactor: The cofactor to multiply with
    :return: The computed shared secret plus cofactor as bytes
    :raises ValueError: If the private and public keys are not on the same curve.
    """
    if private_key.curve.name != public_key.curve.name:
        raise ValueError(
            "Private and public keys are not compatible. "
            f"Given keys are not on the same curve. "
            f"Got: {private_key.curve.name} and {public_key.curve.name}"
        )

    alice_private_key = private_key.private_numbers().private_value
    bob_public_key = convert_public_key_to_tinyec(public_key)
    tmp_point = alice_private_key * bob_public_key
    if isinstance(tmp_point, Inf):
        raise ValueError("Computed point is at infinity. Invalid key agreement.")

    ss_with_cofactor = cofactor * tmp_point  # type: ignore
    if isinstance(ss_with_cofactor, Inf):
        raise ValueError("Computed point is at infinity. Invalid key agreement.")

    ss_with_cofactor: Point

    x = ss_with_cofactor.x
    # Convert the shared secret to bytes
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")


@not_keyword
def perform_ecdh(
    private_key: ECDHPrivateKey,
    public_key: Union[ECDHPublicKey, rfc9480.CMPCertificate],
    use_cofactor: bool = False,
) -> bytes:
    """Derive a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key exchange.

    Supports `ec`, `x25519`, and `x448` curves.

    :param private_key: The private key for generating the shared secret.
    :param public_key: The public key to perform the exchange with.
    :param use_cofactor: If True, the cofactor is used for the key exchange. The computation is done using the
    cofactor of the curve Z = h * (alice's private key) * (bob's public key). Defaults to `False`.
    :return: The derived shared secret as bytes.
    :raises ValueError: If `public_key` or `private_key` are not compatible.
    """
    if isinstance(public_key, rfc9480.CMPCertificate):
        public_key = keyutils.load_public_key_from_spki(  # type: ignore
            public_key["tbsCertificate"]["subjectPublicKeyInfo"]
        )

        if not isinstance(public_key, ECDHPublicKey):
            raise ValueError("Invalid public key type for ECDH key exchange")

    if use_cofactor and isinstance(private_key, (X25519PrivateKey, X448PrivateKey)):
        raise NotImplementedError("Cofactor multiplication is not supported for X25519 and X448 keys.")

    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(public_key, ec.EllipticCurvePublicKey):
        if use_cofactor:
            # Use the cofactor for the key exchange
            curve = private_key.curve
            cofactor = CURVE_2_COFACTORS.get(curve.name)
            if cofactor is None:
                raise ValueError(f"Unsupported curve for cofactor: {curve.name}. Please check: `CURVE_2_COFACTORS`.")

            if cofactor == 1:
                logging.debug("Cofactor is 1, no cofactor multiplication will be applied.")
                return private_key.exchange(ec.ECDH(), public_key)
            if cofactor < 1:
                raise ValueError(f"Invalid cofactor value: {cofactor}. It must be greater than 0.")
            return _compute_ss_plus_cofactor(private_key, public_key, cofactor)
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


@not_keyword
def compute_hkdf(
    hash_alg: str, key_material: bytes, info: bytes = b"", salt: Optional[bytes] = None, length: int = 32
) -> bytes:
    """Compute the HKDF output for the given hash algorithm, key material, and optional user key material (UKM).

    :param hash_alg: The hash algorithm name to use for HKDF (e.g.,"sha256").
    :param key_material: The input key material (IKM) used for key derivation.
    :param info: Optional info parameter for HKDF. Defaults to an empty byte string.
    :param salt: Optional salt value for HKDF. Defaults to None.
    :param length: The desired length of the output key in bytes. Defaults to 32 bytes.
    :return: The derived key as bytes.
    """
    hash_instance = hash_name_to_instance(hash_alg)
    hkdf = HKDF(
        algorithm=hash_instance,
        length=length,
        salt=salt,
        info=info,  # as specified.
    )
    return hkdf.derive(key_material)


def verify_signature(  # noqa D417 undocumented-param
    public_key: Union[VerifyKey, PQSignaturePublicKey],
    signature: bytes,
    data: bytes,
    hash_alg: Optional[Union[str, hashes.HashAlgorithm]] = None,
    use_rsa_pss: bool = False,
    salt_length: Optional[int] = None,
    use_pre_hash: bool = False,
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
        - `use_rsa_pss`: Whether to use RSA-PSS padding for RSA keys. Defaults to `False`.
        - `salt_length`: Length of the salt for RSA-PSS padding. Defaults to the hash algorithm's digest size.

    Key Types and Verification:
        - `RSAPublicKey`: Verifies using PKCS1v15 padding and the provided hash algorithm.
        - `EllipticCurvePublicKey`: Verifies using ECDSA with the provided hash algorithm.
        - `Ed25519PublicKey` and `Ed448PublicKey`: Verifies without a hash algorithm.
        - `DSAPublicKey`: Verifies using the provided hash algorithm.
        - Unsupported key types (e.g., `X25519PublicKey`, `X448PublicKey`): Raises an error.
        - `PQSignaturePublicKey`: Verifies using the provided hash algorithm or `None`.

    Raises:
    ------
        - `InvalidSignature`: If the signature is invalid.
        - `ValueError`: If an unsupported key type is provided.

    Examples:
    --------
    | Verify Signature | ${public_key} | ${signature} | ${data} | sha256 |
    | Verify Signature | ${public_key} | ${signature} | ${data} |

    """
    if isinstance(public_key, PQSignaturePublicKey):
        # TODO maybe think about a better solution.
        hash_alg = public_key.check_hash_alg(hash_alg)
        public_key.verify(data=data, hash_alg=hash_alg, signature=signature, is_prehashed=use_pre_hash)

    elif isinstance(public_key, PQHashStatefulSigPublicKey):
        public_key.verify(data=data, signature=signature)

    elif isinstance(public_key, CompositeSig03PublicKey):
        public_key.verify(signature=signature, data=data, use_pss=use_rsa_pss, pre_hash=use_pre_hash)

    else:
        if isinstance(hash_alg, hashes.HashAlgorithm):
            pass
        elif hash_alg is not None:
            hash_alg = oid_mapping.hash_name_to_instance(hash_alg)

        _verify_trad_signature(
            public_key=public_key,  # type: ignore
            signature=signature,
            data=data,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            salt_length=salt_length,
        )


def _verify_trad_signature(
    public_key: Union[
        RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        dsa.DSAPublicKey,
    ],
    signature: bytes,
    data: bytes,
    hash_alg: Optional[hashes.HashAlgorithm],
    use_rsa_pss: bool = False,
    salt_length: Optional[int] = None,
) -> None:
    """Verify a digital signature using a standalone public key."""
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
        return

    if not hash_alg:
        raise ValueError(f"The {type(public_key).__name__} requires a hash algorithm.")

    if isinstance(public_key, rsa.RSAPublicKey):
        if use_rsa_pss:
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=salt_length or hash_alg.digest_size),
                hash_alg,  # type: ignore
            )
        else:
            public_key.verify(signature, data, padding=padding.PKCS1v15(), algorithm=hash_alg)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, data, hash_alg)

    elif isinstance(public_key, (x25519.X25519PublicKey, x448.X448PublicKey)):
        raise ValueError(
            f"Key type '{type(public_key).__name__}' is not used for signing or verifying signatures."
            f"It is used for key exchange."
        )
    else:
        raise BadAlg(f"Unsupported key type to verify a signature: {type(public_key).__name__}.")


@not_keyword
def decrypt_data_with_alg_id(
    alg_id: rfc9480.AlgorithmIdentifier,
    key: bytes,
    data: bytes,
    mac: Optional[bytes] = None,
    auth_attrs: Optional[bytes] = None,
    allow_bad_gcm_size: bool = False,
) -> bytes:
    """Decrypt data using the given AlgorithmIdentifier.

    :param alg_id: The AlgorithmIdentifier for the content encryption algorithm.
    :param key: The Content Encryption Key (CEK) for decryption.
    :param data: The encrypted content to decrypt.
    :param mac: The Message Authentication Code (MAC) for authenticated encryption algorithms.
    :param auth_attrs: The authenticated attributes for authenticated encryption algorithms.
    :param allow_bad_gcm_size: Whether to allow if the size is set to 12 bytes, but the nonce is not 12 bytes.
    :return: The decrypted plaintext.
    """
    alg_oid = alg_id["algorithm"]
    alg_params = alg_id["parameters"]

    if alg_oid in AES_GCM_OID_2_NAME:
        logging.info("Decrypting with AES-GCM using %s", AES_GCM_OID_2_NAME[alg_oid])
        gcm_params, rest = decoder.decode(alg_params, asn1Spec=GCMParameters())

        if rest:
            raise BadAsn1Data("GCMParameters")

        nonce = gcm_params["aes-nonce"].asOctets()

        _length = int(gcm_params["aes-ICVlen"])
        # The Default size is 12, for no it is accepted
        # if the value was not set.
        # Bad behavior!
        if len(nonce) != _length and not allow_bad_gcm_size:
            raise ValueError(f"Invalid nonce length: {len(nonce)}. Expected: {_length}")

        aes_gcm = AESGCM(key)
        mac_data = mac or b""
        return aes_gcm.decrypt(nonce, data + mac_data, associated_data=auth_attrs)

    if alg_oid in AES_CBC_OID_2_NAME:
        logging.info("Decrypting with AES-CBC using: %s", AES_CBC_OID_2_NAME[alg_oid])
        params, rest = decoder.decode(alg_params, asn1Spec=rfc3565.AES_IV())
        if rest:
            raise BadAsn1Data("AES_IV")

        nonce = params.asOctets()
        return compute_aes_cbc(key=key, data=data, iv=nonce, decrypt=True)

    raise ValueError(f"Unsupported content encryption algorithm: {alg_oid}")


def compute_encapsulation(  # noqa: D417 Missing argument descriptions in the docstring
    key: KEMPublicKey,
    other_key: Optional[ECDHPrivateKey] = None,
    key_length: int = 32,
) -> Tuple[bytes, bytes]:
    """Compute encapsulation for a key.

    Arguments:
    ---------
        - `key`: The key to encapsulate.
        - `other_key`: The other key to use for encapsulation. Defaults to `None`.
        - `key_length`: The length of the key in bytes. Defaults to `32`. (only used for RSA to align with RFC9690.)
        (uses `KDF3` with `SHA-256`).

    Returns:
    -------
        - The shared secret.
        - The ciphertext.

    Raises:
    ------
        - `InvalidKeyCombination`: If the composite key is RSA and the other key is not `None`.
        - `ValueError`: If the key type is unsupported.

    Examples:
    --------
    | ${shared_secret} ${ciphertext}= | Compute Encapsulation | ${key} |
    | ${shared_secret} | ${ciphertext}= | Compute Encapsulation | ${key} | ${other_key} |

    """
    if isinstance(key, RSAPublicKey):
        key = RSAEncapKey(key)

    if isinstance(key, RSAEncapKey):
        return key.encaps(
            use_oaep=False,
            ss_length=key_length,
        )
    if isinstance(key, AbstractHybridRawPublicKey):
        return key.encaps(private_key=other_key)
    if isinstance(key, CompositeKEMPublicKey):
        if isinstance(key.trad_key, RSAEncapKey) and other_key is not None:
            raise InvalidKeyCombination("Composite-KEM RSA can not be encapsulated with ECDH.")
        if isinstance(key.trad_key, RSAEncapKey):
            return key.encaps()
        return key.encaps(private_key=other_key)
    raise ValueError(f"Unsupported key type: {type(key).__name__}.")


def compute_decapsulation(  # noqa: D417 Missing argument descriptions in the docstring
    key: KEMPrivateKey,
    ciphertext: Union[bytes, KemCiphertextInfoAsn1],
    key_length: int = 32,
) -> bytes:
    """Compute decapsulation with a given ciphertext and private key.

    Arguments:
    ---------
        - `key`: The private key to use for decapsulation.
        - `ciphertext`: The ciphertext to decapsulate or a `KemCiphertextInfoAsn1` object.
        - `key_length`: The length of the key in bytes. (only used for RSA to align with RFC9690.) Defaults to `32`.
        (uses `KDF3` with `SHA-256`).

    Returns:
    -------
        - The shared secret.

    Raises:
    ------
        - `ValueError`: If the key type is invalid.

    Examples:
    --------
    | ${shared_secret} = | Compute Decapsulation | ${key} | ${ciphertext} |
    | ${shared_secret} = | Compute Decapsulation | ${key} | ${ciphertext} | 32 |

    """
    if isinstance(ciphertext, KemCiphertextInfoAsn1):
        ct = ciphertext["ciphertext"].asOctets()
    else:
        ct = ciphertext

    if isinstance(key, RSAPrivateKey):
        key = RSADecapKey(key)
    if isinstance(key, RSADecapKey):
        return key.decaps(
            ct=ct,
            use_oaep=False,
            ss_length=key_length,
        )
    return key.decaps(ct)


def derive_shared_secret_ec(
    z: bytes,
    key_wrap_oid: univ.ObjectIdentifier,
    hash_alg: str,
    ukm: Optional[bytes] = None,
) -> bytes:
    """Derive shared secret for EC keys using CMS formatting.

    :param z: The shared secret value Z from key agreement.
    :param key_wrap_oid: The OID of the key wrap algorithm.
    :param ukm: Optional UserKeyingMaterial.
    :param hash_alg: The name of the hashing algorithm (e.g., "sha256", "sha512") to be used for the KDF.
    :return: The derived key.
    """
    length = int(KM_KW_ALG[key_wrap_oid].replace("aes", "").replace("_wrap", ""))
    # As of RFC 5753 Section 7.2
    # (For example, for AES-256 it would be 00 00 01 00.)
    # Must be bit-length.
    ecc_cms_info = envdatautils.prepare_ecc_cms_shared_info(
        key_wrap_oid=key_wrap_oid,
        supp_pub_info=length,
        ukm=ukm,
    )

    key_length = length // 8
    other_info = encoder.encode(ecc_cms_info)
    k = compute_ansi_x9_63_kdf(z, key_length, other_info=other_info, hash_alg=hash_alg, use_version_2=True)
    return k


@not_keyword
def perform_static_dh(
    private_key: ECDHPrivateKey,
    public_key: Union[ECDHPublicKey, rfc9480.CMPCertificate],
    hash_alg: str,
    key_wrap_oid: univ.ObjectIdentifier,
    ukm: Optional[bytes] = None,
    use_cofactor: bool = False,
) -> bytes:
    """Perform static Diffie-Hellman key agreement using the provided private and public keys.

    This function derives a key using the ANSI X9.63 KDF and the specified hashing algorithm
    (uses version 2 of the KDF2: K(i) = Hash (Z || Counter || otherInfo).

    :param private_key: The private key used for the key agreement.
    :param public_key: The public key used for the key agreement.
    :param hash_alg: The name of the hashing algorithm (e.g., "sha256", "sha512") to be used for the KDF.
    :param key_wrap_oid: The OID of the key wrap algorithm used for the key agreement.
    :param ukm: Optional bytes representing the UserKeyingMaterial (UKM) used in the key agreement.
    :param use_cofactor: If True, the cofactor is used in the key agreement (h * z). This is relevant for
    cofactor-based key agreement schemes. Defaults to `False`.
    :return: The derived key as bytes after performing the static DH key agreement and KDF.
    :raises ValueError: If the key types are incompatible or if the key length is invalid.
    :raises KeyError: If the key wrap OID is not found in the mapping.
    """
    length = int(KM_KW_ALG[key_wrap_oid].replace("aes", "").replace("_wrap", ""))
    # As of RFC 5753 Section 7.2
    # (For example, for AES-256 it would be 00 00 01 00.)
    # must be bit-length.
    ecc_cms_info = envdatautils.prepare_ecc_cms_shared_info(
        key_wrap_oid=key_wrap_oid,
        supp_pub_info=length,
        ukm=ukm,
    )

    key_length = length // 8
    other_info = encoder.encode(ecc_cms_info)
    shared_secret = perform_ecdh(private_key, public_key, use_cofactor=use_cofactor)
    logging.info("shared_secret for static-dh: %s", shared_secret.hex())

    k = compute_ansi_x9_63_kdf(shared_secret, key_length, other_info=other_info, hash_alg=hash_alg, use_version_2=True)
    return k


@not_keyword
def avf(point: Point) -> int:
    """Compute the affine value of a point P on the elliptic curve."""
    n = point.curve.field.n
    length = math.ceil((math.floor(math.log2(n)) + 1) / 2)
    return (point.x % (2**length)) + (2**length)


@not_keyword
def compute_sender_ecdh_mqv_one_pass_exchange(
    static_private_key: EllipticCurvePrivateKey,
    ephemeral_key: EllipticCurvePrivateKey,
    recip_public_key: EllipticCurvePublicKey,
) -> bytes:
    """Compute the responder endpoint's shared secret in a One-Pass-MQV (Menezes-Qu-Vanstone) ECDH exchange.

    Computes the shared secret, the KDF **MUST** be applied afterwards!

    :param static_private_key: The static private key of the sender.
    :param ephemeral_key:The ephemeral private key of the sender.
    :param recip_public_key: The public key of the recipient.
    :return: Bytes representing the computed shared secret.
    """
    d_su_val, _ = convert_private_key_to_tinyec(static_private_key)
    public_key = convert_public_key_to_tinyec(recip_public_key)

    ephemeral_value, q_eu = convert_private_key_to_tinyec(ephemeral_key)
    n = q_eu.curve.field.n
    h = q_eu.curve.field.h

    sig_u = (ephemeral_value + avf(q_eu) * d_su_val) % n  # type: ignore
    point = (h * sig_u) * (public_key + avf(public_key) * public_key)
    point: Point

    if isinstance(point, Inf):
        raise ValueError("Computed point is at infinity.")

    z = point.x
    return z.to_bytes((z.bit_length() + 7) // 8, byteorder="big")


def convert_private_key_to_tinyec(private_key: EllipticCurvePrivateKey) -> Tuple[int, Point]:
    """Convert a cryptography EC private key to a tinyec private key.

    :param private_key: The private key to convert.
    :return: The private value and the public point on the curve.
    """
    private_value = private_key.private_numbers().private_value
    curve_name = private_key.curve.name.lower()
    curve = registry.get_curve(curve_name)
    public_point = private_value * curve.g
    public_point: Point

    if isinstance(public_point, Inf):
        raise TypeError("Computed point is at infinity.")

    return private_value, public_point


def convert_public_key_to_tinyec(public_key: EllipticCurvePublicKey) -> Point:
    """Convert a cryptography EC public key to a tinyec public key.

    :param public_key: The public key to convert.
    :return: The point on the curve.
    """
    public_numbers = public_key.public_numbers()
    curve_name = public_key.curve.name.lower()
    curve = registry.get_curve(curve_name)
    return Point(curve, public_numbers.x, public_numbers.y)


@not_keyword
def perform_one_pass_mqv(
    private_key: ec.EllipticCurvePrivateKey,
    peer_cert: Union[rfc9480.CMPCertificate, ec.EllipticCurvePublicKey],
    public_key_eph: ec.EllipticCurvePublicKey,
    key_wrap_oid: univ.ObjectIdentifier,
    hash_alg: str = "sha256",
    ukm: Optional[bytes] = None,
) -> bytes:
    """Perform MQV key agreement using the provided private and public keys.

    :param private_key: The private key used in the MQV process to derive the shared secret.
    :param peer_cert: The certificate or public key of the peer used in the MQV process.
    :param public_key_eph: The ephemeral public key used in the MQV process.
    :param hash_alg: The name of the hashing algorithm (e.g., "sha256", "sha512") to be used for hashing.
    :param key_wrap_oid: The OID of the key wrap algorithm used for the key agreement.
    :param ukm: Optional UserKeyingMaterial (UKM) used in the key agreement.
    :raises ValueError: If the key types are incompatible.
    :return: The derived shared secret as bytes.
    """
    if isinstance(peer_cert, rfc9480.CMPCertificate):
        spki = peer_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        peer_cert = keyutils.load_public_key_from_spki(spki)  # type: ignore

    if not isinstance(peer_cert, ec.EllipticCurvePublicKey):
        raise TypeError(
            f"Invalid public key type for MQV key exchange.Got: {type(peer_cert)} Expected an EllipticCurvePublicKey."
        )

    z = compute_recipient_ecdh_mqv_one_pass_exchange(
        recip_key=private_key,
        ephemeral_pub_key=public_key_eph,
        static_public_key=peer_cert,
    )

    logging.info("MQV shared secret: %s", z.hex())
    # Derive the key using the ANSI X9.63 KDF
    k = derive_shared_secret_ec(z, key_wrap_oid, hash_alg=hash_alg, ukm=ukm)
    logging.info("Derived One-Pass-MQV key: %s", k.hex())
    return k


def compute_recipient_ecdh_mqv_one_pass_exchange(
    recip_key: EllipticCurvePrivateKey,
    static_public_key: EllipticCurvePublicKey,
    ephemeral_pub_key: EllipticCurvePublicKey,
) -> bytes:
    """Compute the shared secret in a One-Pass-MQV (Menezes-Qu-Vanstone) ECDH exchange.

    The KDF **MUST** be applied afterwards!

    :param recip_key: The static private key of the recipient.
    :param static_public_key: The public key of the sender.
    :param ephemeral_pub_key: The ephemeral public key of the sender.
    :return: The computed shared secret as bytes.
    """
    # receiver's static private and public keys.
    q_uv = convert_public_key_to_tinyec(recip_key.public_key())
    d_sv_val, _ = convert_private_key_to_tinyec(recip_key)

    q_su_tiny = convert_public_key_to_tinyec(static_public_key)
    q_eu_tiny = convert_public_key_to_tinyec(ephemeral_pub_key)

    n = q_eu_tiny.curve.field.n
    h = q_eu_tiny.curve.field.h

    # Compute r using AVF
    r = avf(q_uv)
    # Compute d_sv_val + avf(Q_uv) * d_sv_val mod n
    implicit_sig_v = (d_sv_val + r * d_sv_val) % n

    r2 = avf(q_eu_tiny)
    second_part = q_eu_tiny + r2 * q_su_tiny
    point = (h * implicit_sig_v) * second_part
    point: Point

    if isinstance(point, Inf):
        raise ValueError("Computed point is at infinity.")

    z = point.x
    return z.to_bytes((z.bit_length() + 7) // 8, byteorder="big")
