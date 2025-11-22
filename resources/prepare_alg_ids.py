# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Prepare AlgorithmIdentifier for various cryptographic operations.

This module does not need to be imported by the RF. We import is as first import:
from resources.prepare_alg_ids import prepare_alg_id

Inside the `certbuildutils` so that the `prepare_alg_id` can be used.
But this is only allowed to be used in that module, all other modules should use the `prepare_alg_ids.*`
for the import.


"""

import os
from typing import List, Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pyasn1.codec.der import encoder
from pyasn1.type import constraint, tag, univ
from pyasn1.type.base import Asn1Item
from pyasn1_alt_modules import (
    rfc4210,
    rfc5280,
    rfc5480,
    rfc5990,
    rfc6664,
    rfc8017,
    rfc8018,
    rfc9044,
    rfc9480,
    rfc9481,
    rfc9629,
)
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.composite_sig13 import CompositeSig13PrivateKey
from resources import convertutils, oid_mapping
from resources.asn1_structures import KemBMParameterAsn1
from resources.convertutils import str_to_bytes
from resources.oid_mapping import hash_name_to_instance, sha_alg_name_to_oid
from resources.oidutils import (
    AES_GMAC_NAME_2_OID,
    ALL_KNOWN_NAMES_2_OID,
    CURVE_NAMES_TO_INSTANCES,
    HKDF_NAME_2_OID,
    KEY_WRAP_NAME_2_OID,
    RSASSA_PSS_OID_2_NAME,
    SYMMETRIC_ENCR_ALG_NAME_2_OID,
    id_KemBasedMac,
)
from resources.typingutils import OptSecret, SignKey


@keyword(name="Prepare AlgorithmIdentifier")
def prepare_alg_id(  # Noqa: D417 undocumented params
    name_or_oid: str, value: Optional[Union[bytes, str, Asn1Item]] = None, fill_random_params: bool = False
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an algorithm ID for use in a key.

    Arguments:
    ---------
        - `name_or_oid`: The name or OID of the algorithm.
        - `value`: The value to use for the algorithm. Defaults to `None`.
        - `fill_random_params`: The random parameters to use for the algorithm. Defaults to `False`.

    Returns:
    -------
        - The populated `AlgorithmIdentifier` structure.

    Raises:
    ------
        - ValueError: If both 'value' and 'fill_random_params' are provided.

    Examples:
    --------
    | ${alg_id} = | Prepare AlgorithmIdentifier | 1.2.840.113549.1.1.1 |
    | ${alg_id} = | Prepare AlgorithmIdentifier | 1.2.840.113549.1.1.1 |  0x5000 |
    | ${alg_id} = | Prepare AlgorithmIdentifier | ecdsa-sha256 |
    | ${alg_id} = | Prepare AlgorithmIdentifier | ecdsa-sha256 | fill_random_params=True |

    """
    alg_id = rfc9480.AlgorithmIdentifier()

    if value is not None and fill_random_params:
        raise ValueError("Only one of 'value' or 'fill_random_params' can be provided/set.")

    if "." in name_or_oid:
        alg_id["algorithm"] = univ.ObjectIdentifier(name_or_oid)
    else:
        alg_id["algorithm"] = ALL_KNOWN_NAMES_2_OID[name_or_oid]

    if value is not None:
        if isinstance(value, (bytes, str)):
            alg_id["parameters"] = univ.Any(str_to_bytes(value))
        else:
            alg_id["parameters"] = value

    elif fill_random_params:
        alg_id["parameters"] = univ.OctetString(os.urandom(16))

    return alg_id


@not_keyword
def get_all_supported_ecc_alg_ids() -> List[rfc9480.AlgorithmIdentifier]:
    """Get all supported ECC curves as AlgorithmIdentifiers."""
    alg_ids = []
    for curve in CURVE_NAMES_TO_INSTANCES.values():
        oid = getattr(ec.EllipticCurveOID(), curve.name.upper())
        oid = univ.ObjectIdentifier(oid.dotted_string)
        ec_params = rfc5480.ECParameters()
        ec_params["namedCurve"] = oid
        alg_id = prepare_alg_id(str(rfc6664.id_ecPublicKey), value=ec_params)
        alg_ids.append(alg_id)
    return alg_ids


###############################
# KDF AlgorithmIdentifier
###############################


# TODO: Update to use `otherSource` for salt. Allow two parameters for hash and recommendation checks.


@not_keyword
def prepare_pbkdf2_alg_id(salt: bytes, iterations: int = 100, key_length: int = 32, hash_alg: str = "sha256"):
    """Prepare the `PBKDF2` AlgorithmIdentifier object for `PKIMessageTMP` protection.

    :param salt: An optional salt for uniqueness. It can either be:
        - A string starting with '0x' for hexadecimal values,
        - A UTF-8 string, or
        - If not provided, a random 16-byte salt is generated.
    :param iterations: The number of iterations to be used for the key derivation function.
                       Defaults to 100.
    :param key_length: The desired length of the derived key in bytes. Defaults to 32-bytes.
    :param hash_alg: The name of the hash algorithm to use with HMAC. Defaults to "sha256".
    :return: Populated `PBKDF2` AlgorithmIdentifier object.
    """
    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc8018.id_PBKDF2

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params["salt"]["specified"] = univ.OctetString(salt)
    pbkdf2_params["iterationCount"] = iterations
    pbkdf2_params["keyLength"] = key_length
    pbkdf2_params["prf"] = prepare_hmac_alg_id(hash_alg)

    alg_id["parameters"] = pbkdf2_params
    return alg_id


def _prepare_hkdf(name: str, hash_alg: str = "sha256", fill_rand_params: bool = False) -> rfc9480.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for the specified HKDF algorithm.

    :param name: The name of the HKDF algorithm (e.g., "hkdf-sha256", "hkdf-sha384", "hkdf-sha512").
    :param fill_rand_params: If True, assign a random 32-byte value (MUST be absent).
    :return: The populated An AlgorithmIdentifier object.
    """
    name = name + "-" + hash_alg
    kdf_oid = HKDF_NAME_2_OID[name]
    kdf = rfc9480.AlgorithmIdentifier()
    kdf["algorithm"] = kdf_oid
    if fill_rand_params:
        kdf["parameters"] = os.urandom(32)
    return kdf


def _prepare_ansi_x9_kdf(
    name: str, hash_alg: str = "sha256", fill_rand_params: bool = False
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for the specified ANSI X9.63 KDF algorithm.

    :param name: The name of the ANSI X9.63 KDF algorithm (e.g., "kdf2", "kdf3").
    :param hash_alg: The hash algorithm to use for the KDF (e.g., "sha256").
    :param fill_rand_params: If True, assign a random 32-byte value to the parameters filed.
    (**MUST** be absent).
    :return: The populated `AlgorithmIdentifier` object.
    """
    kdf = rfc9480.AlgorithmIdentifier()

    if name == "kdf2":
        kdf["algorithm"] = rfc5990.id_kdf_kdf2
    else:
        kdf["algorithm"] = rfc5990.id_kdf_kdf3

    if fill_rand_params:
        kdf["parameters"] = os.urandom(32)
    else:
        kdf["parameters"] = rfc5990.AlgorithmIdentifier()
        kdf["parameters"]["algorithm"] = sha_alg_name_to_oid(hash_alg)

    return kdf


@keyword(name="Prepare KDF AlgorithmIdentifier")
def prepare_kdf_alg_id(  # noqa D417 undocumented-param
    kdf_name: str,
    fill_rand_params: bool = False,
    salt: OptSecret = None,
    iterations: Union[int, str] = 100000,
    *,
    length: Union[int, str] = 32,
    hash_alg: str = "sha256",
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for the specified KDF algorithm.

    Arguments:
    ---------
        - `kdf_name`: The name of the KDF algorithm (e.g., "hkdf-sha256", "kdf2-sha256", "kdf3-sha256").
        - `fill_rand_params`: Whether to fill the parameters field of the HKDF,KDF2,KDF3, AlgorithmIdentifier with
        random bytes. Defaults to `False`. (**MUST** be absent).
        - `salt`: The salt value for the KDF operation. Defaults to `None`.
                    (If not provided, a random 32-byte value will be generated.)
        - `iterations`: The number of iterations for the KDF operation. Defaults to `100000`.
        - `length`: The desired length of the derived key material. Defaults to `32`.
        - `hash_alg`: The hash algorithm to use for the KDF operation (e.g., "sha256").

    Returns:
    -------
        - The populated `AlgorithmIdentifier` structure.

    Raises:
    ------
        - ValueError: If the provided `kdf_name` is not supported (supported are 'hkdf', 'kdf2', 'kdf3', 'pbkdf2').

    Examples:
    --------
    | ${kdf_alg_id} = | Prepare KDF AlgorithmIdentifier | hkdf |  salt=0x12345678 | length=32 | hash_alg=sha256 |
    | ${kdf_alg_id} = | Prepare KDF AlgorithmIdentifier | kdf2 |
    | ${kdf_alg_id} = | Prepare KDF AlgorithmIdentifier | kdf3 |
    | ${kdf_alg_id} = | Prepare KDF AlgorithmIdentifier | pbkdf2 | salt=0x12345678 | iterations=1000 |

    """
    if kdf_name == "hkdf":
        return _prepare_hkdf(name=kdf_name, hash_alg=hash_alg, fill_rand_params=fill_rand_params)
    if kdf_name.startswith("kdf"):
        return _prepare_ansi_x9_kdf(name=kdf_name, hash_alg=hash_alg, fill_rand_params=fill_rand_params)
    if kdf_name.startswith("pbkdf2"):
        if salt is None:
            salt = os.urandom(32)

        salt = str_to_bytes(salt)
        return prepare_pbkdf2_alg_id(salt=salt, iterations=int(iterations), key_length=int(length), hash_alg=hash_alg)

    raise ValueError(f"Unsupported KDF algorithm: {kdf_name}. Supported are 'hkdf', 'kdf2', 'kdf3', 'pbkdf2'.")


@not_keyword
def prepare_wrap_alg_id(name: str, fill_rand_params: bool = False) -> rfc9629.KeyEncryptionAlgorithmIdentifier:
    """Prepare a KeyEncryptionAlgorithmIdentifier for the specified key wrap algorithm.

    :param name: The name of the key wrap algorithm (e.g., "aes-wrap", "aes-gcm-wrap").
    :param fill_rand_params: Whether to fill the parameters field of the KeyEncryptionAlgorithmIdentifier with
    random bytes. Defaults to `False`. (**MUST** be absent).
    :return: The populated KeyEncryptionAlgorithmIdentifier object.
    """
    key_enc_alg_id = rfc9629.KeyEncryptionAlgorithmIdentifier()
    wrap_oid = KEY_WRAP_NAME_2_OID[name]
    key_enc_alg_id["algorithm"] = wrap_oid
    if fill_rand_params:
        key_enc_alg_id["parameters"] = os.urandom(32)

    return key_enc_alg_id


@not_keyword
def prepare_symmetric_encr_alg_id(
    name: str, value: Optional[Union[str, bytes, Asn1Item]] = None, length: Optional[int] = None
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for the specified symmetric encryption algorithm.

    :param name: The name of the symmetric encryption algorithm (e.g., "aes128_cbc", "aes256_cbc").
    :param value: The value to use for the algorithm. Defaults to `None`.
    :param length: The length of the key to use in bytes, to set the correct OID. Defaults to `None`.
    :return: The populated AlgorithmIdentifier object.
    """
    alg_id = rfc9480.AlgorithmIdentifier()

    if length is not None and name == "cbc":
        if length == 32:
            oid = rfc9481.id_aes256_CBC
        elif length == 24:
            oid = rfc9481.id_aes192_CBC
        else:
            oid = rfc9481.id_aes128_CBC

    elif length is not None and name != "cbc":
        raise NotImplementedError(f"Unsupported symmetric encryption algorithm: {name}")

    else:
        oid = SYMMETRIC_ENCR_ALG_NAME_2_OID[name]

    alg_id["algorithm"] = oid
    if value is not None and isinstance(value, (bytes, str)):
        alg_id["parameters"] = str_to_bytes(value)

    elif value is not None:
        alg_id["parameters"] = encoder.encode(value)

    return alg_id


###############################
# Hash AlgorithmIdentifier
###############################


@not_keyword
def prepare_sha_alg_id(
    hash_alg: str,
    add_params_rand_val: bool = False,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an `AlgorithmIdentifier` for the specified SHA hash algorithm.

    :param hash_alg: The name of the SHA hash algorithm (e.g., 'sha256', 'sha512').
    :param add_params_rand_val: If True, adds a random value to the `parameters` field. Defaults to `False`.
    (**MUST** be absent)
    :return: An `AlgorithmIdentifier` object for the given SHA-family hash algorithm.
    :raises ValueError: If the provided `hash_alg` is invalid.
    """
    hash_alg_oid = sha_alg_name_to_oid(hash_alg)

    value = None
    if not add_params_rand_val:
        value = encoder.encode(univ.Null(""))

    return prepare_alg_id(str(hash_alg_oid), value=value, fill_random_params=add_params_rand_val)


###############################
# MAC AlgorithmIdentifier
###############################


@not_keyword
def prepare_hmac_alg_id(
    hash_alg: str,
    add_params_rand_val: bool = False,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare an `AlgorithmIdentifier` for the specified HMAC hash algorithm.

    :param hash_alg: The name of the hash algorithm to be used with HMAC (e.g., 'sha256', 'sha384', 'sha512').
    :param add_params_rand_val: If True, adds a random value to the `parameters` field. Defaults to `False`.
    (**MUST** be absent)
    :return: An `AlgorithmIdentifier` object for the given HMAC hash algorithm.
    :raises ValueError: If the provided `hash_alg` is invalid.
    """
    hmac_alg_oid = sha_alg_name_to_oid(f"hmac-{hash_alg}")
    return prepare_alg_id(str(hmac_alg_oid), fill_random_params=add_params_rand_val)


@not_keyword
def prepare_password_based_mac_parameters(
    salt: Optional[bytes] = None, iterations=1000, hash_alg="sha256"
) -> rfc9480.PBMParameter:
    """Prepare `rfc8018.PBMParameter` structure for password-based MAC protection in PKIMessage.

    :param salt: Optional salt to use for the password-based MAC protection.
                 If not provided, generates 16 random bytes.
    :param iterations: Number of iterations of the OWF (hashing) to perform.
    :param hash_alg: Name of hashing algorithm to use, "sha256" by default.
    :return: The populated `rfc9480.PBMParameter` structure.
    """
    salt = salt or os.urandom(16)

    pbm_parameter = rfc9480.PBMParameter()
    pbm_parameter["salt"] = univ.OctetString(salt).subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 128))
    pbm_parameter["iterationCount"] = iterations

    pbm_parameter["owf"] = prepare_sha_alg_id(hash_alg)
    pbm_parameter["mac"] = prepare_hmac_alg_id(hash_alg)

    return pbm_parameter


@not_keyword
def prepare_kmac_alg_id(hash_alg: str) -> rfc9480.AlgorithmIdentifier:
    """Prepare an `AlgorithmIdentifier` for the specified KMAC hash algorithm.

    :param hash_alg: The name of the hash algorithm to be used with KMAC (either 'shake128' or 'shake256').
    :return: An `AlgorithmIdentifier` object for the given KMAC hash algorithm.
    :raises ValueError: If the provided `hash_alg` is invalid.
    """
    if hash_alg == "shake128":
        oid = rfc9481.id_KMACWithSHAKE128
    elif hash_alg == "shake256":
        oid = rfc9481.id_KMACWithSHAKE256
    else:
        raise ValueError("KMAC can only be used with 'shake128' or 'shake256'")

    return prepare_alg_id(str(oid))


@not_keyword
def prepare_aes_gmac_prot_alg_id(
    protection_type: str, nonce: Optional[Union[str, bytes]] = None
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for AES-GMAC-based message protection in a PKIMessage.

    :param protection_type: A string representing the protection algorithm type (e.g., "aes-gmac").
    :param nonce: An optional nonce value used for AES-GMAC. It can either be:
                  - A string starting with '0x' for hexadecimal values,
                  - A UTF-8 string, or
                  - If not provided, a random 12-byte nonce is generated.
    :return: The prepared `AlgorithmIdentifier` with the AES-GMAC OID and parameters.
    """
    nonce_bytes = convertutils.str_to_bytes(nonce or os.urandom(12))
    gcm_params = rfc9044.GCMParameters()
    gcm_params["nonce"] = univ.OctetString(nonce_bytes)
    oid = AES_GMAC_NAME_2_OID[protection_type]
    return prepare_alg_id(str(oid), value=gcm_params)


@not_keyword
def prepare_pbmac1_parameters(
    salt: Optional[Union[bytes, str]] = None, iterations: int = 100, length: int = 32, hash_alg: str = "sha256"
) -> rfc8018.PBMAC1_params:
    """Prepare the PBMAC1 `rfc8018.PBMAC1_params` for `PKIMessageTMP` protection, using PBKDF2 with HMAC.

    :param salt: An optional salt for uniqueness. It can either be:
        - A string starting with '0x' for hexadecimal values,
        - A UTF-8 string, or
        - If not provided, a random 16-byte salt is generated.
    :param iterations: The number of iterations to be used in the PBKDF2 key derivation function.
                       Default is 100.
    :param length: The desired length of the derived key in bytes. Default is 32 bytes.
    :param hash_alg: The name of the hash algorithm to use with HMAC. Default is "sha256".
    :return: Populated `rfc8018.PBMAC1_params` object.
    """
    salt = convertutils.str_to_bytes(salt or os.urandom(16))
    outer_params = rfc8018.PBMAC1_params()
    outer_params["keyDerivationFunc"] = prepare_pbkdf2_alg_id(
        salt=salt, iterations=iterations, key_length=length, hash_alg=hash_alg
    )
    outer_params["messageAuthScheme"] = prepare_hmac_alg_id(hash_alg)

    return outer_params


@not_keyword
def prepare_dh_based_mac_params(
    hash_alg: str = "sha1", mac_alg: str = "hmac", nonce: Optional[Union[bytes, str]] = None
) -> rfc4210.DHBMParameter:
    """Prepare a Diffie-Hellman Based MAC (Message Authentication Code) parameter structure.

    The structure uses a one-way hash function (OWF) used on the Diffie-Hellman (DH) shared secret to derive a key,
    which is then used to compute the Message Authentication Code (MAC) with the specified MAC algorithm.

    :param hash_alg: A string representation of the hash algorithm to be used for the
                     one-way function (OWF). Defaults to "sha1".
    :param mac_alg: A string representation of the MAC algorithm to be used for the MAC computation.
    e.g., "hmac" or "aes-gmac256". Defaults to "hmac".
    :param nonce: An optional nonce value used for AES-GMAC. It can either be: a string starting with '0x' for
                    hexadecimal values, a UTF-8 string, or if not provided, a random 12-byte nonce is generated.
    :return: A `rfc9480.DHBMParameter` object populated with the algorithm identifiers for the
             specified hash and MAC algorithm.
    """
    param = rfc9480.DHBMParameter()
    param["owf"] = prepare_sha_alg_id(hash_alg)
    if mac_alg == "hmac":
        param["mac"] = prepare_hmac_alg_id(hash_alg)
    elif mac_alg.startswith("hmac"):
        param["mac"] = prepare_hmac_alg_id(mac_alg.split("-")[1])
    elif mac_alg.startswith("aes"):
        param["mac"] = prepare_aes_gmac_prot_alg_id(mac_alg, nonce=nonce)

    elif mac_alg == "kmac":
        hash_alg = "shake256"
        param["mac"] = prepare_kmac_alg_id(hash_alg)
    elif mac_alg.startswith("kmac"):
        param["mac"] = prepare_kmac_alg_id(mac_alg.split("-")[1])
    else:
        raise ValueError(f"Unsupported MAC algorithm for DHBasedMAC: {mac_alg}")

    return param


@not_keyword
def prepare_dh_based_mac_alg_id(
    hash_alg: str = "sha1", mac_alg: str = "hmac", salt: Optional[Union[bytes, str]] = None
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for DHBasedMac protection in a PKIMessage.

    :param hash_alg: The name of the hash algorithm to be used for the one-way function (OWF). Defaults to "sha1".
    :param mac_alg: The name of the MAC algorithm to be used for the MAC computation. Defaults to "hmac".
    :param salt: Optional salt used for the AES-GMAC. Defaults to `None`.
    :return:
    """
    prot_alg_id = rfc9480.AlgorithmIdentifier()
    prot_alg_id["algorithm"] = rfc9480.id_DHBasedMac
    prot_alg_id["parameters"] = prepare_dh_based_mac_params(hash_alg=hash_alg, mac_alg=mac_alg, nonce=salt)
    return prot_alg_id


###############################
# KEM AlgorithmIdentifier
###############################


def _prepare_kem_based_mac_params(
    kem_context: Optional[Union[bytes, str]] = None,
    kdf: str = "pbkdf2",
    salt: Optional[bytes] = None,
    iterations: int = 100000,
    *,
    length: int = 32,
    hash_alg: str = "sha256",
) -> KemBMParameterAsn1:
    """Prepare a KemBMParameter (RFC 9810, Section 5.1.3.4).

    Behavior per RFC 9810:
    ---------------------
    - kemContext is an OPTIONAL OCTET STRING for algorithm-specific context (ukm).
    - Lines 2009–2033 define KemOtherInfo, which is constructed at computation time and used as KDF 'info'.

    :param kem_context: Optional context information (e.g., UKM) for the KEM operation.
    :param kdf: The key derivation function to use (e.g., "pbkdf2"). Defaults to "pbkdf2".
    :param salt: The salt value for the PBKDF2 key derivation function.
    :param iterations: The number of iterations for PBKDF2 key derivation. Defaults to 100,000.
    :param length: The desired length of the derived key material (OKM) in bytes. Defaults to 32.
    :param hash_alg: The hash algorithm to use for PBKDF2 key derivation. Defaults to "sha256".
    :return: The populated `KemBMParameter` object.
    """
    param = KemBMParameterAsn1()
    mac_alg_id = rfc5280.AlgorithmIdentifier()

    if kdf == "pbkdf2":
        kdf_alg_id = prepare_pbkdf2_alg_id(
            salt=salt or os.urandom(16), iterations=iterations, key_length=length, hash_alg=hash_alg
        )
    else:
        kdf_alg_id = prepare_kdf_alg_id(kdf_name=f"{kdf}", hash_alg=hash_alg)

    mac_alg_id["algorithm"] = sha_alg_name_to_oid(f"hmac-{hash_alg}")

    param["kdf"] = kdf_alg_id

    if kem_context is not None:
        kem_ctx_bytes = str_to_bytes(kem_context)
        param["kemContext"] = univ.OctetString(kem_ctx_bytes).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    param["len"] = univ.Integer(length).subtype(subtypeSpec=constraint.ValueRangeConstraint(1, float("inf")))
    param["mac"] = mac_alg_id
    return param


@not_keyword
def prepare_kem_based_mac_alg_id(
    kem_context: Optional[Union[bytes, str]] = None,
    salt: Optional[bytes] = None,
    kdf: str = "pbkdf2",
    iterations: int = 100000,
    *,
    length: int = 32,
    hash_alg: str = "sha256",
) -> rfc9480.AlgorithmIdentifier:
    """Prepare AlgorithmIdentifier for id-KemBasedMac (RFC 9810, Section 5.1.3.4).

    Behavior per RFC 9810: kemContext is OPTIONAL ukm bytes. The KDF 'info' is the DER-encoded KemOtherInfo composed
    at computation time and MUST NOT be embedded here.

    :param kem_context: Optional KEM context. Defaults to `None`.
    :param salt: Optional salt for key derivation. Defaults to `None`.
    :param iterations: Number of iterations for key derivation. Defaults to 100000.
    :param length: Desired length of the derived key in bytes. Defaults to 32.
    :param kdf: Key derivation function to use (e.g., "pbkdf2","kdf2", "kdf3"). Defaults to "pbkdf2".
    :param hash_alg: Hash algorithm for key derivation (e.g., "sha256"). Defaults to "sha256".
    :return: A populated `AlgorithmIdentifier` object for KEMBasedMac.
    """
    kem_alg_id = rfc9480.AlgorithmIdentifier()
    kem_alg_id["algorithm"] = id_KemBasedMac
    kem_alg_id["parameters"] = _prepare_kem_based_mac_params(
        kem_context=kem_context, kdf=kdf, salt=salt, iterations=iterations, length=length, hash_alg=hash_alg
    )
    return kem_alg_id


def _prepare_rsa_kem_alg_id(hash_kdf: str = "sha384", key_length: int = 384) -> rfc9480.AlgorithmIdentifier:
    """Prepare an `AlgorithmIdentifier` for RSA-KEM with associated parameters.

    :param hash_kdf: Hash name for the KDF (e.g., "sha384").
    :param key_length: Key length in bits.
    :return: AlgorithmIdentifier for RSA-KEM.
    """
    rsa_kem = rfc9480.AlgorithmIdentifier()
    rsa_kem["algorithm"] = rfc5990.id_kem_rsa
    rsa_kem["parameters"] = rfc5990.RsaKemParameters()

    kdf_alg_id = rfc5990.KeyDerivationFunction()
    kdf_alg_id["parameters"] = sha_alg_name_to_oid(hash_kdf)
    rsa_kem["parameters"]["keyDerivationFunction"] = kdf_alg_id

    rsa_kem["parameters"]["keyLength"] = univ.Integer(key_length)
    return rsa_kem


def _prepare_aes_wrap_alg_id(name: str) -> rfc9480.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for AES wrap.

    :param name: Name of the AES wrap algorithm (e.g., "aes256-wrap").
    :return: AlgorithmIdentifier for AES wrap.
    """
    aes_wrap = rfc9480.AlgorithmIdentifier()
    aes_wrap["algorithm"] = KEY_WRAP_NAME_2_OID[name]
    return aes_wrap


def _prepare_gen_hybrid_param(aes_wrap: str = "aes256-wrap") -> rfc9480.AlgorithmIdentifier:
    """Prepare a GenericHybridParameters combining RSA-KEM and AES wrap.

    :param aes_wrap: Name of the AES wrap algorithm (default: "aes256_wrap").
    :return: AlgorithmIdentifier for GenericHybridParameters.
    """
    hybrid_param = rfc9480.AlgorithmIdentifier()
    hybrid_param["algorithm"] = rfc5990.id_kem_rsa
    hybrid_param["parameters"] = rfc5990.GenericHybridParameters()

    hybrid_param["parameters"]["kem"] = _prepare_rsa_kem_alg_id()
    hybrid_param["parameters"]["dem"] = _prepare_aes_wrap_alg_id(aes_wrap)

    return hybrid_param


###############################
# Signature AlgorithmIdentifier
###############################


@not_keyword
def prepare_rsa_pss_alg_id(
    hash_alg: str,
    salt_length: Optional[int] = None,
    add_params_rand_val: bool = False,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the `AlgorithmIdentifier` for RSASSA-PSS with the specified hash algorithm.

    :param hash_alg: A string representing the hash name (e.g., 'sha256', 'shake128').
    :param salt_length: The length of the salt.
    :param add_params_rand_val: If True, adds a random value to the `AlgorithmIdentifier` parameters.
    :return: A populated `AlgorithmIdentifier` instance.
    :raises ValueError: If the algorithm name is not supported.
    """
    alg_id = rfc9480.AlgorithmIdentifier()

    if hash_alg in ["shake128", "shake256"]:
        # `parameters` must be absent
        if add_params_rand_val:
            alg_id["parameters"] = univ.OctetString(os.urandom(16))

        if hash_alg == "shake128":
            oid = rfc9481.id_RSASSA_PSS_SHAKE128
        else:
            oid = rfc9481.id_RSASSA_PSS_SHAKE256

        alg_id["algorithm"] = oid
        return alg_id

    oid = rfc9481.id_RSASSA_PSS

    hash_algorithm = prepare_sha_alg_id(hash_alg, add_params_rand_val=add_params_rand_val)

    hash_inst = hash_name_to_instance(hash_alg)

    mgf_algorithm = rfc9480.AlgorithmIdentifier()
    mgf_algorithm["algorithm"] = rfc8017.id_mgf1
    mgf_algorithm["parameters"] = hash_algorithm

    pss_params = rfc8017.RSASSA_PSS_params()
    # Setting cloneValueFlag=True is necessary; otherwise, the structure will be deleted.
    pss_params["hashAlgorithm"] = hash_algorithm.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0), cloneValueFlag=True
    )
    pss_params["maskGenAlgorithm"] = mgf_algorithm.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )
    # 20 is the default for sha1.
    pss_params["saltLength"] = univ.Integer(value=salt_length or hash_inst.digest_size).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )

    alg_id["algorithm"] = oid
    alg_id["parameters"] = pss_params
    return alg_id


@keyword(name="Prepare Signature AlgorithmIdentifier")
def prepare_sig_alg_id(  # noqa D417 undocumented-param
    signing_key: SignKey,
    hash_alg: Optional[str] = "sha256",
    use_rsa_pss: bool = False,
    add_params_rand_val: bool = False,
    add_null: Optional[bool] = None,
) -> rfc9480.AlgorithmIdentifier:
    """Prepare the AlgorithmIdentifier for the signature algorithm based on the key and hash algorithm.

    If `use_rsa_pss` is `True`, configures RSA-PSS; otherwise, it selects the signature OID
    based on the signing key type and hash algorithm.

    Arguments:
    ---------
        - `signing_key`: The private key used for signing.
        - `hash_alg`: The hash algorithm to use. Defaults to `"sha256"`.
        (must be populated with the correct hash algorithm for PQ signature keys)
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature algorithm. Defaults to `False`.
        - `add_params_rand_val`: Whether to add the `parameters` field with a random value. Defaults to `False`.
        (Or hash algorithm for RSA-PSS-SHA256) (**MUST** be absent)
        - `add_null`: Whether to add a `Null` value to the `parameters` field (will be added if \
        `None`for RSA if hash_alg is `SHA`). Defaults to `None`.

    Raises:
    ------
        - `ValueError`: If both `add_params_rand_val` and `add_null` are set.
        - `ValueError`: If the traditional key type is not supported with the given hash algorithm.

    Returns:
    -------
        - An `rfc9480.AlgorithmIdentifier` for the specified signing configuration.

    Examples:
    --------
    | ${alg_id}= | Prepare Signature AlgorithmIdentifier | signing_key=${private_key} |
    | ${alg_id}= | Prepare Signature AlgorithmIdentifier | signing_key=${private_key} | hash_alg="sha256" |
    | ${alg_id}= | Prepare Signature AlgorithmIdentifier | signing_key=${private_key} | \
    hash_alg="sha256" | use_rsa_pss=True |
    | ${alg_id}= | Prepare Signature AlgorithmIdentifier | signing_key=${private_key} | \
    use_rsa_pss=True | use_pre_hash=True |

    """
    alg_id = rfc9480.AlgorithmIdentifier()

    if isinstance(signing_key, CompositeSig13PrivateKey):
        # means an expired key is used.
        domain_oid = signing_key.get_oid(use_pss=use_rsa_pss)
        alg_id["algorithm"] = domain_oid

    else:
        oid = oid_mapping.get_alg_oid_from_key_hash(key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)
        alg_id["algorithm"] = oid

        if oid in RSASSA_PSS_OID_2_NAME:
            if hash_alg is None:
                raise ValueError("Hash algorithm must be provided for RSASSA-PSS.")
            return prepare_rsa_pss_alg_id(hash_alg=hash_alg, add_params_rand_val=add_params_rand_val)

        if isinstance(signing_key, RSAPrivateKey):
            if add_null is None or add_null:
                alg_id["parameters"] = univ.Null("")

    if add_params_rand_val and add_null:
        raise ValueError("Only one of `add_params_rand_val` and `add_null` can be set.")

    if add_params_rand_val:
        alg_id["parameters"] = univ.OctetString(os.urandom(16))

    if add_null:
        alg_id["parameters"] = univ.Null("")

    return alg_id
