"""
Provides functionality to prepare the `pyasn1` `rfc9480.PKIMessage` protection: AlgorithmIdentifier field and computes the PKIProtection.
"""

import logging
import os
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import encoder
from pyasn1.type import univ, constraint
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc9044, rfc5280, rfc8018, rfc4210, rfc9480, rfc9481
from typing_extensions import Optional

from cryptography.hazmat.primitives import serialization

from certutils import parse_certificate
from cmputils import _prepare_extra_certs, encode_to_der
from cryptoutils import compute_hash, do_dh_key_exchange_password_based
from cryptoutils import generate_cert_from_private_key
from oid_mapping import (
    get_alg_oid_from_key_hash,
    get_hash_name_to_oid,
    HMAC_SHA_OID_2_NAME,
    SUPPORTED_SIG_MAC_OIDS,
    get_hash_from_signature_oid,
    SHA_OID_2_NAME,
    SYMMETRIC_PROT_ALGO,
    AES_GMAC_NAME_2_OID,
    AES_GMAC_OID_2_NAME,
)
from test_suite_enums import ProtectionAlgorithm
from resources.cryptoutils import (
    compute_pbmac1,
    compute_gmac,
    compute_password_based_mac,
    sign_data,
    compute_hmac,
)
from typingutils import PrivateKey, PrivSignCertKey
from verifyingutils import verify_signature


def _prepare_password_based_mac_parameters(
    salt: Optional[bytes] = None, iterations=1000, hash_alg="sha256"
) -> rfc9480.PBMParameter:
    """Prepares password-based-mac protection with the pyasn1 `rfc8018.PBMParameter` structure.

    :param salt: optional bytes, salt to use for the password-based-mac protection, if not given, will generate 16 random bytes
    :param iterations: optional int, number of iterations of the OWF (hashing) to perform
    :param hash_alg: optional str, name of hashing algorithm to use, "sha256" by default.
    :return: pyasn1 rfc9480.PBMParameter structure.
    """
    salt = salt or os.urandom(16)

    hmac_alg_oid = get_hash_name_to_oid(f"hmac-{hash_alg}")
    hash_alg_oid = get_hash_name_to_oid(hash_alg)

    pbm_parameter = rfc9480.PBMParameter()
    pbm_parameter["salt"] = univ.OctetString(salt).subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 128))
    pbm_parameter["iterationCount"] = iterations

    pbm_parameter["owf"] = rfc8018.AlgorithmIdentifier()
    pbm_parameter["owf"]["algorithm"] = hash_alg_oid
    pbm_parameter["owf"]["parameters"] = univ.Null()

    pbm_parameter["mac"] = rfc8018.AlgorithmIdentifier()
    pbm_parameter["mac"]["algorithm"] = hmac_alg_oid
    pbm_parameter["mac"]["parameters"] = univ.Null()

    return pbm_parameter


def _prepare_pbmac1_parameters(salt: Optional[bytes] = None, iterations=100, length=32, hash_alg="sha256"):
    """Prepares the PBMAC1 pyasn1 `rfc8018.PBMAC1_params`. Used for the `rfc9480.PKIMessage` structure Protection.
       PBKDF2 with HMAC as message authentication scheme is used.

    :param salt: Optional bytes for uniqueness.
    :param iterations: The number of iterations to be used in the PBKDF2 key derivation function.
                       Default is 100.
    :param length: int The desired length of the derived key in bytes. Default is 32 bytes.
    :param hash_alg: str the name of the to use with HMAC.
    :return:
    """
    salt = salt or os.urandom(16)

    hmac_alg = get_hash_name_to_oid(f"hmac-{hash_alg}")

    outer_params = rfc8018.PBMAC1_params()
    outer_params["keyDerivationFunc"] = rfc8018.AlgorithmIdentifier()

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params["salt"]["specified"] = univ.OctetString(salt)
    pbkdf2_params["iterationCount"] = iterations
    pbkdf2_params["keyLength"] = length
    pbkdf2_params["prf"] = rfc8018.AlgorithmIdentifier()
    pbkdf2_params["prf"]["algorithm"] = hmac_alg
    pbkdf2_params["prf"]["parameters"] = univ.Null()

    outer_params["keyDerivationFunc"]["algorithm"] = rfc8018.id_PBKDF2
    outer_params["keyDerivationFunc"]["parameters"] = pbkdf2_params

    outer_params["messageAuthScheme"]["algorithm"] = hmac_alg
    outer_params["messageAuthScheme"]["parameters"] = univ.Null()

    return outer_params


def _prepare_dh_based_mac(hash_alg: str = "sha1") -> rfc4210.DHBMParameter:
    """Prepares a Diffie-Hellman Based MAC (Message Authentication Code) parameter structure.

    The structure uses a One-Way Hash Function (OWF) to hash the Diffie-Hellman (DH) shared secret to derive a key,
    which is then used to compute the Message Authentication Code (MAC) with the specified MAC algorithm.

    :param hash_alg: A string representation the hash algorithm to be used for the
                     one-way-function (OWF). Defaults to "sha1"
    :return: A `pyasn1_alt_module.rfc4210.DHBMParameter` object populated with the algorithm identifiers for the
             specified hash and MAC algorithm.
    """
    param = rfc9480.DHBMParameter()

    alg_id_owf = rfc5280.AlgorithmIdentifier()
    alg_id_mac = rfc5280.AlgorithmIdentifier()

    alg_id_owf["algorithm"] = get_hash_name_to_oid(hash_alg)
    alg_id_owf["parameters"] = univ.Null()

    alg_id_mac["algorithm"] = get_hash_name_to_oid(f"hmac-{hash_alg}")
    alg_id_mac["parameters"] = univ.Null()

    param["owf"] = alg_id_owf
    param["mac"] = alg_id_mac
    return param


def _prepare_pki_message_protection_field(
        pki_message: rfc9480.PKIMessage,
        protection: str,
        password: Optional[str] = None,
        private_key: Optional[PrivateKey] = None,
) -> rfc9480.PKIMessage:
    """Preparse the pki protection for the PKIMessage algorithm
    :param pki_message: `pyasn1_alt_module.rfc9480.PKIMessage`
    :param protection: A string representing the type of Protection.
    :param password: A string representing a shared secret or a Server Private Key for DHBasedMac.
    :param private_key: A`cryptography` `PrivateKey` object. For Signing or DHBasedMac.
    :return: Returns the protected `pyasn1_alt_module.rfc9480.PKIMessage` object.
    """

    prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 1))

    assert (
            password or private_key
    ), "Either a password, private key must be provided for PKIMessage structure Protection"

    protection_type = ProtectionAlgorithm.get(protection)

    protected_part = rfc9480.ProtectedPart()
    protected_part["header"] = pki_message["header"]
    protected_part["body"] = pki_message["body"]

    encoded = encoder.encode(protected_part)

    protection_value = b""

    if protection_type == ProtectionAlgorithm.HMAC:
        prot_alg_id["algorithm"] = rfc8018.id_hmacWithSHA256
        prot_alg_id["parameters"] = univ.Null()
        protection_value = compute_hmac(data=encoded, key=password, hash_alg="sha512")

    elif protection_type == ProtectionAlgorithm.PBMAC1:
        prot_alg_id["algorithm"] = rfc8018.id_PBMAC1
        salt = os.urandom(16)
        pbmac1_parameters = _prepare_pbmac1_parameters(salt=salt, iterations=262144, length=32, hash_alg="sha512")
        prot_alg_id["parameters"] = pbmac1_parameters
        protection_value = compute_pbmac1(
            data=encoded,
            key=password,
            iterations=262144,
            salt=salt,
            length=32,
            hash_alg="sha512",
        )

    elif protection_type == ProtectionAlgorithm.PASSWORD_BASED_MAC:
        salt = os.urandom(16)
        prot_alg_id["algorithm"] = rfc4210.id_PasswordBasedMac
        pbm_parameters = _prepare_password_based_mac_parameters(salt=salt, iterations=1000, hash_alg="sha256")
        prot_alg_id["parameters"] = pbm_parameters
        protection_value = compute_password_based_mac(
            data=encoded, key=password, iterations=1000, salt=salt, hash_alg="sha256"
        )

    elif protection_type == ProtectionAlgorithm.AES_GMAC:
        nonce = os.urandom(12)
        prot_alg_id["algorithm"] = AES_GMAC_OIDS[protection]
        prot_alg_id["parameters"] = rfc9044.GCMParameters()
        prot_alg_id["parameters"]["nonce"] = univ.OctetString(nonce)
        protection_value = compute_gmac(data=encoded, key=password.encode("utf-8"), nonce=nonce)

    elif protection_type == ProtectionAlgorithm.SIGNATURE:

        if private_key is None:
            raise ValueError("private_key must be provided for PKIMessage structure Protection")

        elif not isinstance(private_key, PrivateKey):
            raise ValueError("private_key must be an instance of PrivateKey, but is of type: {}.".format(type(private_key)))

        prot_alg_id["algorithm"] = get_alg_oid_from_key_hash(key=private_key, hash_alg="sha256")
        prot_alg_id["parameters"] = univ.Null()
        protection_value = sign_data(data=encoded, key=private_key, hash_alg="sha256")

    elif protection_type == ProtectionAlgorithm.DH:
        prot_alg_id["algorithm"] = rfc9480.id_DHBasedMac
        prot_alg_id["param"] = _prepare_dh_based_mac(hash_alg="sha1", mac="hmac-sha1")
        protection_value = compute_dh_based_mac(data=encoded, key=private_key, password=password, hash_alg="sha1")

    wrapped_protection = (
        rfc9480.PKIProtection()
        .fromOctetString(protection_value)
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
    )
    pki_message["protection"] = wrapped_protection
    return pki_message


def apply_pki_message_protection(
        pki_message: rfc9480.PKIMessage,
        protection: str,
        password: Optional[str] = None,
        private_key: Optional[PrivateKey] = None,
) -> rfc9480.PKIMessage:
    """
    Prepares the PKI protection for the PKIMessage algorithm.

    Arguments:
    - `pki_message`: `pyasn1_alt_module.rfc9480.PKIMessage` object. which has a set `pyasn1_alt_module.rfc9480.PKIBody`
    - `protection`: String representing the type of protection.
    - `password`: String representing a shared secret or a server private key for DHBasedMac (default is None).
    - `private_key`: `cryptography` ``PrivateKey`` object, used for signing or DHBasedMac (default is None).

    Returns:
    - `rfc9480.PKIMessage`: The PKIMessage object with the applied protection.

    Raises:
    - ValueError | If the `PKIMessage` body is not set or is not a value. |


    Example:
    | ${protected_message}= | Apply PKI Message Protection | ${PKI_MESSAGE} | pbmac1    | ${SECRET}       |
    | ${protected_message}= | Apply PKI Message Protection | ${PKI_MESSAGE} | aes-gmac  | ${SECRET}       |
    | ${protected_message}= | Apply PKI Message Protection | ${PKI_MESSAGE} | signature | private_key=${PRIVATE_KEY}  |
    | ${protected_message}= | Apply PKI Message Protection | ${PKI_MESSAGE} | dh | private_key=${PRIVATE_KEY}  password={PASSWORD}|

    """
    if not pki_message["body"].isValue:
        raise ValueError("PKI Message body needs to be a value!")

    return _prepare_pki_message_protection_field(
        pki_message=pki_message,
        protection=protection,
        password=password,
        private_key=private_key,
    )
