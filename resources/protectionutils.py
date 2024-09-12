"""Utilities that generate and parse protection-related structures in PKIMessage."""

import logging
import os
from typing import Optional, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import encoder
from pyasn1.type import constraint, univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc4210, rfc5280, rfc8018, rfc9044, rfc9480, rfc9481
from robot.api.deco import not_keyword

import certutils
import cmputils
import cryptoutils
from cmputils import encode_to_der, prepare_extra_certs
from cryptoutils import compute_gmac, compute_hash, compute_password_based_mac, compute_pbmac1
from oid_mapping import (
    AES_GMAC_NAME_2_OID,
    AES_GMAC_OID_2_NAME,
    HMAC_SHA_OID_2_NAME,
    SHA_OID_2_NAME,
    SUPPORTED_SIG_MAC_OIDS,
    SYMMETRIC_PROT_ALGO,
    get_alg_oid_from_key_hash,
    get_hash_from_signature_oid,
    sha_alg_name_to_oid,
)
from suiteenums import ProtectionAlgorithm
from typingutils import PrivateKey, PrivSignCertKey


def _prepare_password_based_mac_parameters(
    salt: Optional[bytes] = None, iterations=1000, hash_alg="sha256"
) -> rfc9480.PBMParameter:
    """Prepare `rfc8018.PBMParameter` structure for password-based-mac protection in PKIMessage.

    :param salt: optional bytes, salt to use for the password-based-mac protection,
                 if not given, will generate 16 random bytes
    :param iterations: optional int, number of iterations of the OWF (hashing) to perform
    :param hash_alg: optional str, name of hashing algorithm to use, "sha256" by default.
    :return: `rfc9480.PBMParameter` structure.
    """
    salt = salt or os.urandom(16)

    hmac_alg_oid = sha_alg_name_to_oid(f"hmac-{hash_alg}")
    hash_alg_oid = sha_alg_name_to_oid(hash_alg)

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


def _prepare_pbmac1_parameters(
    salt: Optional[bytes] = None, iterations=100, length=32, hash_alg="sha256"
) -> rfc8018.PBMAC1_params:
    """Prepare the PBMAC1 `rfc8018.PBMAC1_params`, for `rfc9480.PKIMessage` protection, using PBKDF2 with HMAC.

    :param salt: optional bytes for uniqueness.
    :param iterations: The number of iterations to be used in the PBKDF2 key derivation function.
                       Default is 100.
    :param length: int The desired length of the derived key in bytes. Default is 32 bytes.
    :param hash_alg: str the name of the to use with HMAC. Default is "sha256".
    :return:  Populated `rfc8018.PBMAC1_params` object.
    """
    salt = salt or os.urandom(16)

    hmac_alg = sha_alg_name_to_oid(f"hmac-{hash_alg}")

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
    """Prepare a Diffie-Hellman Based MAC (Message Authentication Code) parameter structure.

    The structure uses a One-Way Hash Function (OWF) to hash the Diffie-Hellman (DH) shared secret to derive a key,
    which is then used to compute the Message Authentication Code (MAC) with the specified MAC algorithm.

    :param hash_alg: A string representation the hash algorithm to be used for the
                     one-way-function (OWF). Default is "sha1"
    :return: A `rfc4210.DHBMParameter` object populated with the algorithm identifiers for the
             specified hash and MAC algorithm.
    """
    param = rfc9480.DHBMParameter()

    alg_id_owf = rfc5280.AlgorithmIdentifier()
    alg_id_mac = rfc5280.AlgorithmIdentifier()

    alg_id_owf["algorithm"] = sha_alg_name_to_oid(hash_alg)
    alg_id_owf["parameters"] = univ.Null()

    alg_id_mac["algorithm"] = sha_alg_name_to_oid(f"hmac-{hash_alg}")
    alg_id_mac["parameters"] = univ.Null()

    param["owf"] = alg_id_owf
    param["mac"] = alg_id_mac
    return param


@not_keyword
def add_cert_to_pkimessage_used_by_protection(
    pki_message: rfc9480.PKIMessage,
    private_key: PrivateKey,
    certificate: Optional[x509.Certificate] = None,
    sign_key: Optional[PrivSignCertKey] = None,
    issuer_cert: Optional[x509.Certificate] = None,
):
    """Ensure that `extraCerts` of a signature-protected `rfc9480.PKIMessage` starts with a CMP-Protection certificate.

    If a certificate is provided, it checks that the first certificate matches the provided CMP-Protection certificate.
    If no `certificate` is provided, it generates a new one using the given `private_key`
    and optional `sign_key` and `issuer_cert`.

    :param pki_message: `rfc9480.PKIMessage` to which the certificate protection is to be applied.
    :param private_key:  The private key used to signing the structure.
    :param certificate: optional `cryptography.x509.Certificate` object. A certificate to use as
                        the CMP-Protection certificate.
    :param sign_key:    optional PrivSignCertKey A signing key to use for generating a new certificate.
    :param issuer_cert: optional `cryptography.x509.Certificate`
                        Certificate used for generating a new certificate if no `certificate` is provided.
    :raises ValueError: If the first certificate in `extraCerts` is not the CMP-Protection certificate as specified in
        RFC 9483, Section 3.3, or if there is a signature verification failure
    :return: None
    """
    if certificate is not None:
        if not pki_message["extraCerts"].hasValue():
            asn1_cert = certutils.parse_certificate(certificate.public_bytes(serialization.Encoding.DER))
            pki_message["extraCerts"] = prepare_extra_certs([asn1_cert])
        else:
            first_cert = x509.load_der_x509_certificate(encode_to_der(pki_message["extraCerts"][0]))
            #  RFC 9483, Section 3.3, the first certificate must be the CMP-Protection certificate.
            if first_cert != certificate:
                other_cert = certutils.parse_certificate(certificate.public_bytes(serialization.Encoding.DER))
                logging.warning(
                    f"First Cert in PKIMessage: {pki_message['extraCerts'][0].prettyPrint()}"
                    f"Certificate Provided: {other_cert.prettyPrint()}"
                )
                raise ValueError(
                    "The first certificate must be the CMP-Protection certificate as specified "
                    "in RFC 9483, Section 3.3."
                )

    elif not pki_message["extraCerts"].hasValue():
        # contains no Certificates so a new one is added.
        certificate = cryptoutils.generate_certificate(
            private_key=private_key, sign_key=sign_key, issuer_cert=issuer_cert
        )
        raw = certificate.public_bytes(serialization.Encoding.DER)
        certificate = certutils.parse_certificate(raw)
        pki_message["extraCerts"] = prepare_extra_certs([certificate])

    else:
        # The first certificate must be a CMP-Protection Certificate.
        # To ensure the sign key for the PKIMessage structure and
        # public key in the certificate matches. the following `data` is signed.
        data = b"test_if_keypair_matches"

        certificate = pki_message["extraCerts"][0]
        certificate = cmputils.encode_to_der(certificate)
        crypto_lib_cert = x509.load_der_x509_certificate(certificate)
        signature = cryptoutils.sign_data(key=private_key, data=data, hash_alg=crypto_lib_cert.signature_hash_algorithm)

        try:
            certutils.verify_signature(
                public_key=certificate.public_key(),
                signature=signature,
                data=data,
                hash_alg=certificate.signature_hash_algorithm,
            )
        except InvalidSignature:
            raise ValueError("The first certificate must be the CMP-Protection certificate, see RFC 9483, Section 3.3.")


def _compute_symmetric_protection(pki_message: rfc9480.PKIMessage, password: bytes) -> bytes:
    """Compute the `rfc9480.PKIMessage` protection.

    :param pki_message: `rfc9480.PKIMessage` object to protect.
    :param password: bytes a symmetric password to protect the message.
    :return: bytes the computed signature.
    """
    protected_part = rfc9480.ProtectedPart()
    protected_part["header"] = pki_message["header"]
    protected_part["body"] = pki_message["body"]

    protection_type_oid = pki_message["header"]["protectionAlg"]["algorithm"]
    prot_params = pki_message["header"]["protectionAlg"]["parameters"]

    encoded = encoder.encode(protected_part)

    if protection_type_oid in HMAC_SHA_OID_2_NAME:
        hash_alg = HMAC_SHA_OID_2_NAME[protection_type_oid].split("-")[1]
        return cryptoutils.compute_hmac(data=encoded, key=password, hash_alg=hash_alg)

    if protection_type_oid == rfc8018.id_PBMAC1:
        salt = prot_params["keyDerivationFunc"]["parameters"]["salt"]["specified"].asOctets()
        iterations = int(prot_params["keyDerivationFunc"]["parameters"]["iterationCount"])
        length = int(prot_params["keyDerivationFunc"]["parameters"]["keyLength"])

        hmac_alg = prot_params["messageAuthScheme"]["algorithm"]

        # gets the sha-Algorithm
        hash_alg = HMAC_SHA_OID_2_NAME[hmac_alg].split("-")[1]

        return compute_pbmac1(
            data=encoded,
            key=password,
            iterations=iterations,
            salt=salt,
            length=length,
            hash_alg=hash_alg,
        )

    if protection_type_oid == rfc4210.id_PasswordBasedMac:
        salt = prot_params["salt"].asOctets()
        iterations = int(prot_params["iterationCount"])

        hash_alg = HMAC_SHA_OID_2_NAME[prot_params["mac"]["algorithm"]].split("-")[1]
        return compute_password_based_mac(
            data=encoded, key=password, iterations=iterations, salt=salt, hash_alg=hash_alg
        )

    if protection_type_oid in AES_GMAC_OID_2_NAME:
        nonce = prot_params["nonce"].asOctets()
        password = password.encode("utf-8") if isinstance(password, str) else password
        return compute_gmac(data=encoded, key=password, iv=nonce)

    if protection_type_oid == rfc8018.id_PBMAC1:
        salt = prot_params["keyDerivationFunc"]["parameters"]["salt"]["specified"].asOctets()
        iterations = int(prot_params["keyDerivationFunc"]["parameters"]["iterationCount"])
        length = int(prot_params["keyDerivationFunc"]["parameters"]["keyLength"])

        outer_params: rfc8018.PBKDF2_params = prot_params["keyDerivationFunc"]["parameters"]
        hmac_alg = outer_params["messageAuthScheme"]["algorithm"]

        hash_alg = HMAC_SHA_OID_2_NAME[hmac_alg].split("-")[1]

        return compute_pbmac1(
            data=encoded,
            key=password,
            iterations=iterations,
            salt=salt,
            length=length,
            hash_alg=hash_alg,
        )

    if rfc9480.id_DHBasedMac:
        hash_alg: str = SHA_OID_2_NAME[prot_params["owf"]["algorithm"]]
        password = compute_hash(alg_name=hash_alg, data=password)
        return cryptoutils.compute_hmac(key=password, data=encoded)

    raise ValueError(f"Unsupported Symmetric Mac Protection! : {protection_type_oid}")


def _compute_pkimessage_protection(
    pki_message: rfc9480.PKIMessage,
    password: Optional[str] = None,
    private_key: Optional[PrivateKey] = None,
    certificate: Optional[x509.Certificate] = None,
    sign_key: Optional[PrivSignCertKey] = None,
    signer_cert: Optional[x509.Certificate] = None,
    exclude_cert: bool = False,
) -> bytes:
    """Compute the protection for a `rfc9480.PKIMessage` based on the specified protection algorithm.

    :param pki_message: `rfc9480.PKIMessage` object to compute the protection for.
    :param password: A string representing a shared secret or a server private key for DHBasedMac.
    :param private_key: optional PrivateKey used for signature-based protection or DH-based MAC computation.
    :param certificate:  A certificate used as the CMP-Protection certificate for signature-based protection.
                         if signature is the protection type includes a self-signed certificate.
    :param sign_key:  optional PrivSignCertKey: A signing key used for generating a new certificate if needed.
    :param exclude_cert:  bool exclude generating a certificate for signature protection.
    :raises:
        ValueError: If the protection algorithm OID is not supported or required parameters are not provided
                   or is the first certificate in the `PKIMessage.extraCerts` is not the signature certificate.
    :returns:
        bytes: The computed protection value for the `PKIMessage`.
    """
    protected_part = rfc9480.ProtectedPart()
    protected_part["header"] = pki_message["header"]
    protected_part["body"] = pki_message["body"]

    protection_type_oid = pki_message["header"]["protectionAlg"]["algorithm"]
    encoded = encoder.encode(protected_part)

    if protection_type_oid == rfc9480.id_DHBasedMac:
        shared_secret = cryptoutils.do_dh_key_exchange_password_based(password=password, peer_key=private_key)
        return _compute_symmetric_protection(pki_message=pki_message, password=shared_secret)

    if protection_type_oid in SYMMETRIC_PROT_ALGO:
        return _compute_symmetric_protection(pki_message=pki_message, password=password)

    if protection_type_oid in SUPPORTED_SIG_MAC_OIDS:
        if protection_type_oid in {rfc9481.id_Ed25519, rfc9481.id_Ed448}:
            hash_alg = None
        else:
            # gets sha Algorithm.
            hash_alg = get_hash_from_signature_oid(oid=protection_type_oid).split("-")[1]

        protection_value = cryptoutils.sign_data(data=encoded, key=private_key, hash_alg=hash_alg)

        if not exclude_cert:
            add_cert_to_pkimessage_used_by_protection(
                pki_message=pki_message,
                private_key=private_key,
                certificate=certificate,
                sign_key=sign_key,
                issuer_cert=signer_cert,
            )
        return protection_value

    raise ValueError(f"Unsupported PKIMessage Protection oid: {protection_type_oid}")


def _prepare_pki_message_protection_field(
    pki_message: rfc9480.PKIMessage, protection: str, private_key: Optional[PrivateKey] = None, **params
) -> rfc9480.PKIMessage:
    """Prepare the protection for the PKIMessage algorithm.

    :param pki_message: `rfc9480.PKIMessage` to protect.
    :param protection: A string representing the type of protection.
    :param private_key: A`cryptography` `PrivateKey` object. For signing or DHBasedMac.
    :param **params: Additional parameters that may be required for specific protection types,
        such as 'iterations', 'salt', 'length', or 'hash_alg'.

    :return: Protected `rfc9480.PKIMessage` object.
    """
    prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 1))

    protection_type = ProtectionAlgorithm.get(protection)

    if protection_type == ProtectionAlgorithm.HMAC:
        prot_alg_id["algorithm"] = rfc8018.id_hmacWithSHA256
        prot_alg_id["parameters"] = univ.Null()

    elif protection_type == ProtectionAlgorithm.PBMAC1:
        prot_alg_id["algorithm"] = rfc8018.id_PBMAC1
        if not params.get("salt"):
            salt = os.urandom(16)
        else:
            salt = bytes.fromhex(params.get("salt"))

        pbmac1_parameters = _prepare_pbmac1_parameters(
            salt=salt,
            iterations=int(params.get("iterations", 262144)),
            length=int(params.get("length", 32)),
            hash_alg=params.get("hash_alg", "sha512"),
        )
        prot_alg_id["parameters"] = pbmac1_parameters

    elif protection_type == ProtectionAlgorithm.PASSWORD_BASED_MAC:
        if not params.get("salt"):
            salt = os.urandom(16)
        else:
            salt = bytes.fromhex(params.get("salt"))
        prot_alg_id["algorithm"] = rfc4210.id_PasswordBasedMac
        pbm_parameters = _prepare_password_based_mac_parameters(
            salt=salt, iterations=int(params.get("iterations", 1000)), hash_alg=params.get("hash_alg", "sha256")
        )
        prot_alg_id["parameters"] = pbm_parameters

    elif protection_type == ProtectionAlgorithm.AES_GMAC:
        if not params.get("salt"):
            nonce = os.urandom(12)
        else:
            nonce = bytes.fromhex(params.get("salt"))
        prot_alg_id["algorithm"] = AES_GMAC_NAME_2_OID[protection]
        prot_alg_id["parameters"] = rfc9044.GCMParameters()
        prot_alg_id["parameters"]["nonce"] = univ.OctetString(nonce)

    elif protection_type == ProtectionAlgorithm.SIGNATURE:
        if private_key is None:
            raise ValueError("private_key must be provided for PKIMessage structure Protection")

        if not isinstance(private_key, PrivateKey):
            raise ValueError(f"private_key must be an instance of PrivateKey, but is of type: {type(private_key)}.")

        prot_alg_id["algorithm"] = get_alg_oid_from_key_hash(key=private_key, hash_alg=params.get("hash_alg", "sha256"))
        prot_alg_id["parameters"] = univ.Null()

    elif protection_type == ProtectionAlgorithm.DH:
        prot_alg_id["algorithm"] = rfc9480.id_DHBasedMac
        prot_alg_id["parameters"] = _prepare_dh_based_mac(hash_alg=params.get("hash_alg", "sha1"))

    else:
        raise ValueError(f"Unknown or Unsupported PKIMessage Protection: {protection}")

    pki_message["header"]["protectionAlg"] = prot_alg_id

    return pki_message


# TODO add decorator for salt
def protect_pki_message(  # noqa: D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    protection: str,
    password: Optional[str, bytes] = None,
    private_key: Optional[PrivateKey] = None,
    certificate: Optional[x509.Certificate] = None,
    sign_key: Optional[PrivSignCertKey] = None,
    exclude_cert: bool = False,
    **params,
) -> rfc9480.PKIMessage:
    """Prepare the PKI protection for the PKIMessage.

    Includes:
         - Checks if the certificate is the first in the `extraCerts` field!
              If provided, otherwise adds a certificate! Unless `exclude_cert` is set to `True`
    Excludes:
         - Certificate checks!

    Arguments:
    ---------
    - `pki_message`: `rfc9480.PKIMessage` where the body and header are set.
    - `protection`: string representing the type of protection.
    - `password`: string representing a shared secret (default is None).
    - `private_key`: `cryptography` `PrivateKey` object, used for signing or DHBasedMac (default is None).
    - `certificate`: `rfc9480.CMPCertificate` or  `cryptography` `x509.Certificate` object.
                     The certificate used for verifying of the signature. If provided.
    - `exclude_cert`: bool indicates if for signing a certificate should be added.
                      used for negative testing.
    - `**params`:
                 salt: bytes used for pbmac1, pbm or aes-gmac.
                 iterations: (str, int)  Number of iterations to be used for KDF.
                 length: (str, int) Length of the output for pbmac1.
                 hash_alg: str name of the owf to be used. ex: "sha256".

    Returns:
    -------
    - `rfc9480.PKIMessage`: The PKIMessage object with the applied protection.

    Raises:
    ------
    - ValueError | If the `PKIMessage` body is not set or is not a value. |

    Example:
    -------
    | ${prot_msg}= | Protect PKI Message | ${PKI_MESSAGE} | pbmac1    | ${SECRET}       |
    | ${prot_msg}= | Protect PKI Message | ${PKI_MESSAGE} | aes-gmac  | ${SECRET}       |
    | ${prot_msg}= | Protect PKI Message | ${PKI_MESSAGE} | signature | private_key=${KEY}  |
    | ${prot_msg}= | Protect PKI Message | ${PKI_MESSAGE} | dh | private_key=${KEY}  password={PASSWORD}  |

    """
    if not pki_message["body"].isValue:
        raise ValueError("PKI Message body needs to be a value!")

    if (password or private_key) is None:
        raise ValueError("Either a password, private key must be provided for PKIMessage structure Protection")

    pki_message = _prepare_pki_message_protection_field(
        pki_message=pki_message, protection=protection, private_key=private_key, **params
    )

    protection_value = _compute_pkimessage_protection(
        pki_message=pki_message,
        password=password,
        private_key=private_key,
        certificate=certificate,
        sign_key=sign_key,
        exclude_cert=exclude_cert,
    )
    wrapped_protection = (
        rfc9480.PKIProtection()
        .fromOctetString(protection_value)
        .subtype(explicitTag=Tag(tagClassContext, tagFormatSimple, 0))
    )
    pki_message["protection"] = wrapped_protection
    return pki_message


def verify_pki_message_protection(  # noqa: D417
    pki_message: rfc9480.PKIMessage,
    private_key: Optional[PrivateKey] = None,
    password: Optional[Union[bytes, str]] = None,
):
    """Verify the PKIProtection of the given `rfc9480.PKIMessage`.

    Arguments:
    ---------
    - `pki_message`: The `PKIMessage` object whose protection needs to be verified.
    - `private_key`: The private key of the server or client. For Diffie-Hellman-based protection, this is needed to
                     compute the shared secret. If the protection algorithm is signature-based, the private key is
                     not required.
    - `password`: The shared secret for symmetric or Diffie-Hellman-based protection. This is used for computing the
                  derived keys for verifying the protection value.

    Raises:
    ------
        - InvalidSignature: If the signature-based protection verification fails due to a mismatched signature.
        - ValueError: If the protection algorithm is unsupported or if the computed protection value does not match the
                    expected value, indicating tampering or data corruption.

    Returns:
    -------
        - None

    Example:
    -------
    | Verify PKI Message Protection | ${PKI_MESSAGE} | ${private_key}    | ${SECRET}    |
    | Verify PKI Message Protection | ${PKI_MESSAGE} | ${private_key}    |
    | Verify PKI Message Protection | ${PKI_MESSAGE} | password=${SECRET}    |

    Note:
    ----
        - If the `PKIMessage` uses a Diffie-Hellman-based MAC (`DHBasedMac`) for protection, both the `private_key`
          and a password must be provided.
        - If the protection algorithm is signature-based, the certificate used for signing must be the first certificate
          in the `extraCerts` field of the `PKIMessage`, as per RFC 9483, Section 3.3. (is tested)

    """
    protection_value: bytes = pki_message["protection"].asOctets()

    prot_alg_id = pki_message["header"]["protectionAlg"]
    protection_type_oid = prot_alg_id["algorithm"]

    # Extract protected part for verification
    protected_part = rfc9480.ProtectedPart()
    protected_part["header"] = pki_message["header"]
    protected_part["body"] = pki_message["body"]
    encoded: bytes = encoder.encode(protected_part)

    if protection_type_oid == rfc9480.id_DHBasedMac:
        password = cryptoutils.do_dh_key_exchange_password_based(password=password, peer_key=private_key)
        expected_protection_value = _compute_symmetric_protection(pki_message, password)

    elif protection_type_oid in SYMMETRIC_PROT_ALGO:
        expected_protection_value = _compute_symmetric_protection(pki_message, password)

    elif protection_type_oid in SUPPORTED_SIG_MAC_OIDS:
        certificate = pki_message["extraCerts"][0]
        certificate = cmputils.encode_to_der(certificate)
        certificate = x509.load_der_x509_certificate(certificate)

        # Raises an InvalidSignature Exception.
        certutils.verify_signature(
            data=encoded,
            signature=protection_value,
            public_key=certificate.public_key(),
            hash_alg=certificate.signature_hash_algorithm,
        )
        return

    else:
        raise ValueError(f"Unsupported protection algorithm for verification : {protection_type_oid}.")

    if protection_value != expected_protection_value:
        raise ValueError(
            f"PKIMessage Protection should be:" f" {expected_protection_value.hex()} but was: {protection_value.hex()}"
        )
