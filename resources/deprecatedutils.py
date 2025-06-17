# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Deprecated functions to build a certificate with the `cryptography` library.

As a fallback, if there is an error with `pyasn1`.
"""

import datetime
import enum
import os
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.x509 import AuthorityInformationAccess, ExtensionNotFound, UniformResourceIdentifier, extensions
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc9480, rfc9481
from robot.api.deco import keyword, not_keyword

import resources.prepareutils
from resources import keyutils
from resources.asn1utils import get_set_bitstring_names, is_bit_set
from resources.certutils import _convert_to_crypto_lib_cert
from resources.convertutils import ensure_is_sign_key, ensure_is_trad_sign_key
from resources.cryptoutils import compute_aes_cbc
from resources.oid_mapping import hash_name_to_instance
from resources.typingutils import PrivateKey, PublicKey, SignKey, Strint, TradSignKey


def _build_cert(
    public_key,
    issuer: x509.Name,
    subject: Optional[x509.Name] = None,
    serial_number: Optional[int] = None,
    days: Strint = 365,
    *,
    not_valid_before: Optional[datetime.datetime] = None,
) -> x509.CertificateBuilder:
    """Create a `cryptography.x509.CertificateBuilder` using a public key, issuer, subject, and a validity period.

    :param public_key: `cryptography.hazmat.primitives.asymmetric` public key to associate with the certificate.
    :param issuer: issuer's distinguished name.
    :param subject: optional, subject's distinguished name.
    :param serial_number: serial number of the certificate. If not provided, will be set to a random number.
    :param days: number of days for which the certificate is valid. Defaults to 365 days.
    :param not_valid_before: start date and time when the certificate becomes valid (defaults to the current time).

    :return: `cryptography.x509.CertificateBuilder`
    """
    if subject is None:
        subject = issuer

    if serial_number is None:
        serial_number = x509.random_serial_number()

    days = int(days)

    # TODO change in the future. may allow str
    if not not_valid_before:
        not_valid_before = datetime.datetime.now() - datetime.timedelta(days=1)

    # Create the certificate builder
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_before + datetime.timedelta(days=days))
    )
    return cert_builder


def _sign_crl_builder(
    crl_builder: x509.CertificateRevocationListBuilder,
    sign_key: Optional[TradSignKey],
    hash_alg: Optional[str] = "sha256",
):
    """Sign a `cryptography.x509.CertificateRevocationListBuilder` object.

    :param crl_builder: `cryptography.x509.CertificateRevocationListBuilder`
    :param sign_key: The private key to sign the certificate.
    :param hash_alg: The name of the hash function to use for signing the certificate. Defaults to "sha256".
    :return: The signed `cryptography.x509.CertificateRevocationList` object.
    """
    hash_instance = None
    if hash_alg is not None:
        hash_instance = hash_name_to_instance(hash_alg)  # type: ignore

    if isinstance(sign_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return crl_builder.sign(sign_key, algorithm=None)

    if hash_instance is None:
        raise ValueError(f"`hash_alg` must be set sign the CRL with a: {type(sign_key)} key.")

    return crl_builder.sign(private_key=sign_key, algorithm=hash_instance)  # type: ignore


def _sign_cert_builder(
    cert_builder: x509.CertificateBuilder, sign_key: Optional[TradSignKey], hash_alg: Optional[str] = None
) -> x509.Certificate:
    """Sign a `cryptography.x509.CertificateBuilder` object with a provided key to sign and a hash algorithm.

    :param cert_builder: `cryptography.x509.CertificateBuilder`
    :param sign_key: A traditional signing key object (e.g., RSA, ECDSA) to sign the certificate.
    :param hash_alg: optional str the name of the hash function to use for signing the certificate.
    :return: a `cryptography.x509.Certificate` object
    """
    if isinstance(sign_key, ec.EllipticCurvePrivateKey):
        hash_instance = hash_name_to_instance(hash_alg)  # type: ignore
        certificate = cert_builder.sign(private_key=sign_key, algorithm=hash_instance)  # type: ignore

    elif isinstance(sign_key, rsa.RSAPrivateKey):
        hash_instance = hash_name_to_instance(hash_alg)  # type: ignore
        certificate = cert_builder.sign(
            private_key=sign_key,
            algorithm=hash_instance,  # type: ignore
            rsa_padding=padding.PKCS1v15(),
        )

    elif isinstance(sign_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        certificate = cert_builder.sign(private_key=sign_key, algorithm=None)

    else:
        raise ValueError(f"Unsupported to sign a certificate!: {type(sign_key)}")

    return certificate


def _add_extension(
    cert_builder: x509.CertificateBuilder,
    basic_constraint: Optional[Tuple[bool, Optional[int]]] = None,
    key_usage: Optional[str] = None,
    ski: Optional[PublicKey] = None,
    ocsp_url: Optional[str] = None,
    critical: bool = True,
) -> x509.CertificateBuilder:
    """Add Certificate extension to a certificate builder object.

    :param cert_builder: `x509.CertificateBuilder` object.
    :param basic_constraint: optional tuple (bool, (None, int))
    :param key_usage: optional tuple (str) always critical.
    :param ski: if present the public key.
    :param ocsp_url: the ocsp url to add to the certificate.
    :param critical: if the extension is critical or not. Defaults to `True`.
    :return: the builder object with applied extensions.
    """
    if basic_constraint is not None:
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=basic_constraint[0], path_length=basic_constraint[1]), critical=critical
        )

    if key_usage is not None:
        cert_builder = cert_builder.add_extension(KeyUsageEnum.get_obj(key_usage), critical=critical)

    if ski is not None:
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ski),  # type: ignore
            critical=critical,
        )

    if ocsp_url is not None:
        cert_builder = cert_builder.add_extension(
            AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,  # type: ignore
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]
            ),
            critical=critical,
        )

    return cert_builder


def _build_certificate(  # noqa D417 undocumented-param
    private_key: Optional[Union[str, PrivateKey]] = None,
    common_name: str = "CN=Hans",
    hash_alg: str = "sha256",
    ski: Optional[bool] = False,
    **params,
) -> Tuple[x509.Certificate, PrivateKey]:
    """Build an X.509 certificate that can be customized based on provided parameters.

    Arguments:
    ---------
    - `private_key` (Optional[Union[str, PrivateKey]]): A optional private key object.
    - `common_name`: The common name for the certificate subject, in OpenSSL notation. Defaults to "CN=Hans".
    - `hash_alg`: The hash algorithm for signing, Defaults to "sha256". If the key is a (ed25519 or ed448)
    not used like supposed to.
    - `ski`: If `True`, includes the SubjectKeyIdentifier (ski) extension in the certificate.

    **params (Additional optional parameters for customization):
    ---------------------------------------------------
    - `sign_key` (PrivateKey): The private key used to sign the certificate.
    - `issuer_cert` (x509.certificate): The issuer’s certificate. If not provided, the certificate is self-signed.
    - `serial_number` (int, str): The serial number for the certificate. If omitted, a random number is generated.
    - `days` (int, str): Number of days for certificate validity, starting from `not_valid_before`. Defaults to 365.
    - `not_valid_before` (datetime.datetime): Start date of the certificate’s validity. Defaults to now.
    - `not_valid_after` (datetime.datetime): End date of validity. Overrides `days` if provided.
    - `is_ca` (bool): Indicates if the certificate is for a CA (Certificate Authority). Defaults to `False`.
    - `path_length` (int): The maximum path length for CA certificates.
    - `key_alg` (str): Algorithm for key generation (e.g., "ecdsa"). Defaults to "ecdsa".
    - `key_usage` (str): Specific key usage (e.g., "digitalSignature") to set on the certificate.

    Returns:
    -------
        - A tuple containing the generated `cryptography.X509.Certificate` and the private key.

    Raises:
    ------
    - `ValueError`: If the provided key is not allowed to sign a certificate.

    Examples:
    --------
    | ${certificate}, ${private_key}= | Build Certificate | keyAlg=ecdsa | common_name="CN=Example" |
    | ${certificate}, ${private_key}= | Build Certificate | private_key=${key} \
    | serial_number=12345 | days=730 |
    | ${certificate}, ${private_key}= | Build Certificate | private_key=${key} \
    | sign_key=${sign_key} | issuer_cert=${cert} |

    """
    issuer_cert = params.get("issuer_cert")
    issuer = issuer_cert.subject if issuer_cert else resources.prepareutils.parse_common_name_from_str(common_name)
    subject = resources.prepareutils.parse_common_name_from_str(common_name)

    key = private_key or keyutils.generate_key(params.get("key_alg", "ecdsa"))
    private_key = ensure_is_sign_key(key)

    cert_builder = _build_cert(
        public_key=private_key.public_key(),
        issuer=issuer,
        subject=subject,
        serial_number=params.get("serial_number"),
        days=params.get("days", 365),
        not_valid_before=params.get("not_valid_before"),
    )

    basic_constraint: Optional[Tuple[bool, Optional[int]]] = None
    if params.get("is_ca") is not None:
        path_length = None
        if params.get("path_length") is not None:
            path_length = int(params.get("path_length"))  # type: ignore

        basic_constraint = (params.get("is_ca", False), path_length)

    ski = private_key.public_key() if ski else None  # type: ignore
    cert_builder = _add_extension(
        cert_builder=cert_builder,
        key_usage=params.get("key_usage"),
        basic_constraint=basic_constraint,
        ski=ski,  # type: ignore
    )
    sign_key = params.get("sign_key", private_key)
    cert = _sign_cert_builder(cert_builder=cert_builder, sign_key=sign_key, hash_alg=hash_alg)

    return cert, private_key


def _get_crl_dpn(cert: x509.Certificate) -> Union[bytes, None]:
    """Get the CRL Distribution Points extension, DER-encoded, from a `x509.Certificate` object.

    :param cert: the certificate to extract the extension from.
    :return: None if not present or bytes.
    """
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        # returned as DER encoded.
        crl_der = crl_ext.value.public_bytes()
        return crl_der

    except x509.ExtensionNotFound:
        return None


def _get_issuing_distribution_point(cert: x509.Certificate) -> Union[bytes, None]:
    """Get the Issuing Distribution Point extension, DER-encoded, from a `x509.Certificate` object.

    :param cert: the certificate to extract the extension from.
    :return: None if not present or bytes.
    """
    try:
        idp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
        # returned as DER encoded.
        issuing_distribution_point = idp_ext.value.public_bytes()
        return issuing_distribution_point

    except x509.ExtensionNotFound:
        return None


class KeyUsageEnum(enum.Enum):
    """KeyUsage for a Certificate to identify the use case of a Certificate."""

    # pylint: disable=invalid-name
    # to allow correctly rfc names.

    digitalSignature = "digital_signature"
    nonRepudiation = "content_commitment"
    keyEncipherment = "key_encipherment"
    dataEncipherment = "data_encipherment"
    keyAgreement = "key_agreement"
    keyCertSign = "key_cert_sign"
    cRLSign = "crl_sign"
    encipherOnly = "encipher_only"
    decipherOnly = "decipher_only"

    @classmethod
    def get_obj(cls, key_usage: str) -> extensions.KeyUsage:
        """Create a `cryptography.x509.KeyUsage` extension object.

        :param key_usage: Comma-separated key usage attributes in a human-readable format.
        :return: The `cryptography.x509.KeyUsage` object.
        :raises ValueError: If any provided name does not match an enum member.
        """
        # Initialize all key usage parameters to `False`
        key_usage_params = {member.value: False for member in cls}
        usage_names = [name.strip() for name in key_usage.split(",") if name.strip()]

        for usage_name in usage_names:
            if usage_name in cls.__members__:
                param_name = cls.__members__[usage_name].value
                key_usage_params[param_name] = True
            else:
                valid_names = list(cls.__members__.keys())
                raise ValueError(f"Invalid usage name: '{usage_name}'. Valid names are: {valid_names}.")

        return extensions.KeyUsage(**key_usage_params)

    @staticmethod
    def validate(expected_usage: str, given_usage: rfc5280.KeyUsage, same_vals: bool) -> bool:
        """Validate if the expected key usage attributes are inside the provided `KeyUsage` object.

        :param expected_usage: The expected key usage attributes, comma-separated in a human-readable format.
        :param given_usage: The found `KeyUsage` object inside a certificate.
        :param same_vals: If set, the attributes must be equal.
        :return: `True` if all expected key usage attributes are set; `False`
        if unequal, but expected to be equal, or if not all attributes are set.
        """
        names = get_set_bitstring_names(given_usage)
        if same_vals:
            # to ensure same names are used.
            usage_obj = rfc5280.KeyUsage(expected_usage)
            expected_names = get_set_bitstring_names(usage_obj)  # type: ignore
            return names == expected_names

        vals = [val.strip() for val in expected_usage.split(",")]
        is_set = 0
        for x in vals:
            is_set += is_bit_set(given_usage, x, exclusive=False)

        return len(vals) == is_set


@not_keyword
def x509_to_pyasn1_extensions(
    crypto_lib_obj: Union[x509.Certificate, x509.CertificateSigningRequest],
    extn_obj: Optional[rfc5280.Extensions] = None,
) -> rfc5280.Extensions:
    """Convert x509.Certificate extensions into a pyasn1 `rfc5280.Extensions` structure.

    :param crypto_lib_obj: A certificate or certificate signing request (CSR) from the `cryptography` library.
    :param extn_obj: Optional existing `rfc5280.Extensions` object to which new extensions
                     will be appended. If not provided, a new `rfc5280.Extensions` object will be created.
    :return: A `pyasn1` rfc5280.Extensions object containing the converted extensions.
    """
    if extn_obj is None:
        extn_obj = rfc5280.Extensions()

    for ext in crypto_lib_obj.extensions:
        pyasn1_extension = rfc5280.Extension()
        pyasn1_extension["extnID"] = univ.ObjectIdentifier(ext.oid.dotted_string)
        pyasn1_extension["critical"] = ext.critical
        ext_value_der = ext.value.public_bytes()
        pyasn1_extension["extnValue"] = univ.OctetString(ext_value_der)
        extn_obj.append(pyasn1_extension)

    return extn_obj


def generate_csr(  # noqa D417 undocumented-param
    common_name: Optional[str] = None, subject_alt_name: Optional[str] = None
):
    """Generate a CSR based on the given common name and subjectAltName.

    Arguments:
    ---------
        - `common name`: Optional string in OpenSSL notation, Defaults to "C=DE,ST=Bavaria,
        L=Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
        - `subjectAltName`: Optional string, list of subject alternative names, e.g.,
                           "example.com,www.example.com,pki.example.com"

    Returns:
    -------
        - The x509.CertificateSigningRequestBuilder object.

    """
    csr = x509.CertificateSigningRequestBuilder()

    common_name = (
        common_name or "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    )

    x509_name = resources.prepareutils.parse_common_name_from_str(common_name)
    csr = csr.subject_name(x509_name)
    # this produces something like
    # csr = csr.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CMP Lab"),
    #     ]))

    if subject_alt_name:
        # if there are any subjectAltNames given, process the list into objects that the CSRBuilder can deal with
        items = subject_alt_name.strip().split(",")
        dns_names = [x509.DNSName(item) for item in items]
        csr = csr.add_extension(x509.SubjectAlternativeName(dns_names), critical=False)

        # the logic above will essentially boil down to a call like this one:
        # csr = csr.add_extension(
        #     x509.SubjectAlternativeName([
        #     x509.DNSName(u"mysite.com"),
        #     x509.DNSName(u"www.mysite.com"),
        #     x509.DNSName(u"subdomain.mysite.com"),
        # ]), critical=False)

    return csr


def sign_csr(  # noqa D417 undocumented-param
    csr: x509.CertificateSigningRequestBuilder, key: TradSignKey, hash_alg: str = "sha256"
):
    """Sign a CSR with a given key, using a specified hashing algorithm.

    Arguments:
    ---------
       - `csr`: `x509.CertificateSigningRequestBuilder`, the CSR to be signed.
       - `key`: Private key used for the signature.
       - `hash_alg`: Optional string, a hashing algorithm name (e.g., "sha256").

    Returns:
    -------
       - The PEM-encoded CSR as bytes.

    """
    csr_out = _sign_csr_builder(csr, key, hash_alg=hash_alg)
    return csr_out.public_bytes(serialization.Encoding.PEM)


@keyword(name="Generate Signed CSR")
def generate_signed_csr2(  # noqa D417 undocumented-param
    common_name: str, key: Union[TradSignKey, str, None] = None, **params
) -> Tuple[bytes, SignKey]:
    """Generate signed CSR for a given common name (CN).

    If a key is not provided, a new RSA key is generated. If a string is provided, it is used as the key generation
    algorithm (e.g., "rsa") with additional parameters. If a `PrivateKey` object is provided, it is used directly.

    Arguments:
    ---------
        - `common_name`: The common name (CN) to include in the CSR.
        - `key`: Optional. The private key to use for signing the CSR. Can be one of:
            - A `PrivateKey` object from the cryptography library.
            - A string representing the key generation algorithm (e.g., "rsa").
            As default will be a new RSA key generated.
        - `params`: Additional keyword arguments to customize key generation when `key` is a string.

    Returns:
    -------
        - A Tuple the signed CSR in bytes and the corresponding private key.

    Raises:
    ------
        - `ValueError`: If the provided key is neither a valid key generation algorithm string nor
        a `PrivateKey` object.

    Examples:
    --------
    | ${csr_signed} ${private_key}= | Generate Signed CSR | CN=${cm} | rsa | length=2048 |
    | ${csr_signed}  ${private_key}= | Generate Signed CSR | CN=${cm} | ed25519 |

    """
    if key is None:
        key = keyutils.generate_key(algorithm="rsa")  # type: ignore
    elif isinstance(key, str):
        key = keyutils.generate_key(algorithm=key, **params)  # type: ignore
    elif isinstance(key, TradSignKey):
        pass
    else:
        raise ValueError("`key` must be either an algorithm name or a private key")

    sign_key = ensure_is_trad_sign_key(key)
    csr = generate_csr(common_name=common_name)
    csr_signed = sign_csr(csr=csr, key=sign_key)

    return csr_signed, sign_key


def _sign_csr_builder(
    csr_builder: x509.CertificateSigningRequestBuilder,
    sign_key: Optional[TradSignKey],
    hash_alg: Optional[str] = None,
) -> x509.CertificateSigningRequest:
    """Sign a `cryptography.x509.CertificateBuilder` object with a provided key to sign and a hash algorithm.

    :param csr_builder: `cryptography.x509.CertificateSigningRequestBuilder`
    :param sign_key: `cryptography.hazmat.primitives.asymmetric PrivSignCertKey` object.
    :param hash_alg: optional str the name of the hash function to use for signing the certificate.
    :return: a `cryptography.x509.CertificateSigningRequest` object
    """
    if isinstance(sign_key, ec.EllipticCurvePrivateKey):
        hash_instance = hash_name_to_instance(hash_alg)  # type: ignore
        certificate = csr_builder.sign(private_key=sign_key, algorithm=hash_instance)  # type: ignore

    elif isinstance(sign_key, rsa.RSAPrivateKey):
        hash_instance = hash_name_to_instance(hash_alg)  # type: ignore
        certificate = csr_builder.sign(
            private_key=sign_key,
            algorithm=hash_instance,  # type: ignore
            rsa_padding=padding.PKCS1v15(),
        )

    elif isinstance(sign_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        certificate = csr_builder.sign(private_key=sign_key, algorithm=None)

    else:
        raise ValueError(f"Unsupported to sign a certificate!: {type(sign_key)}")

    return certificate


AES_ALG_NAME_2_OID = {
    "aes128_cbc": rfc9481.id_aes128_CBC,
    "aes192_cbc": rfc9481.id_aes192_CBC,
    "aes256_cbc": rfc9481.id_aes256_CBC,
    "aes128_wrap": rfc9481.id_aes128_wrap,
    "aes192_wrap": rfc9481.id_aes192_wrap,
    "aes256_wrap": rfc9481.id_aes256_wrap,
    #    "aes128_wrap_pad": rfc5649.id_aes128_wrap_pad,
    #    "aes192_wrap_pad": rfc5649.id_aes192_wrap_pad,
    #    "aes256_wrap_pad": rfc5649.id_aes256_wrap_pad
}


def prepare_encrypted_value(
    data: bytes,
    kek: bytes,
    cek: bytes,
    iv: Optional[bytes] = None,
    aes_cbc_size: Optional[int] = None,
    aes_wrap_size: Optional[int] = None,
):
    """Prepare an `EncryptedValue` structure using AES Key Wrap and AES-CBC.

    Generate an `EncryptedValue` structure suitable for secure data transfer.
    It uses the provided Key Encryption Key (KEK) to wrap a Content Encryption Key (CEK),
    and then encrypts the plaintext data using the CEK and AES-CBC.

    :param data: The plaintext data to encrypt (bytes).
    :param kek: The Key Encryption Key (KEK) used to wrap the CEK (bytes).
    :param cek: The Content Encryption Key (CEK) used for data encryption (bytes).
    :param iv: Optional initialization vector (IV) for AES-CBC. If not provided, a random IV of 16 bytes is generated.
    :param aes_cbc_size: Optional size (in bits) of the AES key used in AES-CBC mode. If not specified,
                         the size is determined from the length of the `cek`.
    :param aes_wrap_size: Optional size (in bits) of the AES key used for AES Key Wrap. If not specified,
                          the size is determined from the length of the `kek`.

    :return: An `EncryptedValue` structure populated with encrypted data, encryption parameters,
             and wrapped CEK.

    :raises ValueError: If the `cek` or `kek` sizes are not supported or the encryption process fails.
    """
    encrypted_value = rfc4211.EncryptedValue()

    iv = iv if iv is not None else os.urandom(16)

    enc_symm_key = aes_key_wrap(wrapping_key=kek, key_to_wrap=cek)
    enc_value = compute_aes_cbc(key=cek, iv=iv, data=data, decrypt=False)

    aes_wrap_size = aes_wrap_size if aes_wrap_size is not None else int(len(kek) * 8)
    key_alg = rfc5280.AlgorithmIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
    key_alg["algorithm"] = AES_ALG_NAME_2_OID[f"aes{aes_wrap_size}_wrap"]

    aes_cbc_size = aes_cbc_size if aes_cbc_size is not None else int(len(cek) * 8)
    symm_alg = rfc5280.AlgorithmIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    symm_alg["algorithm"] = AES_ALG_NAME_2_OID[f"aes{aes_cbc_size}_wrap"]
    # normally would use AES_IV which has a value constraint so basic univ.OctetString is used.
    symm_alg["parameters"] = univ.OctetString(iv)

    encrypted_value["symmAlg"] = symm_alg

    encrypted_value["encSymmKey"] = (
        univ.BitString()
        .fromOctetString(enc_symm_key)
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
    )

    encrypted_value["keyAlg"] = key_alg

    encrypted_value["encValue"] = univ.BitString.fromOctetString(enc_value)

    return encrypted_value


def process_encrypted_value(kek: bytes, enc_val: rfc4211.EncryptedValue) -> bytes:
    """Decrypt the data encapsulated within an `EncryptedValue` structure.

    Process an `EncryptedValue` object, extracts the encrypted
    symmetric key (CEK) and initialization vector (IV), and decrypts the encrypted
    content using AES-CBC.

    :param kek: The Key Encryption Key (KEK) used to unwrap the encrypted CEK.
    :param enc_val: The `EncryptedValue` structure containing the encrypted CEK,
                    symmetric algorithm information, and encrypted data.
    :return: The decrypted plaintext data.

    :raises ValueError: If the decryption process fails due to invalid keys,
                        incorrect parameters, or corrupted data.
    """
    enc_symm_key = enc_val["encSymmKey"].asOctets()
    cek = aes_key_unwrap(wrapping_key=kek, wrapped_key=enc_symm_key)
    symm_alg = enc_val["symmAlg"]
    iv = symm_alg["parameters"].asOctets()
    enc_value = enc_val["encValue"].asOctets()
    decrypted_data = compute_aes_cbc(key=cek, iv=iv, data=enc_value, decrypt=True)
    return decrypted_data


def prepare_ocsp_aia_value(ocsp_url: str) -> AuthorityInformationAccess:
    """Prepare an OCSP Authority Information Access (AIA) extension value for a certificate."""
    aia = AuthorityInformationAccess(
        [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, UniformResourceIdentifier(ocsp_url))]
    )

    return aia


def get_ocsp_url_from_cert(cert: Union[x509.Certificate, rfc9480.CMPCertificate]) -> List[str]:
    """Extract the OCSP URL from a certificate's Authority Information Access extension.

    :param cert: The certificate to extract the OCSP URL from.
    :return: The OCSP URLs, if present.
    """
    cert = _convert_to_crypto_lib_cert(cert)
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except ExtensionNotFound:
        return []

    ocsp_urls = [
        access_description.access_location.value
        for access_description in aia  # type: ignore
        if access_description.access_method == AuthorityInformationAccessOID.OCSP
    ]

    return ocsp_urls


def _prepare_crypto_lib_reason_flags(
    reason_flags: Optional[str] = None,
) -> Optional[frozenset]:
    """Prepare ReasonFlags.

    :param reason_flags: Reason flags for the CRL.
    :return: The populated `ReasonFlags` structure, correctly tagged.
    """
    if reason_flags is not None:
        reasons = set()
        for reason in reason_flags.split(","):
            options = list(rfc5280.ReasonFlags.namedValues.keys())
            if reason not in options:
                raise ValueError(f"Invalid reason: {reason}. Must be one of {x509.ReasonFlags}.")

            reasons.add(x509.ReasonFlags(reason))
        return frozenset(reasons)

    return None


def create_issuing_distribution_point(
    crl_url: str,
    only_contains_user_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_some_reasons: Optional[str] = None,
    indirect_crl: bool = False,
    only_contains_attribute_certs: bool = False,
    critical: bool = True,
) -> x509.Extension:
    """Create an Issuing Distribution Point extension.

    :param crl_url: URL where the CRL can be accessed.
    :param only_contains_user_certs: Indicates if the CRL only contains user certificates.
    :param only_contains_ca_certs: Indicates if the CRL only contains CA certificates.
    :param only_some_reasons: Specifies the reasons for which the CRL is issued.
    :param indirect_crl: Indicates if the CRL is an indirect CRL.
    :param only_contains_attribute_certs: Indicates if the CRL only contains attribute certificates.
    :param critical: Indicates if the extension is critical.
    :return: x509.Extension object for Issuing Distribution Point.
    """
    reasons = _prepare_crypto_lib_reason_flags(only_some_reasons)

    idp = x509.IssuingDistributionPoint(
        full_name=[x509.UniformResourceIdentifier(crl_url)],
        relative_name=None,
        only_contains_user_certs=only_contains_user_certs,
        only_contains_ca_certs=only_contains_ca_certs,
        only_some_reasons=reasons,
        indirect_crl=indirect_crl,
        only_contains_attribute_certs=only_contains_attribute_certs,
    )
    return x509.Extension(ExtensionOID.ISSUING_DISTRIBUTION_POINT, critical, idp)


@not_keyword
def prepare_crl_distribution_point_extension(
    crl_url: str,
    critical: bool = False,
) -> x509.Extension:
    """Prepare a CRL distribution point extension.

    :param crl_url: The URL of the CRL distribution point.
    :param critical: Whether the extension is marked as critical or not. Defaults to `False`.
    :return: The prepared `CRLDistributionPoints` extension.
    """
    crl_dp = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )

    return x509.Extension(oid=x509.CRLDistributionPoints.oid, critical=critical, value=crl_dp)
