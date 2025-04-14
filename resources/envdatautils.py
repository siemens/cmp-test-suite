# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utilities for the CMP `EnvelopedData` structure to securely transport data."""

import logging
import os
from typing import List, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1.type.base import Asn1Item
from pyasn1_alt_modules import (
    rfc4055,
    rfc4211,
    rfc5280,
    rfc5652,
    rfc5753,
    rfc5958,
    rfc8018,
    rfc8418,
    rfc9480,
    rfc9481,
    rfc9629,
)
from robot.api.deco import keyword, not_keyword

from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.abstract_wrapper_keys import AbstractCompositePrivateKey, HybridKEMPublicKey, KEMPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey, CompositeSig04PublicKey
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_public_key
from pq_logic.tmp_oids import CMS_COMPOSITE03_OID_2_HASH
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from resources import (
    asn1utils,
    certbuildutils,
    certextractutils,
    cryptoutils,
    keyutils,
    prepare_alg_ids,
    prepareutils,
    protectionutils,
    utils,
)
from resources.convertutils import copy_asn1_certificate, ensure_is_kem_pub_key, str_to_bytes
from resources.copyasn1utils import copy_name
from resources.exceptions import BadAsn1Data
from resources.oid_mapping import compute_hash, get_alg_oid_from_key_hash, get_hash_from_oid, sha_alg_name_to_oid
from resources.oidutils import (
    CURVE_2_COFACTORS,
    ECMQV_NAME_2_OID,
    HKDF_NAME_2_OID,
    KEY_WRAP_NAME_2_OID,
    KM_KA_ALG,
    KM_KA_ALG_NAME_2_OID,
    KM_KW_ALG,
    PQ_SIG_PRE_HASH_NAME_2_OID,
)
from resources.typingutils import PrivateKey, PublicKey, RecipInfo, SignKey, Strint, VerifyKey


@not_keyword
def get_aes_keywrap_length(alg_name: str) -> int:
    """Retrieve the AES key length in bits for the specified key wrap algorithm.

    :param alg_name: The name of the key wrap algorithm (e.g., "aes128-wrap", "aes192-wrap", "aes256-wrap").
    :return: The key length in bits corresponding to the specified algorithm.
    :raises ValueError: If the algorithm name is not recognized.
    """
    if alg_name not in KEY_WRAP_NAME_2_OID:
        raise ValueError(f"Unrecognized algorithm name: {alg_name}")

    if "128" in alg_name:
        return 16
    if "192" in alg_name:
        return 24
    if "256" in alg_name:
        return 32

    raise ValueError(f"Unable to determine key length for algorithm: {alg_name}")


@not_keyword
def prepare_encrypted_content_info(
    cek: bytes,
    data_to_protect: bytes,
    for_signed_data: bool = True,
    iv: Optional[bytes] = None,
    enc_oid: Optional[univ.ObjectIdentifier] = None,
) -> rfc5652.EncryptedContentInfo:
    """Create an `EncryptedContentInfo` with AES-CBC encryption for the signed data.

    This function prepares the `EncryptedContentInfo` structure, which holds the encrypted content
    in the `EnvelopedData` structure of a CMP message. It uses AES-CBC encryption with a fixed IV
    (for testing purposes) to encrypt the signed data using the provided content encryption key.

    :param cek: AES key for encrypting the signed data.
    :param data_to_protect: The signed data to encrypt.
    :param for_signed_data: If True, the content type is set to `id_signedData`. Defaults to True.
    :param iv: Optional initialization vector for AES-CBC encryption. Defaults to `None`.
    :param enc_oid: Optional Object Identifier for the content encryption algorithm. Defaults to `None`.
    :return: An `EncryptedContentInfo` containing the encrypted content.
    """
    iv = iv or os.urandom(16)
    alg_id = prepare_alg_ids.prepare_symmetric_encr_alg_id("cbc", value=univ.OctetString(iv), length=len(cek))

    enc_content_info = rfc5652.EncryptedContentInfo()

    enc_oid = enc_oid or rfc5652.id_signedData if for_signed_data else rfc5652.id_data

    enc_content_info["contentType"] = enc_oid
    enc_content_info["contentEncryptionAlgorithm"] = alg_id

    encrypted_content = cryptoutils.compute_aes_cbc(decrypt=False, iv=iv, key=cek, data=data_to_protect)

    enc_content = rfc5652.EncryptedContent(encrypted_content).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    enc_content_info["encryptedContent"] = enc_content

    return enc_content_info


@keyword(name="Prepare EnvelopedData with PWRI")
def prepare_enveloped_data_with_pwri(  # noqa D417 undocumented-param
    password: Union[str, bytes],
    data: Union[bytes, Asn1Item],
    cek: Optional[Union[bytes, str]] = None,
    salt: Optional[Union[bytes, str]] = None,
    kdf: str = "pbkdf2",
    for_raw_data: bool = False,
    oid: str = str(rfc5652.id_signedData),
    for_enc_key: bool = True,
    for_popo: bool = False,
) -> rfc9480.EnvelopedData:
    """Prepare an `EnvelopedData` structure with password-based encryption.

    This function creates an `EnvelopedData` structure that uses password-based encryption
    to protect the content. It generates a content encryption key (CEK) and encrypts the
    provided data using the specified password and key derivation function (KDF).

    Arguments:
    ---------
        - `password`: The password used for key derivation.
        - `data`: The data to be encrypted.
        - `cek`: Optional content encryption key. Defaults to `None`.
        - `salt`: Optional salt for key derivation. Defaults to `None`.
        - `kdf`: Key derivation function to use. Defaults to "pbkdf2".
        - `for_raw_data`: If True, the content type is set to `id_rawData`. Defaults to False.
        - `oid`: Object Identifier for the content encryption algorithm. Defaults to `id_signedData`.
        - `for_enc_key`: If True, the structured is correctly tagged for the EncryptedKey structure. Defaults to `True`.
        - `for_popo`: If True, the structure is tagged for the POPO, for the `POPOPrivKey` structure.
        Defaults to `False`.

    Returns:
    -------
        - The populated `EnvelopedData` structure.

    Examples:
    --------
    | ${env_data}= | Prepare EnvelopedData with PWRI | ${password} | ${data} |
    | ${env_data}= | Prepare EnvelopedData with PWRI | ${password} | ${data} | kdf=hkdf | hash_alg=sha256 |

    """
    cek = cek or os.urandom(32)
    cek = str_to_bytes(cek)

    pwri = prepare_password_recipient_info(
        password=password,
        cek=cek,
        salt=salt,
        kdf=kdf,
    )

    if for_enc_key:
        target = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    elif for_popo:
        target = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
    else:
        target = rfc9480.EnvelopedData()

    return prepare_enveloped_data(
        recipient_infos=parse_recip_info(pwri),
        cek=cek,
        data_to_protect=data,
        version=0,
        enc_oid=rfc5652.id_data if for_raw_data else univ.ObjectIdentifier(oid),
        target=target,
    )


@not_keyword
def prepare_enveloped_data(
    recipient_infos: Union[rfc5652.RecipientInfo, List[rfc5652.RecipientInfo]],
    cek: bytes,
    data_to_protect: Union[bytes, Asn1Item],
    version: int = 2,
    target: Optional[rfc9480.EnvelopedData] = None,  # type: ignore
    enc_oid: Optional[univ.ObjectIdentifier] = None,
) -> rfc5652.EnvelopedData:
    """Create an `EnvelopedData` structure with encrypted content and recipient information.

    The `EnvelopedData` structure is used in CMP messages to encapsulate encrypted content
    and the information needed by recipients to decrypt it. This function assembles the
    `EnvelopedData` structure by combining the encrypted content and recipient information.

    :param recipient_infos: List of recipient information structures, specifying how each
    recipient can decrypt the content.
    :param cek: AES key for encrypting the signed data.
    :param data_to_protect: The signed data to encrypt and include in the `EnvelopedData`.
    :param version: Version of the `EnvelopedData` structure. Defaults to 2.
    :param target: An optional `EnvelopedData` structure to populate. Defaults to `None`.
    :param enc_oid: Optional Object Identifier for the content encryption algorithm. Defaults to `None`.
    :return: An `EnvelopedData` containing the encrypted content and recipient info.
    """
    if target is None:
        target = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    if not isinstance(data_to_protect, bytes):
        data_to_protect = asn1utils.encode_to_der(data_to_protect)

    target: rfc9480.EnvelopedData

    target["version"] = version
    infos = rfc5652.RecipientInfos()
    if not isinstance(recipient_infos, (rfc5652.RecipientInfos, list)):
        recipient_infos = [recipient_infos]

    for recipient_info in recipient_infos:
        infos.append(parse_recip_info(recipient_info))

    target["encryptedContentInfo"] = prepare_encrypted_content_info(
        cek=cek, data_to_protect=data_to_protect, enc_oid=enc_oid
    )

    target["recipientInfos"] = infos

    return target


@not_keyword
def prepare_originator_with_rid(rid: rfc5652.RecipientIdentifier) -> rfc5652.OriginatorIdentifierOrKey:
    """Prepare the `OriginatorIdentifierOrKey` structure with a recipient identifier.

    This function sets the `originator` field of the `OriginatorIdentifierOrKey` structure
    to indicate that the originator is identified by a recipient identifier.

    :param rid: The `RecipientIdentifier` structure to populate.
    :return: The populated `OriginatorIdentifierOrKey` structure.
    """
    originator = rfc5652.OriginatorIdentifierOrKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

    rid_name = rid.getName()

    if rid_name == "issuerAndSerialNumber":
        originator[rid_name] = rfc5652.IssuerAndSerialNumber()
        originator[rid_name]["issuer"] = rid[rid_name]["issuer"]
        originator[rid_name]["serialNumber"] = rid[rid_name]["serialNumber"]
    elif rid_name == "subjectKeyIdentifier":
        ski = rfc5652.SubjectKeyIdentifier(rid[rid_name].asOctets()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        originator[rid_name] = ski
    else:
        raise ValueError(
            "The `RecipientIdentifier` must be either `issuerAndSerialNumber` or "
            "`subjectKeyIdentifier` to be used as an originator identifier."
        )

    return originator


@keyword(name="Prepare Recipient Identifier")
def prepare_recipient_identifier(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    ski: Optional[bytes] = None,
    key: Optional[Union[PublicKey, PrivateKey]] = None,
    bad_ski: bool = False,
) -> rfc5652.RecipientIdentifier:
    """Prepare a RecipientIdentifier used for kari and ktri.

    Used to identify the certificate used for the key transport.

    Arguments:
    ---------
        - `cert`: A certificate to extract the identifier from. Defaults to `None`.
        - `issuer_and_ser`: An IssuerAndSerialNumber structure to use. Defaults to `None`.
        - `ski`: A Subject Key Identifier as bytes. Defaults to `None`.
        - `key`: A public key to compute the identifier from. Defaults to `None`.
        - `bad_ski`: If True, the SubjectKeyIdentifier is modified. Defaults to `False`.

    Returns:
    -------
        - The populated `RecipientIdentifier` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor an issuer and serial number is provided or a key.

    Examples:
    --------
    | ${recip_id}= | Prepare Recipient Identifier | cert=${cert} |
    | ${recip_id}= | Prepare Recipient Identifier | key=${key} |

    """
    recip_id = rfc5652.RecipientIdentifier()

    if key is None and cert is None and issuer_and_ser is None and ski is None:
        raise ValueError(
            "Either a certificate, an issuer and serial number, or a key must be "
            "provided, to prepare the `RecipientIdentifier`."
        )

    if issuer_and_ser is not None:
        recip_id["issuerAndSerialNumber"] = issuer_and_ser
        return recip_id

    if key is not None:
        if not isinstance(key, PublicKey):
            key = key.public_key()
        ski = x509.SubjectKeyIdentifier.from_public_key(key).digest  # type: ignore

    elif cert is not None:
        ski = ski or certextractutils.get_field_from_certificate(cert, extension="ski")  # type: ignore

    if bad_ski and ski is not None:
        ski = utils.manipulate_first_byte(ski)

    if ski is not None:
        recip_id["subjectKeyIdentifier"] = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
    else:
        recip_id["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)
    return recip_id


@keyword(name="Prepare IssuerAndSerialNumber")
def prepare_issuer_and_serial_number(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    modify_serial_number: bool = False,
    modify_issuer: bool = False,
    issuer: Optional[str] = None,
    serial_number: Optional[Union[str, int]] = None,
) -> rfc5652.IssuerAndSerialNumber:
    """Extract issuer and serial number from a certificate.

    Creates an `IssuerAndSerialNumber` structure, which uniquely identifies
    a certificate by its issuer's distinguished name and its serial number. It's used when
    the certificate lacks a SubjectKeyIdentifier extension.

    Arguments:
    ---------
        - `cert`: Certificate from which to extract the issuer and serial number.
        - `modify_serial_number`: If True, increment the serial number by 1. Defaults to `False`.
        - `modify_issuer`: If True, modify the issuer common name. Defaults to `False`.
        - `issuer`: The issuer's distinguished name to use. Defaults to `None`.
        - `serial_number`: The serial number to use. Defaults to `None`.

    Returns:
    -------
        - The populated `IssuerAndSerialNumber` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor an issuer and serial number is provided.

    Examples:
    --------
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | cert=${cert} | modify_serial_number=True |
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | issuer=${issuer} | serial_number=${serial_number} |

    """
    if cert is None and (issuer is None or serial_number is None):
        raise ValueError("Either a certificate or a issuer and serial number must be provided.")

    iss_ser_num = rfc5652.IssuerAndSerialNumber()

    if issuer:
        iss_ser_num["issuer"] = prepareutils.prepare_name(issuer)
    elif not modify_issuer:
        iss_ser_num["issuer"] = copy_name(
            target=rfc9480.Name(),
            filled_name=cert["tbsCertificate"]["issuer"],  # type: ignore
        )
    else:
        data = certbuildutils.modify_common_name_cert(cert, issuer=True)  # type: ignore
        data: str
        iss_ser_num["issuer"] = prepareutils.prepare_name(data)

    if serial_number is None:
        serial_number = int(cert["tbsCertificate"]["serialNumber"])  # type: ignore

    if modify_serial_number:
        serial_number = int(serial_number) + 1
    iss_ser_num["serialNumber"] = rfc5280.CertificateSerialNumber(serial_number)
    return iss_ser_num


@not_keyword
def prepare_signer_identifier(cert: rfc9480.CMPCertificate) -> rfc5652.SignerIdentifier:
    """Create a `SignerIdentifier` to identify the CMP protection certificate.

    Prepares the `SignerIdentifier` used in the `SignerInfo` structure
    to specify the certificate corresponding to the signing key (CMP protection certificate).
    It uses the SubjectKeyIdentifier extension if present; otherwise, it falls back to
    using the issuer and serial number.

    :param cert: Certificate to derive the identifier from (CMP protection certificate).
    :return: A `SignerIdentifier` structure identifying the signer.
    """
    ski = certextractutils.get_field_from_certificate(cert, extension="ski")
    sid = rfc5652.SignerIdentifier()
    if ski is not None:
        val = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        sid["subjectKeyIdentifier"] = val
    else:
        sid["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)

    return sid


def prepare_signed_attributes(message_digest: bytes) -> rfc5652.SignedAttributes:
    """Create `SignedAttributes` with content type and message digest.

    The `SignedAttributes` structure includes attributes that are signed along with the content.
    This function prepares the mandatory attributes: content type and message digest, which are
    necessary for signature verification in CMP.

    :param message_digest: Digest of the content to be signed.
    :return: A `SignedAttributes` structure containing the necessary attributes.
    """
    signed_attrs = rfc5652.SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    attr_content_type = rfc5652.Attribute()
    attr_content_type.setComponentByName("attrType", rfc5652.id_contentType)
    # must be set like this.
    attr_content_type.setComponentByName(
        "attrValues", univ.SetOf().setComponentByPosition(0, rfc5958.id_ct_KP_aKeyPackage)
    )

    attr_msg_dig = rfc5652.Attribute()
    attr_msg_dig.setComponentByName("attrType", rfc5652.id_messageDigest)
    # must be set like this.
    attr_msg_dig.setComponentByName(
        "attrValues", univ.SetOf().setComponentByPosition(0, univ.OctetString(message_digest))
    )

    signed_attrs.setComponentByPosition(0, attr_content_type)
    signed_attrs.setComponentByPosition(1, attr_msg_dig)

    signed_attrs2 = rfc5652.SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    der_data = encoder.encode(signed_attrs)
    data, rest = decoder.decode(der_data, signed_attrs2)
    if rest != b"":
        raise ValueError("The decoding of the SignedAttributes failed")

    return data


@not_keyword
def prepare_encapsulated_content_info(content: bytes, override_oid: bool = False) -> rfc5652.EncapsulatedContentInfo:
    """Create an `EncapsulatedContentInfo` with the provided content.

    The `EncapsulatedContentInfo` structure wraps the content that is to be signed or encrypted.
    This function prepares this structure with the specified content type and the actual content.

    :param content: Content data to encapsulate.
    :param override_oid: If True, use an alternate OID for negative testing (e.g., to simulate errors).
    Which is `id_at_commonName`. Defaults to False. The correct OID is `id_ct_KP_aKeyPackage`.
    :return: An `EncapsulatedContentInfo` structure containing the content.
    """
    encap_content_info = rfc5652.EncapsulatedContentInfo()
    encap_content_info["eContentType"] = rfc5958.id_ct_KP_aKeyPackage if not override_oid else rfc5280.id_at_commonName
    econtent = univ.OctetString(content).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    encap_content_info["eContent"] = econtent

    return encap_content_info


def prepare_signer_info(
    signing_key: SignKey,
    cert: rfc9480.CMPCertificate,
    e_content: bytes,
    sig_hash_name: Optional[str],
    digest_hash_name: Optional[str] = None,
    bad_sig: bool = False,
    version: int = 3,
) -> rfc5652.SignerInfo:
    """Create a `SignerInfo` structure for signing content.

    The `SignerInfo` structure provides information about the signer and the signature.
    This function prepares the `SignerInfo`, including setting the appropriate version,
    digest algorithm, signature algorithm, and signed attributes. It also generates the
    signature over the encapsulated content.

    :param signing_key: Private key used for signing.
    :param cert: Certificate corresponding to the signing key (CMP protection certificate).
    :param e_content: Content to sign (typically the DER-encoded `EncapsulatedContentInfo`).
    :param sig_hash_name: Hash algorithm for signature (e.g., "sha256").
    :param digest_hash_name: Hash algorithm for digest calculation. Defaults to `sig_hash_name`.
    :param bad_sig: Whether to modify the signature of the signed_info. Defaults to `False`.
    `EncapsulatedContentInfo` inside the `SignerInfo` structure.  Defaults to False.
    :param version: The CMSVersion for the structure.
    :return: A `SignerInfo` structure ready to be included in `SignedData`.
    """
    if sig_hash_name is None:
        sig_hash_name = get_digest_from_key_hash(signing_key)

    digest_hash_name = digest_hash_name or sig_hash_name
    message_digest = compute_hash(digest_hash_name, e_content)

    # Prepare signature and digest algorithm identifiers
    sig_alg_id = rfc5652.SignatureAlgorithmIdentifier()
    sig_alg_id["algorithm"] = get_alg_oid_from_key_hash(signing_key, hash_alg=sig_hash_name)

    dig_alg_id = rfc5652.DigestAlgorithmIdentifier()
    dig_alg_id["algorithm"] = sha_alg_name_to_oid(digest_hash_name)

    # Create SignerInfo structure
    signer_info = rfc5652.SignerInfo()
    signer_info["version"] = version
    signer_info["digestAlgorithm"] = dig_alg_id
    signer_info["signatureAlgorithm"] = sig_alg_id
    signer_info["signedAttrs"] = prepare_signed_attributes(message_digest)
    signer_info["sid"] = prepare_signer_identifier(cert)

    # Generate signature over the signed attributes
    encap_content_info = prepare_encapsulated_content_info(e_content)
    der_encap_content_info = encoder.encode(encap_content_info)

    signature = cryptoutils.sign_data(data=der_encap_content_info, key=signing_key, hash_alg=sig_hash_name)
    signature += b"" if not bad_sig else b"AA"
    signer_info["signature"] = univ.OctetString(signature)

    return signer_info


@not_keyword
def prepare_signer_infos(
    signing_key: SignKey,
    cert: rfc9480.CMPCertificate,
    e_content: bytes,
    sig_hash_name: Optional[str],
    digest_hash_name: Optional[str] = None,
    add_another: bool = False,
    negative_signature: bool = False,
) -> rfc5652.SignerInfos:
    """Create a `SignerInfos` set with one or more `SignerInfo` entries.

    The `SignerInfos` structure is a set of `SignerInfo` entries. This function prepares
    this structure, optionally adding multiple `SignerInfo` entries for negative testing.

    :param signing_key: Private key used for signing.
    :param cert: Certificate corresponding to the signing key (CMP protection certificate).
    :param e_content: Content to sign.
    :param sig_hash_name: Hash algorithm for signature.
    :param digest_hash_name: Hash algorithm for digest calculation. Defaults to `sig_hash_name`.
    :param add_another: If `True`, add another `SignerInfo` for negative testing.
    :param negative_signature: A boolean flag that, if True, modifies the signature of the signed_info.
    `EncapsulatedContentInfo` inside the `SignerInfo` structure.  Defaults to False.
    :return: A `SignerInfos` structure containing one or more `SignerInfo` entries.
    """
    signer_infos = rfc5652.SignerInfos()

    if sig_hash_name is None:
        sig_hash_name = get_digest_from_key_hash(signing_key)

    signer_info = prepare_signer_info(
        signing_key=signing_key,
        cert=cert,
        e_content=e_content,
        digest_hash_name=digest_hash_name,
        sig_hash_name=sig_hash_name,
        bad_sig=negative_signature,
    )
    signer_infos.append(signer_info)

    if add_another:
        signer_infos.append(signer_info)

    return signer_infos


def prepare_certificate_set(certs: List[rfc9480.CMPCertificate]) -> rfc5652.CertificateSet:
    """Prepare a `CertificateSet` for a list of certificates.

    Constructs a `CertificateSet` containing multiple certificates, enabling
    recipient systems to verify that the certificate identifying the KGA is trusted and
    allow to generate a private key for us.

    :param certs: List of certificates to include (e.g., KGA certificate chain).
    :return: The populated `CertificateSet` structure, with the correct tagging.
    """
    certificates = rfc5652.CertificateSet().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    for cert in certs:
        new_cert = rfc5652.CertificateChoices()
        new_cert["certificate"] = copy_asn1_certificate(cert, rfc9480.CMPCertificate())
        certificates.append(new_cert)

    return certificates


def _prepare_digest_alg_ids(hash_algs: str) -> rfc5652.DigestAlgorithmIdentifiers:
    """Prepare a set of `DigestAlgorithmIdentifiers` for the specified hash algorithms.

    :param hash_algs: A list of hash algorithm names (e.g., "sha256", "sha384").
    :return: A `DigestAlgorithmIdentifiers` structure containing the specified hash algorithms.
    """
    digest_alg_set = rfc5652.DigestAlgorithmIdentifiers()
    for alg_name in hash_algs.split(","):
        alg_name = alg_name.strip()
        digest_alg_id = rfc5652.DigestAlgorithmIdentifier()
        digest_alg_id["algorithm"] = sha_alg_name_to_oid(alg_name)
        digest_alg_set.append(digest_alg_id)

    return digest_alg_set


@keyword(name="Prepare SignedData")
def prepare_signed_data(  # noqa D417 undocumented-param
    signing_key: SignKey,
    cert: rfc9480.CMPCertificate,
    sig_hash_name: Optional[str],
    e_content: Optional[bytes] = None,
    digest_hash_name: Optional[str] = None,
    bad_sig: bool = False,
    cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
    private_keys: Optional[List[PrivateKey]] = None,
    signer_infos: Optional[Union[rfc5652.SignerInfo, List[rfc5652.SignerInfo]]] = None,
) -> rfc5652.SignedData:
    """Prepare a `SignedData` structure for the provided content, key, and certificate.

    Creates `SignedData` structure as defined in RFC 5652, including digest
    algorithm identifiers, encapsulated content, certificates, and signer information.

    Arguments:
    ---------
        - `e_content`: The content to be signed, provided as a byte string.
        - `signing_key`: The private key used for signing.
        - `cert`: A `CMPCertificate` object used for KGA.
        - `sig_hash_name`: The hash algorithm name to use for signing.
        - `digest_hash_name`: The hash algorithm name to use for digest calculation. Defaults to `sig_hash_name`.
        - `bad_sig`: A boolean flag that, if True, modifies the signature of the signed_info.
        - `cert_chain`: Optional The certificate chain of the KGA `CMPCertificate`. Defaults to cert.
        - `private_keys`: A list of private keys to parse inside the asymmetric key package structure.
        - `signer_infos`: Optional SignerInfo structure or list of SignerInfo structures to include. Defaults to `None`.

    Returns:
    -------
        - The populated `SignedData` structure.

    Raises:
    ------
        - ValueError: If neither `e_content` nor `private_keys` is provided.

    Examples:
    --------
    | ${signed_data}= | Prepare SignedData | ${signing_key} | ${cert} | e_content=${e_content} | "sha256" |

    """
    if e_content is None and private_keys is None:
        raise ValueError("Either `e_content` or `private_keys` must be provided.")

    if sig_hash_name is None:
        sig_hash_name = get_digest_from_key_hash(signing_key)

    digest_hash_name = digest_hash_name or sig_hash_name

    if private_keys is not None:
        # Generate content from private keys if provided
        e_content = asn1utils.encode_to_der(prepare_asymmetric_key_package(private_keys))

    signed_data = rfc5652.SignedData()
    signed_data["version"] = 3

    digest_alg_set = _prepare_digest_alg_ids(digest_hash_name)
    signed_data["digestAlgorithms"] = digest_alg_set

    if cert_chain is None:
        cert_chain = [cert]

    # pyasn1-alt-modules automatically re-orders them after decoding.
    # print_chain_subject_and_issuer([cert["certificate"] for cert in certs])
    signed_data["certificates"] = prepare_certificate_set(cert_chain)

    signed_data["encapContentInfo"] = prepare_encapsulated_content_info(e_content)  # type: ignore

    if signer_infos is not None:
        if isinstance(signer_infos, rfc5652.SignerInfo):
            signer_infos = [signer_infos]

        signed_data["signerInfos"].extend(signer_infos)
    else:
        signed_data["signerInfos"] = prepare_signer_infos(
            signing_key=signing_key,
            cert=cert,
            e_content=e_content,  # type: ignore
            sig_hash_name=sig_hash_name,
            digest_hash_name=digest_hash_name,
            add_another=False,
            negative_signature=bad_sig,
        )

    # to show the different order after decoding
    # print_chain_subject_and_issuer([cert["certificate"] for cert in data["certificates"]])
    return signed_data


def prepare_asymmetric_key_package(
    private_keys: List[PrivateKey],
) -> rfc5958.AsymmetricKeyPackage:
    """Create an `AsymmetricKeyPackage` containing private keys.

    The `AsymmetricKeyPackage` structure is used to transport private keys securely.
    This function prepares the package by including the provided private keys.

    :param private_keys: List of private keys to include (e.g., newly generated keys).
    :return: An `AsymmetricKeyPackage` structure containing the private keys.
    """
    asym_key_package = rfc5958.AsymmetricKeyPackage()
    for key in private_keys:
        asym_key_package.append(prepare_one_asymmetric_key(private_key=key))
    return asym_key_package


@not_keyword
def prepare_one_asymmetric_key(
    private_key,
    version: str = "v2",
) -> rfc5958.OneAsymmetricKey:
    """Create a `OneAsymmetricKey` structure for a private key.

    Wraps a private key into the `OneAsymmetricKey` structure,
    including the algorithm identifier and the public key. It's used when
    preparing an `AsymmetricKeyPackage`.

    :param private_key: Private key to include.
    :param version: Version of the structure. Defaults to "v2".
    :return: A `OneAsymmetricKey` structure containing the private key.
    """
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    if int(rfc5958.Version(version)) == 0:
        one_asym_key, _ = decoder.decode(private_key_bytes, asn1Spec=rfc4211.PrivateKeyInfo())
        return private_key_bytes

    one_asym_key, _ = decoder.decode(private_key_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
    one_asym_key["version"] = rfc5958.Version(version)

    if isinstance(private_key, rsa.RSAPrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
        )

    elif isinstance(private_key, AbstractCompositePrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    else:
        public_key_bytes = private_key.public_key().public_bytes_raw()

    public_key_bit_str = (
        rfc5958.PublicKey()
        .fromOctetString(public_key_bytes)
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    )
    one_asym_key["publicKey"] = public_key_bit_str

    return one_asym_key


def _get_rsa_kari_alg_id(use_rsa_oaep: bool) -> rfc5652.KeyEncryptionAlgorithmIdentifier:
    """Prepare the KeyEncryptionAlgorithmIdentifier based on whether RSA-OAEP is used.

    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5.
    :return: A KeyEncryptionAlgorithmIdentifier object configured accordingly.
    """
    key_enc_alg_oaep = rfc5652.KeyEncryptionAlgorithmIdentifier()
    if not use_rsa_oaep:
        key_enc_alg_oaep["algorithm"] = rfc9481.rsaEncryption
        return key_enc_alg_oaep

    oaep_params = rfc4055.RSAES_OAEP_params()
    oaep_params["hashFunc"]["algorithm"] = rfc4055.id_sha384
    oaep_params["maskGenFunc"]["algorithm"] = rfc4055.id_mgf1
    oaep_params["maskGenFunc"]["parameters"] = encoder.encode(rfc4055.id_sha256)

    key_enc_alg_oaep["algorithm"] = rfc4055.id_RSAES_OAEP
    key_enc_alg_oaep["parameters"] = oaep_params
    return key_enc_alg_oaep


def _encrypt_rsa_oaep(key: rsa.RSAPublicKey, alg_id: rfc5280.AlgorithmIdentifier, content_enc_key):
    """Encrypt the content encryption key using RSA encryption with specified padding.

    :param key: The RSA private key used for encryption.
    :param alg_id: The AlgorithmIdentifier specifying the encryption algorithm and parameters.
    :param content_enc_key: The content encryption key to be encrypted.
    :return: The encrypted content encryption key.
    """
    if alg_id["parameters"].isValue:
        padding_val = protectionutils.get_rsa_oaep_padding(alg_id["parameters"])
    else:
        padding_val = padding.PKCS1v15()

    return key.encrypt(plaintext=content_enc_key, padding=padding_val)


@not_keyword
def prepare_ktri(
    ee_key: rsa.RSAPublicKey,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate],
    cek: bytes,
    use_rsa_oaep: bool = True,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
) -> rfc5652.RecipientInfo:
    """Prepare a KeyTransRecipientInfo object for testing.

    :param ee_key: The RSA public key of the end entity.
    :param cmp_protection_cert: The certificate of the server.
    :param cek: The content encryption key to be encrypted.
    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5 padding.
    :param issuer_and_ser: The `IssuerAndSerialNumber` structure to use. Defaults to None.
    :param rid: The `RecipientIdentifier` structure to use. Defaults to `None`.
    :return: A RecipientInfo object containing the KeyTransRecipientInfo.
    """
    if isinstance(ee_key, rsa.RSAPublicKey):
        key_enc_alg_id = _get_rsa_kari_alg_id(use_rsa_oaep=use_rsa_oaep)
        encrypted_key = _encrypt_rsa_oaep(key=ee_key, alg_id=key_enc_alg_id, content_enc_key=cek)
    else:
        raise ValueError(f"Unsupported key type: {type(ee_key)}")

    # Version MUST be 2 for KTRI.
    ktri = prepare_key_transport_recipient_info(
        version=2,
        key_enc_alg_id=key_enc_alg_id,
        cmp_protection_cert=cmp_protection_cert,
        encrypted_key=encrypted_key,
        issuer_and_ser=issuer_and_ser,
        rid=rid,
    )

    return parse_recip_info(ktri)


@not_keyword
def prepare_key_transport_recipient_info(
    version: int = 2,
    key_enc_alg_oid: univ.ObjectIdentifier = rfc9481.id_RSAES_OAEP,
    encrypted_key: Optional[bytes] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    key_enc_alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
    **kwargs,
) -> rfc5652.KeyTransRecipientInfo:
    """Create a `KeyTransRecipientInfo` structure for key transport encryption.

    The `KeyTransRecipientInfo` structure is used in CMS `EnvelopedData` to specify
    a recipient that uses key transport algorithms (e.g., RSA) to decrypt the content encryption key.
    This function prepares this structure by setting the recipient identifier and key encryption algorithm,
    which are necessary for the recipient to recover the content encryption key.

    :param version: Version of the CMS structure. Defaults to 2.
    :param key_enc_alg_oid: OID for the key encryption algorithm. Defaults to RSAES-OAEP.
    :param encrypted_key: Encrypted key material (the content encryption key encrypted with the recipient's public key).
    :param cmp_protection_cert: Certificate to extract the recipient identifier from. Used to set the `rid` if provided.
    are not provided. Defaults to `None`.
    :param rid: `RecipientIdentifier` structure. If provided, `cert`, `ski`, and `issuer_and_ser` are ignored.
    Defaults to `None`.
    :param key_enc_alg_id: `AlgorithmIdentifier` for the key encryption algorithm. If provided,
    `key_enc_alg_oid` is ignored.
    :return: A `KeyTransRecipientInfo` structure ready to be included in `RecipientInfo`.
    """
    ktri_structure = rfc5652.KeyTransRecipientInfo()
    ktri_structure["version"] = rfc5652.CMSVersion(version)

    rid = rid or prepare_recipient_identifier(
        cert=cmp_protection_cert,
        issuer_and_ser=kwargs.get("issuer_and_ser"),
        ski=kwargs.get("ski"),
        bad_ski=kwargs.get("bad_ski", False),
    )

    ktri_structure["rid"] = rid

    if key_enc_alg_id is not None:
        # Ensure that parameters are properly encoded
        key_enc_alg_id, _ = decoder.decode(encoder.encode(key_enc_alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
        ktri_structure["keyEncryptionAlgorithm"] = key_enc_alg_id
    else:
        alg_id = rfc5652.KeyEncryptionAlgorithmIdentifier()
        alg_id["algorithm"] = key_enc_alg_oid
        ktri_structure["keyEncryptionAlgorithm"] = alg_id

    if encrypted_key is not None:
        ktri_structure["encryptedKey"] = rfc5652.EncryptedKey(encrypted_key)

    return ktri_structure


def _get_kari_ephemeral_oid(hash_alg: Optional[str]) -> univ.ObjectIdentifier:
    """Determine the ECMQV (Elliptic Curve Menezes-Qu-Vanstone) oid.

    :return: Corresponding OID.
    :raises KeyError: If the combination is not allowed.
    """
    if hash_alg is None:
        hash_alg = "sha256"
    try:
        return ECMQV_NAME_2_OID[f"mvq-{hash_alg}"]
    except KeyError as e:
        _hash_algs = ["sha224", "sha256", "sha384", "sha512"]
        raise KeyError(f"The ECMQV ECC supports only the hash algorithms: {hash_alg}") from e


def _get_ecc_dh_oid(public_key: EllipticCurvePublicKey, hash_alg: str) -> univ.ObjectIdentifier:
    """Get the ECC KARI oid"""
    if public_key.curve.name.startswith("brainpoolP"):
        name = f"cofactorDH-{hash_alg.upper()}"
    else:
        try:
            order = CURVE_2_COFACTORS[public_key.curve.name.lower()]
        except KeyError as e:
            raise ValueError(f"Unsupported KARI ECC Public Key: `{public_key.curve.name}`") from e

        if hash_alg is None:
            raise ValueError("Hash algorithm must be provided for ECC KARI.")

        if order == 1:
            name = f"cofactorDH-{hash_alg.upper()}"

        else:
            name = f"stdDH-{hash_alg.upper()}"

    return KM_KA_ALG_NAME_2_OID[name]


def _get_kari_oid(
    public_key: ECDHPublicKey, use_ephemeral: bool = True, hash_alg: str = "sha256"
) -> univ.ObjectIdentifier:
    if isinstance(public_key, X448PublicKey):
        oid = rfc9481.id_X448
    elif isinstance(public_key, X25519PublicKey):
        oid = rfc9481.id_X25519
    elif use_ephemeral:
        oid = _get_kari_ephemeral_oid(hash_alg=hash_alg)
    else:
        oid = _get_ecc_dh_oid(public_key, hash_alg)

    return oid


# TODO fix for complete support of KARI.


@keyword(name="Prepare KeyAgreeRecipientInfo")
def prepare_kari(  # noqa D417 undocumented-param
    public_key: ECDHPublicKey,
    recip_private_key: ECDHPrivateKey,
    cek: Optional[Union[str, bytes]] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    hash_alg: str = "sha256",
    oid: Optional[univ.ObjectIdentifier] = rfc9481.dhSinglePass_stdDH_sha256kdf_scheme,
    originator: Optional[rfc5652.OriginatorIdentifierOrKey] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    ukm: Optional[Union[str, bytes]] = None,
) -> rfc5652.KeyAgreeRecipientInfo:
    """Prepare a KeyAgreeRecipientInfo object to securely exchange data with ECC key agreement.

    Arguments:
    ---------
        - `public_key`: The public key of the recipient.
        - `recip_private_key`: The private key of the sender.
        - `cek`: The content encryption key to be encrypted. Defaults to 32 random bytes.
        - `cmp_protection_cert`: The certificate of the recipient.
        - `issuer_and_ser`: The IssuerAndSerialNumber structure to use. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for key derivation.
        - `oid`: The Object Identifier for the key agreement algorithm.
        Defaults to dhSinglePass-stdDH-sha256kdf-scheme.
        - `originator`: The OriginatorIdentifierOrKey structure to use. Defaults to `None`.
        - `rid`: The RecipientIdentifier structure to use. Defaults to `None`.
        (NOT used is allowed to make argument parsing easier.)
        - `ukm`: The UserKeyMaterial to use (does not expect the ECMVQ byte string). Defaults to 32 random bytes.

    Returns:
    -------
        - The populated `KeyAgreeRecipientInfo` structure (correctly tagged).

    Raises:
    ------
        - ValueError: If the public key is not of the expected type.
        - KeyError: If the hash algorithm is not supported for the specified key type.
        - KeyError: If the key agreement algorithm is not supported.

    Examples:
    --------
    | ${kari}= | Prepare KeyAgreeRecipientInfo | ${public_key} | ${recip_private_key} | cek=${cek} |
    | ${kari}= | Prepare KeyAgreeRecipientInfo | ${public_key} | ${recip_private_key} | rid=${rid} |


    :param public_key: The public key of the recipient.
    :param recip_private_key: The private key of the sender.
    :param cek: The content encryption key to be encrypted. Defaults to 32 random bytes.
    :param cmp_protection_cert: The certificate of the recipient.
    :param issuer_and_ser: The IssuerAndSerialNumber structure to use. Defaults to `None`.
    :param hash_alg: The hash algorithm to use for key derivation.
    :param oid: The Object Identifier for the key agreement algorithm.
    Defaults to dhSinglePass-stdDH-sha256kdf-scheme.
    :param originator: The OriginatorIdentifierOrKey structure to use. Defaults to `None`.
    :param rid: The RecipientIdentifier structure to use. Defaults to `None`.
    :param ukm: The UserKeyMaterial to use (does not expect the ECMVQ byte string). Defaults to 32 random bytes.
    :return: The populated `KeyAgreeRecipientInfo` structure.

    """
    ukm = str_to_bytes(ukm or os.urandom(32))

    cek = cek or os.urandom(32)
    cek = str_to_bytes(cek)

    if oid is None:
        oid = _get_kari_oid(public_key=public_key, use_ephemeral=False, hash_alg=hash_alg)

    name = KM_KA_ALG[oid]
    if isinstance(public_key, (X448PublicKey, X25519PublicKey)):
        hash_alg = "sha256"
    else:
        hash_alg = name.lower().split("-")[1]

    k = cryptoutils.perform_static_dh(
        public_key=public_key,
        private_key=recip_private_key,
        hash_alg=hash_alg,
        key_wrap_oid=rfc9481.id_aes256_wrap,
        ukm=ukm,
    )
    logging.info("Prepare KARI KEK: %s for %s", k.hex(), name)
    encrypted_key = keywrap.aes_key_wrap(key_to_wrap=cek, wrapping_key=k)

    # Version MUST be 3 for KARI.
    kari = prepare_key_agreement_recipient_info(
        version=3,
        cmp_cert=cmp_protection_cert,
        encrypted_key=encrypted_key,
        key_agreement_oid=oid,
        key_wrap_oid=rfc9481.id_aes256_wrap,
        issuer_and_ser=issuer_and_ser,
        originator=originator,
        rid=rid,
        ukm=ukm,
    )

    return kari


@not_keyword
def parse_recip_info(
    info_obj: RecipInfo,
) -> rfc5652.RecipientInfo:
    """Prepare a RecipientInfo object with the underlying populated structure.

    :param info_obj: The structure to set. (e.g, `KeyAgreeRecipientInfo` or `KEMRecipientInfo`)
    :return: The populated `RecipientInfo` object.
    """
    recip_info = rfc5652.RecipientInfo()

    if isinstance(info_obj, rfc5652.RecipientInfo):
        return info_obj

    if isinstance(info_obj, rfc5652.KeyAgreeRecipientInfo):
        recip_info.setComponentByName("kari", info_obj)

    elif isinstance(info_obj, rfc5652.OtherRecipientInfo):
        recip_info.setComponentByName("ori", info_obj)

    elif isinstance(info_obj, rfc9629.KEMRecipientInfo):
        ori = rfc5652.OtherRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )

        ori["oriType"] = rfc9629.id_ori_kem
        ori["oriValue"] = info_obj
        recip_info["ori"] = ori

    elif isinstance(info_obj, rfc5652.KeyTransRecipientInfo):
        recip_info.setComponentByName("ktri", info_obj)

    elif isinstance(info_obj, rfc5652.PasswordRecipientInfo):
        recip_info.setComponentByName("pwri", info_obj)

    else:
        raise ValueError(f"Unsupported recipient info object: {type(info_obj)}")

    return recip_info


@keyword(name="Prepare RecipientInfo")
def prepare_recip_info(  # noqa D417 undocumented-param
    public_key_recip: Optional[PublicKey],
    private_key: Optional[ECDHPrivateKey] = None,
    cert_recip: Optional[rfc9480.CMPCertificate] = None,
    password: Optional[Union[str, bytes]] = None,
    cek: Optional[Union[bytes, str]] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    use_rsa_oaep: bool = True,
    salt: Optional[Union[bytes, str]] = None,
    kdf_name: str = "pbkdf2",
    **kwargs,
) -> rfc5652.RecipientInfo:
    """Prepare the appropriate RecipientInfo structure based on the type of the recipient's public key.

    Arguments:
    ---------
        - `public_key_recip`: The public key of the recipient.
        - `private_key`: The private key for key agreement (EC), if required.
        - `cert_recip`: The sender's certificate (used in some KEM flows or RSA).
        (For KEMRI is it the certificate of the recipient, For KARI, KTRI the CMP protection certificate).
        - `cek`: The content encryption key (32 random bytes if not supplied).
        - `issuer_and_ser`: IssuerAndSerialNumber structure.
        - `password`: The password for the password recipient info structure.
        - `use_rsa_oaep`: Whether to use RSA OAEP (True) or PKCS#1 v1.5 (False).
        - `salt`: The salt value for the PasswordRecipientInfo structure. Defaults to 32 random bytes.
        (can be used for negative testing, by setting to same value for CMP-protection-salt (MAC-protection)).
        - `kdf_name`: The key derivation function to use for the PasswordRecipientInfo or KEMRecipientInfo structure.
        Defaults to "pbkdf2".
        (which is the only allowed for PasswordRecipientInfo,).

    Returns:
    -------
        - The populated `RecipientInfo` structure.

    Raises:
    ------
        - ValueError: If the public key type is not supported.
        - ValueError: If a password is not provided for the password recipient info structure.
        - ValueError: If The ECDH private key was not provided for EC key exchange.
        - ValueError: If neither a certificate nor an issuer and serial number is provided.

    """
    if cek is None:
        cek = os.urandom(32)
    cek = str_to_bytes(cek)

    if isinstance(public_key_recip, rsa.RSAPublicKey):
        return prepare_ktri(
            ee_key=public_key_recip,
            cmp_protection_cert=cert_recip,
            cek=cek,
            use_rsa_oaep=use_rsa_oaep,
            issuer_and_ser=issuer_and_ser,
            rid=rid,
        )

    if isinstance(public_key_recip, ECDHPublicKey):
        if private_key is None:
            raise ValueError("An ECDH private key must be provided for EC key exchange.")
        kari = prepare_kari(
            public_key=public_key_recip,
            recip_private_key=private_key,
            issuer_and_ser=issuer_and_ser,
            cek=cek,
            cmp_protection_cert=cert_recip,
            originator=kwargs.get("originator"),
            rid=rid,
        )
        return parse_recip_info(kari)

    if is_kem_public_key(
        public_key_recip,
    ):
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=cert_recip,
            public_key_recip=public_key_recip,  # type: ignore
            cek=cek,
            rid=rid,
            issuer_and_ser=issuer_and_ser,
            kdf_name=kdf_name,
        )
        return parse_recip_info(kem_recip_info)

    if password is None and public_key_recip is None:
        raise ValueError(
            "A password must be provided for password recipient info structure, or a public key"
            "for key agreement or key transport recipient info structure, or KEM recipient info."
        )

    if password is not None:
        pwri = prepare_password_recipient_info(password=password, cek=cek, salt=salt, kdf_name=kdf_name)
        return parse_recip_info(pwri)

    raise ValueError(f"Unsupported public key type: {type(public_key_recip)}")


def _prepare_rid_for_enc_key(
    ca_pub_key: PublicKey,
    ca_cert: rfc9480.CMPCertificate,
    cmp_protection_cert: rfc9480.CMPCertificate,
) -> rfc5652.RecipientIdentifier:
    """Prepare the RecipientIdentifier for the `encryptedKey` POPO."""
    if is_kem_public_key(ca_pub_key):
        return prepare_recipient_identifier(
            cert=ca_cert,
        )
    return prepare_recipient_identifier(
        cert=cmp_protection_cert,
    )


@keyword(name="Prepare EncryptedKey For POPO")
def prepare_enc_key_for_popo(  # noqa D417 undocumented-param
    enc_key_with_id: rfc4211.EncKeyWithID,
    rid: Optional[rfc5652.RecipientIdentifier],
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    recip_info: Optional[RecipInfo] = None,
    for_agreement: bool = False,
    version: Optional[Strint] = None,
    cek: Optional[bytes] = None,
    private_key: Optional[ECDHPrivateKey] = None,
    originator: Optional[rfc5652.OriginatorIdentifierOrKey] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare an EncKeyWithID structure for the `ProofOfPossession` structure.

    Used to prove the possession of a private key by sending the encrypted key to the CA/RA.

    Note:
    ----
       - For `KTRI` and `KARI`, the rid field must be set to the CMP protection certificate.


    Arguments:
    ---------
        - `enc_key_with_id`: The EncKeyWithID structure to include.
        - `ca_cert`: The CA certificate to use for encryption.
        - `recip_info`: The recipient information structure to include. Which is used to encrypt the CEK.
        - `for_agreement`: Whether the Proof-of-Possession is for a key agreement (True) or key encipherment (False).
        - `version`: The version of the EnvelopedData structure. If None, it is set based on the recipient info.
        - `cek`: The content encryption key to use. Defaults to 32 random bytes.
        - `private_key`: The private key used for key agreement. Defaults to `None`.

    Returns:
    -------
        - The populated `ProofOfPossession` structure.

    Raises:
    ------
        - ValueError: If the private key is not provided for EC key exchange.
        - ValueError: If the recipient information is not provided.

    Examples:
    --------
    | ${popo_structure} = | Prepare EncryptedKey For POPO | ${enc_key_with_id} | ${ca_cert} | ${recip_info} |


    """
    cek = cek or os.urandom(32)
    env_data = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))

    if recip_info is None:
        if ca_cert is None:
            raise ValueError("A CA certificate must be provided, if the recipient info structure is not provided.")

        spki = ca_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        public_key_recip = keyutils.load_public_key_from_spki(spki)

        if rid is None and cmp_protection_cert is not None:
            logging.info("Prepared the `rid` based on the `ca_public_key`")
            rid = _prepare_rid_for_enc_key(public_key_recip, ca_cert, cmp_protection_cert)

        if rid is not None and originator is None and isinstance(public_key_recip, ECDHPublicKey):
            originator = prepare_originator_with_rid(rid)

        recip_info = prepare_recip_info(
            public_key_recip=public_key_recip,
            private_key=private_key,
            cek=cek,
            cert_recip=ca_cert,
            rid=rid,
            kdf_name="hkdf",
            originator=originator,
        )

    else:
        recip_info = parse_recip_info(recip_info)  # type: ignore

    if version is None and recip_info:
        version = 0 if recip_info.getName() in ["ori", "pwri"] else 2

    env_data = prepare_enveloped_data(
        cek=cek,
        recipient_infos=recip_info,
        target=env_data,
        enc_oid=rfc5652.id_data,
        version=int(version) if version is not None else 2,
        data_to_protect=encoder.encode(enc_key_with_id),
    )

    return parse_encrypted_key_for_popo(
        env_data=env_data,
        for_key_agreement=for_agreement,
    )


@not_keyword
def parse_encrypted_key_for_popo(
    env_data: rfc9480.EnvelopedData,
    for_key_agreement: bool = False,
) -> rfc4211.ProofOfPossession:
    """Parse the EncryptedKey structure for the ProofOfPossession structure.

    :param env_data: The EnvelopedData structure to parse.
    :param for_key_agreement: Boolean indicating whether the POP is for `keyAgreement`
    or `keyEncipherment`. Defaults to `False`.
    :return: The populated ProofOfPossession structure.
    """
    if not for_key_agreement:
        index = 2
        option = "keyEncipherment"
    else:
        index = 3
        option = "keyAgreement"

    popo_priv_key = rfc4211.POPOPrivKey().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, index)
    )
    popo_priv_key["encryptedKey"] = env_data

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option] = popo_priv_key

    return popo_structure


@not_keyword
def build_env_data_for_exchange(
    public_key_recip: PublicKey,
    data: bytes,
    private_key: Optional[ECDHPrivateKey] = None,
    cert_sender: Optional[rfc9480.CMPCertificate] = None,
    cek: Optional[Union[str, bytes]] = None,
    target: Optional[rfc9480.EnvelopedData] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    use_rsa_oaep: bool = True,
    enc_oid: Optional[univ.ObjectIdentifier] = None,
    hybrid_key_recip: Optional[ECDHPrivateKey] = None,
) -> rfc9480.EnvelopedData:
    """Build an EnvelopedData structure for the provided public key and data.

    Prepare an EnvelopedData structure for the provided public key and data.
    The EnvelopedData structure is used in CMP messages to securely transport encrypted content.

    :param public_key_recip: The public key of the recipient.
    :param data: The data to be encrypted.
    :param private_key: The private key used for key agreement.
    :param cert_sender: The certificate of the sender.
    :param cek: The content encryption key to use. Defaults to 32 random bytes.
    :param target: An optional `EnvelopedData` structure to populate. Defaults to None.
    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5 padding.
    :param issuer_and_ser: An optional `IssuerAndSerialNumber` structure to use. Defaults to `None`.
    :param enc_oid: The OID for the content type. Defaults to `None`.
    :param hybrid_key_recip: The hybrid key recipient to use for encryption. Defaults to None.
    :return: The populated `EnvelopedData` structure.
    """
    if cek is None:
        cek = os.urandom(32)

    cek = str_to_bytes(cek)

    if isinstance(public_key_recip, rsa.RSAPublicKey):
        kari = prepare_ktri(
            ee_key=public_key_recip,
            cmp_protection_cert=cert_sender,
            cek=cek,
            use_rsa_oaep=use_rsa_oaep,
            issuer_and_ser=issuer_and_ser,
        )
        return prepare_enveloped_data(
            recipient_infos=[kari], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    if isinstance(public_key_recip, ECDHPublicKey):
        if private_key is None or not isinstance(private_key, ECDHPrivateKey):
            raise ValueError("Private key must be provided for EC key exchange.")

        kari = prepare_kari(
            public_key=public_key_recip,
            recip_private_key=private_key,
            issuer_and_ser=issuer_and_ser,
            cek=cek,
            cmp_protection_cert=cert_sender,
        )
        kari = parse_recip_info(kari)
        return prepare_enveloped_data(
            recipient_infos=[kari], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    if is_kem_public_key(public_key_recip):
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=cert_sender,
            public_key_recip=public_key_recip,  # type: ignore
            cek=cek,
            issuer_and_ser=issuer_and_ser,
            hybrid_key_recip=hybrid_key_recip,
        )
        kem_recip_info = parse_recip_info(kem_recip_info)
        return prepare_enveloped_data(
            recipient_infos=[kem_recip_info], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    raise ValueError(f"Unsupported public key type: {type(public_key_recip)}")


def _handle_kem_encapsulation(
    public_key_recip: Optional[KEMPublicKey],
    recip_cert: Optional[rfc9480.CMPCertificate],
    hybrid_key_recip: Optional[ECDHPrivateKey],
    kem_recip_info: rfc9629.KEMRecipientInfo,
    kem_oid: Optional[univ.ObjectIdentifier] = None,
):
    """Perform the KEM encapsulation."""
    if public_key_recip:
        kem_pub_key = public_key_recip
    elif recip_cert is not None:
        kem_pub_key = keyutils.load_public_key_from_spki(  # type: ignore
            recip_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        )

    else:
        raise ValueError("No valid KEM public key or certificate provided.")

    kem_pub_key = ensure_is_kem_pub_key(kem_pub_key)

    if hybrid_key_recip is None:
        shared_secret, kemct = kem_pub_key.encaps()
    elif isinstance(kem_pub_key, HybridKEMPublicKey):
        shared_secret, kemct = kem_pub_key.encaps(hybrid_key_recip)
    else:
        shared_secret, kemct = kem_pub_key.encaps()

    if not kem_recip_info["kemct"].isValue:
        kem_recip_info["kemct"] = univ.OctetString(kemct)

    if kem_oid is None:
        kem_recip_info["kem"]["algorithm"] = get_kem_oid_from_key(kem_pub_key)

    return shared_secret, kem_recip_info


@keyword(name="Prepare KEMRecipientInfo")
def prepare_kem_recip_info(  # noqa D417 undocumented-param
    version: int = 0,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    recip_cert: Optional[rfc9480.CMPCertificate] = None,
    public_key_recip: Optional[KEMPublicKey] = None,
    kdf_name: str = "hkdf",
    ukm: Optional[bytes] = None,
    cek: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    wrap_name: str = "aes256_wrap",
    encrypted_key: Optional[bytes] = None,
    kek_length: Optional[int] = None,
    kemct: Optional[bytes] = None,
    hybrid_key_recip: Optional[ECDHPrivateKey] = None,
    shared_secret: Optional[bytes] = None,
    kem_oid: Optional[univ.ObjectIdentifier] = None,
    **kwargs,
) -> rfc9629.KEMRecipientInfo:
    """Prepare a KEMRecipientInfo structure.

    Either with provided values or by deriving them from encapsulation and encryption mechanisms.

    Arguments:
    ---------
        - `version`: The version number. Defaults to 0.
        - `rid`: Recipient Identifier. Defaults to None.
        - `recip_cert`: Server certificate containing the server's public key. Defaults to None.
        - `public_key_recip`: Public key of the recipient. Defaults to None.
        - `kdf_name`: The name of the key derivation function. Defaults to "hkdf".
        - `ukm`: User keying material, used as salt. Defaults to a random 32 bytes.
        - `cek`: Content Encryption Key to encrypt. Defaults to a random 32 bytes.
        - `hash_alg`: Hash algorithm for KDF. Defaults to "sha256".
        - `wrap_name`: Key wrap algorithm name. Defaults to "aes256-wrap".
        - `encrypted_key`: Pre-encrypted key. Defaults to None.
        - `kek_length`: Length of the KEK in bytes. Defaults to None.
        - `kemct`: KEM ciphertext. Defaults to None.
        - `hybrid_key_recip`: The hybrid key recipient to use for encryption. Defaults to None.
        - `shared_secret`: The shared secret to use for key derivation. Defaults to None.
        - `kem_oid`: The Object Identifier for the KEM algorithm. Defaults to None.

    **kwargs:
    ---------
        - `issuer_and_ser`: The `IssuerAndSerialNumber` structure to use for the recipient identifier.
        - `ski`: The subject key identifier to use for the recipient identifier.
        - `bad_ski`: The bad subject key identifier to use for the recipient identifier.

    Returns:
    -------
        - A populated `KEMRecipientInfo` structure.

    Raises:
    ------
        - `ValueError`: If neither kemct nor public_key_recip and recip_cert are provided.
        - `ValueError`: If neither `encrypted_key` nor `shared_secret` is provided.
        - `ValueError`: If the public key is not a KEMPublicKey.

    Examples:
    --------
    | ${kem_recip_info} = | Prepare KEMRecipientInfo | public_key_recip=${public_key_recip} | cek=${cek} |

    """
    key_enc_key = None

    rid = rid or prepare_recipient_identifier(
        cert=recip_cert,
        issuer_and_ser=kwargs.get("issuer_and_ser"),
        ski=kwargs.get("ski"),
        bad_ski=kwargs.get("bad_ski", False),
    )
    cek = str_to_bytes(cek or os.urandom(32))

    kem_recip_info = rfc9629.KEMRecipientInfo()
    kem_recip_info["version"] = univ.Integer(version)
    kem_recip_info["rid"] = rid
    kem_recip_info["wrap"] = prepare_alg_ids.prepare_wrap_alg_id(wrap_name)

    kek_length = kek_length or get_aes_keywrap_length(wrap_name)
    der_ukm = prepare_cmsori_for_kem_other_info(
        wrap_algorithm=kem_recip_info["wrap"],
        kek_length=kek_length or get_aes_keywrap_length(wrap_name),
        ukm=ukm,
    )

    if kem_oid is not None:
        kem_recip_info["kem"]["algorithm"] = kem_oid

    if kemct is not None:
        kem_recip_info["kemct"] = univ.OctetString(kemct)

    if kemct is not None and (shared_secret is not None or encrypted_key is not None):
        pass

    else:
        shared_secret, kem_recip_info = _handle_kem_encapsulation(
            public_key_recip=public_key_recip,
            recip_cert=recip_cert,
            hybrid_key_recip=hybrid_key_recip,
            kem_recip_info=kem_recip_info,
            kem_oid=kem_oid,
        )

    if kemct is None and recip_cert is None and public_key_recip is None:
        raise ValueError("Either `kemct` or `recip_cert` or the `public_key` must be provided.")

    kem_recip_info["kdf"] = prepare_alg_ids.prepare_kdf_alg_id(kdf_name=kdf_name, hash_alg=hash_alg)
    if shared_secret is not None:
        key_enc_key = protectionutils.compute_kdf_from_alg_id(
            kdf_alg_id=kem_recip_info["kdf"],
            ss=shared_secret,
            ukm=der_ukm,
            length=kek_length,
        )

    if encrypted_key is None and shared_secret is None:
        raise ValueError("Either `encrypted_key` or `shared_secret` must be provided.")

    if encrypted_key is None:
        if key_enc_key is None:
            raise ValueError("Key encryption key must be provided or must be derived from shared secret.")

        encrypted_key = keywrap.aes_key_wrap(wrapping_key=key_enc_key, key_to_wrap=cek)

    if ukm is not None:
        kem_recip_info["ukm"] = rfc9629.UserKeyingMaterial(der_ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    kem_recip_info["encryptedKey"] = encrypted_key
    kem_recip_info["kekLength"] = kek_length or get_aes_keywrap_length(wrap_name)

    return kem_recip_info


@not_keyword
def prepare_mqv_user_keying_material(
    ephemeral_key: ec.EllipticCurvePrivateKey, added_ukm: Optional[bytes] = None
) -> rfc5753.MQVuserKeyingMaterial:
    """Create an `MQVuserKeyingMaterial` structure for MQV key agreement.

    In MQV key agreement, the ephemeral public key and optional additional
    user keying material (ukm) are included in the `MQVuserKeyingMaterial`.
    This function prepares this structure for use in `EnvelopedData`.

    :param ephemeral_key: Ephemeral EC private key to derive the public key.
    :param added_ukm: Additional user keying material. Defaults to None.
    :return: An `MQVuserKeyingMaterial` structure containing the ephemeral public key and UKM.
    """
    mqv_ukm = rfc5753.MQVuserKeyingMaterial()
    public_key_der = ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    originator_public_key, _ = decoder.decode(public_key_der, rfc5753.OriginatorPublicKey())
    mqv_ukm["ephemeralPublicKey"] = originator_public_key

    if added_ukm is not None:
        added_ukm_field = univ.OctetString(added_ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        mqv_ukm["addedukm"] = added_ukm_field

    return mqv_ukm


@not_keyword
def prepare_ecc_cms_shared_info(
    key_wrap_oid: univ.ObjectIdentifier,
    supp_pub_info: Optional[int] = 32,
    ukm: Optional[bytes] = None,
) -> rfc5753.ECC_CMS_SharedInfo:
    """Create an `ECC_CMS_SharedInfo` structure.

    The `ECC_CMS_SharedInfo` provides additional shared information needed
    for key derivation in ECC-based key agreement. This function prepares
    this structure with the specified key wrap algorithm and other parameters.

    :param key_wrap_oid: OID for the key wrap algorithm.
    :param supp_pub_info: Length of the key to derive in bytes.
    :param ukm: Optional entity user information. Used to ensure a
    unique key.
    :return: An `ECC_CMS_SharedInfo` structure containing the shared info.
    """
    ecc_cms_info = rfc5753.ECC_CMS_SharedInfo()
    ecc_cms_info["keyInfo"]["algorithm"] = key_wrap_oid

    if supp_pub_info is None:
        supp_pub_info = int(KM_KW_ALG[key_wrap_oid].replace("aes", "").replace("_wrap", "")) // 8

    if ukm is not None:
        ecc_cms_info["entityUInfo"] = univ.OctetString(ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    supp_pub_info_bytes = supp_pub_info.to_bytes(4, byteorder="big")
    ecc_cms_info["suppPubInfo"] = univ.OctetString(supp_pub_info_bytes).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )

    return ecc_cms_info


@keyword(name="Prepare OriginatorIdentifierOrKey")
def prepare_originator_identifier_or_key(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    invalid_ski: bool = False,
) -> rfc5652.OriginatorIdentifierOrKey:
    """Create an `OriginatorIdentifierOrKey` from a certificate.

    The `OriginatorIdentifierOrKey` identifies the sender in the key agreement.
    This function prepares this structure by using the SubjectKeyIdentifier
    extension if present; otherwise, it uses the issuer and serial number.

    Arguments:
    ---------
        - `cert`: The certificate to derive the originator identifier from (typically CMP protection certificate).
        - `issuer_and_ser`: The `IssuerAndSerialNumber` structure to set inside the `rid`. Defaults to `None`.
        - `invalid_ski`: If `True`, manipulates the first byte of the SKI. Defaults to `False`.

    Returns:
    -------
        - The populated `OriginatorIdentifierOrKey` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor issuer and serial number are provided.

    """
    if cert is None and issuer_and_ser is None:
        raise ValueError("Either a certificate or issuer and serial number must be provided.")

    if cert is not None:
        ski = certextractutils.get_field_from_certificate(cert, extension="ski")  # type: ignore
        ski: Optional[bytes]
    else:
        ski = None

    originator = rfc5652.OriginatorIdentifierOrKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

    if issuer_and_ser is not None:
        originator["issuerAndSerialNumber"] = issuer_and_ser

    elif ski is not None:
        if invalid_ski:
            ski = utils.manipulate_first_byte(ski)  # type: ignore
        val = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        originator["subjectKeyIdentifier"] = val

    else:
        originator["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)

    return originator


def _prepare_key_agree_rid(
    cmp_cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    ski: Optional[bytes] = None,  # type: ignore
    bad_ski: bool = False,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
) -> rfc5652.KeyAgreeRecipientIdentifier:
    """Prepare the recipient identifier for key agreement.

    The `KeyAgreeRecipientIdentifier` is used to identify the recipient in
    key agreement scenarios. This function prepares this structure by using
    the SubjectKeyIdentifier extension if present; otherwise, it uses the
    issuer and serial number.

    :param cmp_cert: Certificate of the recipient (typically the CMP protection certificate).
    :param issuer_and_ser: `IssuerAndSerialNumber` structure to set inside the `rid`. Defaults to `None`.
    :param ski: Subject Key Identifier as bytes. Defaults to `None`.
    :param bad_ski: If `True`, manipulates the first byte of the SKI. Defaults to `False`.
    :param rid: The `RecipientIdentifier` structure to set inside the `rid` field. Defaults to `None`.
    :return: A `RecipientIdentifier` structure ready to be included in `KeyAgreeRecipientInfo`.
    """
    key_rid = rfc5652.KeyAgreeRecipientIdentifier()
    if rid is not None:
        if rid.getName() == "issuerAndSerialNumber":
            key_rid["issuerAndSerialNumber"] = rid["issuerAndSerialNumber"]
            return key_rid
        if rid.getName() == "subjectKeyIdentifier":
            ski = rid["subjectKeyIdentifier"].asOctets()
        else:
            raise ValueError("Invalid recipient identifier type.")

    if cmp_cert is not None and ski is None:
        ski = certextractutils.get_field_from_certificate(cmp_cert, extension="ski")  # type: ignore
        ski: Optional[bytes]

    if ski is not None:
        ski = str_to_bytes(ski)
        if bad_ski:
            ski = utils.manipulate_first_byte(ski)

        r_key_id = rfc5652.RecipientKeyIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        r_key_id["subjectKeyIdentifier"] = ski
        key_rid["rKeyId"] = r_key_id
        return key_rid

    if issuer_and_ser is not None:
        key_rid["issuerAndSerialNumber"] = issuer_and_ser
        return key_rid

    if cmp_cert is not None:
        issuer_and_ser = prepare_issuer_and_serial_number(cmp_cert)
        key_rid["issuerAndSerialNumber"] = issuer_and_ser
        return key_rid

    raise ValueError("Either a certificate or issuer and serial number must be provided for the recipient identifier.")


@not_keyword
def prepare_recipient_encrypted_key(
    cmp_cert: Optional[rfc9480.CMPCertificate],
    encrypted_key: Optional[bytes],
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
) -> rfc5652.RecipientEncryptedKey:
    """Create a `RecipientEncryptedKey` structure.

    The `RecipientEncryptedKey` contains the encrypted key for a recipient.
    This function prepares this structure by specifying the recipient identifier
    and the encrypted key.

    :param cmp_cert: Certificate of the recipient (typically the CMP protection certificate).
    :param encrypted_key: Encrypted key material.
    :param issuer_and_ser: `IssuerAndSerialNumber` structure to set inside the `rid`. Defaults to `None`.
    :param rid: The `RecipientIdentifier` structure to set inside the `rid` field. Defaults to `None`.
    :return: A `RecipientEncryptedKey` structure ready to be included in `KeyAgreeRecipientInfo`.
    """
    recip_enc_key = rfc5652.RecipientEncryptedKey()

    recip_enc_key["rid"] = _prepare_key_agree_rid(
        cmp_cert=cmp_cert,
        issuer_and_ser=issuer_and_ser,
        bad_ski=False,
        rid=rid,
    )

    if encrypted_key is not None:
        recip_enc_key["encryptedKey"] = encrypted_key
    return recip_enc_key


@not_keyword
def prepare_recipient_encrypted_keys(
    cmp_prot_cert: rfc9480.CMPCertificate,
    enc_key: bytes,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    negative_size: bool = False,
):
    """Prepare a `RecipientEncryptedKeys` structure with one or more `RecipientEncryptedKey` entries.

    The `RecipientEncryptedKeys` contains the encrypted keys which are wrapped and then used to
    decrypt the private keys.

    :param cmp_prot_cert: A `CMPCertificate` object representing the recipient's certificate.
    :param enc_key: The encrypted key material as bytes.
    :param issuer_and_ser: Optional `IssuerAndSerialNumber` structure to set inside the `rid`.
    :param negative_size: If `True`, adds a duplicate entry for negative testing. Defaults to `False`.
    :return: The populated `RecipientEncryptedKeys` structure.
    """
    recipient_encrypted_keys = rfc5652.RecipientEncryptedKeys()

    recipient_encrypted_key = prepare_recipient_encrypted_key(cmp_prot_cert, enc_key, issuer_and_ser=issuer_and_ser)
    recipient_encrypted_keys.append(recipient_encrypted_key)
    if negative_size:
        recipient_encrypted_keys.append(recipient_encrypted_key)

    return recipient_encrypted_keys


@not_keyword
def prepare_key_agreement_alg_id(
    key_agree_oid: univ.ObjectIdentifier,
    key_wrap_alg: Union[str, univ.ObjectIdentifier] = "aes256_wrap",
) -> rfc5280.AlgorithmIdentifier:
    """Create an `AlgorithmIdentifier` for key agreement with ECC_CMS_SharedInfo.

    Prepares the key encryption algorithm identifier used in key agreement
    recipient info (`KeyAgreeRecipientInfo`). It includes the necessary parameters
    for deriving the key, such as the key wrap algorithm and shared information.

    :param key_agree_oid: OID for the key agreement algorithm.
    :param key_wrap_alg: The name of the key wrap algorithm. Defaults to "aes256_wrap".
    :raises KeyError: If the key wrap algorithm name is not supported.
    :return: An `AlgorithmIdentifier` structure ready to be included in `KeyAgreeRecipientInfo`.
    """
    if isinstance(key_wrap_alg, str):
        key_wrap_name = key_wrap_alg
        wrap_oid = KEY_WRAP_NAME_2_OID[key_wrap_name]
    else:
        wrap_oid = key_wrap_alg

    key_enc_alg_id = rfc5280.AlgorithmIdentifier()
    key_enc_alg_id["algorithm"] = key_agree_oid
    key_alg_id = rfc5753.KeyWrapAlgorithm()
    key_alg_id["algorithm"] = wrap_oid
    key_enc_alg_id["parameters"] = encoder.encode(key_alg_id)
    return key_enc_alg_id


# TODO fix for complete Support!!!
@not_keyword
def prepare_key_agreement_recipient_info(
    key_agreement_oid: univ.ObjectIdentifier,
    cmp_cert: Optional[rfc9480.CMPCertificate] = None,
    encrypted_key: Optional[bytes] = None,
    key_wrap_oid: univ.ObjectIdentifier = rfc9481.id_aes256_wrap,
    version: int = 3,
    ukm: Optional[bytes] = None,
    add_another: bool = False,
    issuer_and_ser_orig: Optional[rfc5652.IssuerAndSerialNumber] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    originator: Optional[rfc5652.OriginatorIdentifierOrKey] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
) -> rfc5652.KeyAgreeRecipientInfo:
    """Create a `KeyAgreeRecipientInfo` structure for key agreement.

    The `KeyAgreeRecipientInfo` provides information needed by recipients
    to perform key agreement and obtain the content encryption key.
    This function assembles this structure with the necessary parameters.

    :param cmp_cert: Certificate of the recipient (typically the CMP protection certificate).
    :param key_agreement_oid: OID for the key agreement algorithm.
    :param encrypted_key: Optional encrypted key material.
    :param key_wrap_oid: OID for the key wrap algorithm.
    :param version: Version of the CMS structure. Defaults to 3.
    :param ukm: Optional user keying material.
    :param add_another: If True, adds duplicate entries for negative testing.
    :param issuer_and_ser_orig: Optional `IssuerAndSerialNumber` structure to set inside the `originator`
    field. Defaults to `None`. Filled with the cmp-protection-cert.
    :param issuer_and_ser: Optional `IssuerAndSerialNumber` structure to set inside the `rid`.
    :param originator: The `OriginatorIdentifierOrKey` structure to set inside the `originator` field.
    Defaults to `None`. Filled with the cmp-protection-cert.
    (MUST be populated for POP.)
    :param rid: The `RecipientIdentifier` structure to set inside the `rid` field. Defaults to `None`.
    :return: A `KeyAgreeRecipientInfo` structure ready to be included in `EnvelopedData`.
    """
    if issuer_and_ser is None and cmp_cert is None:
        raise ValueError("Either a certificate or issuer and serial number must be provided.")

    key_agree_info = rfc5652.KeyAgreeRecipientInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )
    key_agree_info["version"] = version
    key_agree_info["originator"] = originator or prepare_originator_identifier_or_key(
        cert=cmp_cert, issuer_and_ser=issuer_and_ser_orig or issuer_and_ser
    )

    if ukm is not None:
        ukm_field = rfc5652.UserKeyingMaterial(ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        key_agree_info["ukm"] = ukm_field

    recipient_encrypted_key = prepare_recipient_encrypted_key(
        cmp_cert=cmp_cert,
        encrypted_key=encrypted_key,
        issuer_and_ser=issuer_and_ser,
        rid=rid,
    )
    recip_keys = rfc5652.RecipientEncryptedKeys()
    recip_keys.append(recipient_encrypted_key)
    if add_another:
        # Add duplicate recipient encrypted key for negative testing
        recip_keys.append(recipient_encrypted_key)

    key_agree_info["recipientEncryptedKeys"] = recip_keys

    key_agree_info["keyEncryptionAlgorithm"] = prepare_key_agreement_alg_id(
        key_agree_oid=key_agreement_oid,
        key_wrap_alg=key_wrap_oid,
    )

    return key_agree_info


def _prepare_aes_warp_alg_id(
    wrap_name: Optional[str], cek_length: int, fill_params_rand: bool = False
) -> rfc5280.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for AES key wrap algorithm.

    :param wrap_name: Name of the AES key wrap algorithm (e.g., "aes256-wrap"). Defaults to `None`.
    :param cek_length: Length of the content encryption key in bytes.
    :param fill_params_rand: If `True`, fill the parameters with random data. Defaults to `False`.
    (**MUST** be absent for AES key wrap algorithms.)
    :return: The populated `AlgorithmIdentifier` structure.
    """
    if wrap_name is None:
        if cek_length == 16:
            wrap_name = "aes128_wrap"
        elif cek_length == 32:
            wrap_name = "aes256_wrap"
        elif cek_length == 24:
            wrap_name = "aes192_wrap"
        else:
            raise ValueError(
                f"Unsupported AES key wrap length: {cek_length}. Expected 16, 24, or 32 bytes."
                f"If used for negative nesting testing, provide the key wrap algorithm name."
                f"(`wrap_name`)"
            )

    oid = KEY_WRAP_NAME_2_OID.get(wrap_name)
    if oid is None:
        raise KeyError(f"Unsupported AES key wrap algorithm: {wrap_name}. Supported are: {KEY_WRAP_NAME_2_OID.keys()}")

    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid

    if fill_params_rand:
        alg_id["parameters"] = univ.OctetString(os.urandom(32))

    return alg_id


@keyword(name="Prepare PasswordRecipientInfo")
def prepare_password_recipient_info(  # noqa D417 undocumented-param
    password: Union[str, bytes],
    version: Union[str, int] = 0,
    cek: Optional[bytes] = None,
    kdf_name: str = "pbkdf2",
    bad_encrypted_key: bool = False,
    exclude_kdf_alg_id: bool = False,
    **params,
) -> rfc5652.PasswordRecipientInfo:
    """Prepare a `PasswordRecipientInfo` structure for password-based encryption.

    The `PasswordRecipientInfo` structure is used to encrypt the content encryption key (CEK)
    using a password and a key derivation function (KDF). This function prepares the structure
    with the necessary parameters.

    Arguments:
    ---------
        - `password`: The password to use for encryption.
        - `version`: The version number for the `PasswordRecipientInfo` structure. Defaults to `0`.
        - `cek`: The content encryption key to encrypt. Defaults to a random 32-byte key.
        - `kdf_name`: The key derivation function to use. Defaults to "pbkdf2".
        (which is the only one allowed for `PasswordRecipientInfo`).
        - `bad_encrypted_key`: If `True`, manipulate the first byte of the encrypted key. Defaults to `False`.
        - `exclude_kdf_alg_id`: If `True`, excludes the key derivation algorithm identifier. Defaults to `False`.

    **params:
    ---------
        - `salt` (str, bytes): The salt value for the PasswordRecipientInfo structure. Defaults to 32 random bytes.
        (will be interpreted as hex if it starts with "0x").
        - `iterations` (str, int): The number of iterations for the key derivation function. Defaults to `100000`.
        - `key_length` (str, int): The length of the derived key. Defaults to 32.
        - `hash_alg` (str): The hash algorithm to use for the key derivation function. Defaults to "sha256".
        - `wrap_name` (str): The name of the AES key wrap algorithm (e.g., "aes256-wrap"). Defaults to `None`.

    Returns:
    -------
        - A `PasswordRecipientInfo` structure ready to be included in `EnvelopedData`.

    Raises:
    ------
        - NotImplementedError: If an unsupported KDF is provided. (only supports "pbkdf2").

    Examples:
    --------
    | ${pwri} = | Prepare PasswordRecipientInfo | password=${password} | cek=${cek} |

    """
    cek = cek or os.urandom(32)
    cek = str_to_bytes(cek)

    if kdf_name == "pbkdf2":
        salt = params.get("salt") or os.urandom(32)
        salt = str_to_bytes(salt)
        kdf_alg_id = prepare_alg_ids.prepare_pbkdf2_alg_id(
            salt=salt,
            iterations=int(params.get("iterations", 100000)),
            key_length=int(params.get("key_length", 32)),
            hash_alg=params.get("hash_alg", "sha256"),
        )
        encrypted_key = wrap_key_password_based_key_management_technique(
            password=password, key_to_wrap=cek, parameters=kdf_alg_id["parameters"]
        )

    elif kdf_name == "hkdf":
        hash_alg = params.get("hash_alg") or "sha256"
        kdf_alg_id = rfc9480.AlgorithmIdentifier()
        kdf_alg_id["algorithm"] = HKDF_NAME_2_OID[f"hkdf-{hash_alg}"]
        wrapping_key = cryptoutils.compute_hkdf(
            hash_alg=hash_alg,
            info=b"",
            length=int(params.get("key_length", 32)),
            salt=None,
            key_material=cek,
        )
        encrypted_key = keywrap.aes_key_wrap(wrapping_key=wrapping_key, key_to_wrap=cek)

    else:
        raise NotImplementedError(f"Unsupported KDF: {kdf_name}")

    pwri = rfc5652.PasswordRecipientInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
    )
    pwri["version"] = int(version)

    if not exclude_kdf_alg_id:
        pwri["keyDerivationAlgorithm"] = kdf_alg_id.subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0), cloneValueFlag=True
        )

    if params.get("aes_wrap"):
        pwri["keyEncryptionAlgorithm"] = _prepare_aes_warp_alg_id(params.get("wrap_name"), len(cek))

    pwri["keyEncryptionAlgorithm"]["algorithm"] = rfc9481.id_aes256_wrap

    if bad_encrypted_key:
        encrypted_key = utils.manipulate_first_byte(encrypted_key)

    pwri["encryptedKey"] = rfc5652.EncryptedKey(encrypted_key)
    return pwri


@not_keyword
def wrap_key_password_based_key_management_technique(
    password: Union[str, bytes], parameters: rfc8018.PBKDF2_params, key_to_wrap: bytes
) -> bytes:
    """Derive a key from a password using PBKDF2 parameters and wrap the given AES key using the derived key.

    :param password: The password used to derive the key.
    :param parameters: The PBKDF2 parameters used to derive the key.
    :param key_to_wrap: The AES key to be wrapped.
    :return: The wrapped (encrypted) AES key.
    """
    password = str_to_bytes(password)
    derive_key = cryptoutils.compute_pbkdf2_from_parameter(parameters, key=password)
    logging.debug("Prepare PWRI - Derived Key: %s", derive_key.hex())
    return keywrap.aes_key_wrap(wrapping_key=derive_key, key_to_wrap=key_to_wrap)


@not_keyword
def prepare_cmsori_for_kem_other_info(
    wrap_algorithm: rfc8418.KeyWrapAlgorithmIdentifier,
    kek_length: int,
    ukm: Optional[bytes],
) -> bytes:
    """Prepare the `CMSORIforKEMOtherInfo` structure for use in the KEM key derivation.

    :param wrap_algorithm: The key wrap algorithm identifier.
    :param kek_length: The length of the key encryption key (KEK) in bytes.
    :param ukm: The User Keying Material (UKM) as bytes, or None if absent.
    :return: The DER-encoded `CMSORIforKEMOtherInfo` structure as bytes.
    """
    obj = rfc9629.CMSORIforKEMOtherInfo()
    obj["wrap"] = wrap_algorithm
    obj["kekLength"] = kek_length
    if ukm is not None:
        obj["ukm"] = rfc9629.UserKeyingMaterial(ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    return encoder.encode(obj)


@not_keyword
def is_cmsori_kem_other_info_decode_able(ukm_der: bytes) -> bytes:
    """Check if the provided `CMSORIforKEMOtherInfo` is decode-able.

    :param ukm_der: The DER-encoded `CMSORIforKEMOtherInfo` structure.
    :return: The decoded `CMSORIforKEMOtherInfo` structure as bytes.
    :raises BadAsn1Data: If the provided data is not decode-able or had a remainder.
    """
    try_decode, rest = asn1utils.try_decode_pyasn1(ukm_der, rfc9629.CMSORIforKEMOtherInfo())  # type: ignore
    try_decode: rfc9629.CMSORIforKEMOtherInfo

    if rest:
        raise BadAsn1Data("CMSORIforKEMOtherInfo")

    return encoder.encode(try_decode)


@not_keyword
def get_digest_from_key_hash(
    key: Union[SignKey, VerifyKey],
) -> str:
    """Find the pyasn1 oid given the hazmat key instance and a name of a hashing algorithm.

    Only used for single key algorithms, not for composite keys.

    :param key: The private key instance, to determine the hash algorithm.
    :return: The matching hash algorithm or the default one "sha512".
    """
    if isinstance(key, (PQSignaturePrivateKey, PQSignaturePublicKey)):
        for x in PQ_SIG_PRE_HASH_NAME_2_OID:
            x: str
            if x.startswith(key.name):
                hash_alg = get_hash_from_oid(PQ_SIG_PRE_HASH_NAME_2_OID[x], only_hash=True)
                if hash_alg:
                    return hash_alg
                raise ValueError(f"Could not find a valid hash algorithm for {key.name}.")

    if isinstance(
        key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
            rsa.RSAPublicKey,
        ),
    ):
        return "sha256"

    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "sha512"

    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "shake256"

    if isinstance(key, (CompositeSig04PrivateKey, CompositeSig04PublicKey)):
        return "sha512"

    if isinstance(key, (CompositeSig03PrivateKey, CompositeSig03PublicKey)):
        return CMS_COMPOSITE03_OID_2_HASH[key.get_oid(use_pss=False, pre_hash=False)]

    return "sha512"
