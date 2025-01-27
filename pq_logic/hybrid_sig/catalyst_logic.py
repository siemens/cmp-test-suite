# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Union

import pyasn1.error
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480
from pyasn1_alt_modules.rfc4210 import CMPCertificate
from resources.certbuildutils import prepare_sig_alg_id, prepare_tbs_certificate, sign_cert
from resources.certutils import verify_cert_signature
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.cryptoutils import sign_data, verify_signature
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid
from resources.typingutils import PrivateKey, PrivateKeySig

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey

# Extension Object Identifiers (OIDs)
id_ce_subjectAltPublicKeyInfo = rfc5280.id_ce + (72,)
id_ce_altSignatureAlgorithm = rfc5280.id_ce + (73,)
id_ce_altSignatureValue = rfc5280.id_ce + (74,)





def prepare_subject_alt_public_key_info_extn(
    public_key: Union[PQSignaturePrivateKey, PQSignaturePublicKey], critical: bool
) -> rfc5280.Extension:
    """Prepare the subjectAltPublicKeyInfo extension.

    :param public_key: The alternative public key.
    :param critical: Whether the extension is critical.
    :return: The prepared Extension object.
    """
    if isinstance(public_key, PQSignaturePrivateKey):
        public_key = public_key.public_key()

    spki = subjectPublicKeyInfo_from_pubkey(public_key)  # type: ignore

    spki_ext = rfc5280.Extension()
    spki_ext["extnID"] = id_ce_subjectAltPublicKeyInfo
    spki_ext["critical"] = critical
    spki_ext["extnValue"] = univ.OctetString(encoder.encode(spki))
    return spki_ext


def _prepare_sig_alt_extn(alg_id: rfc5280.AlgorithmIdentifier, critical: bool) -> rfc5280.Extension:
    """
    Prepare the altSignatureAlgorithm extension.

    :param alg_id: The alternative AlgorithmIdentifier.
    :param critical: Whether the extension is critical.
    :return: The prepared Extension object.
    """
    alt_signature_algorithm_extension = rfc5280.Extension()
    alt_signature_algorithm_extension["extnID"] = id_ce_altSignatureAlgorithm
    alt_signature_algorithm_extension["critical"] = critical
    alt_signature_algorithm_extension["extnValue"] = univ.OctetString(encoder.encode(alg_id))

    return alt_signature_algorithm_extension


def prepare_alt_signature_value_extn(signature: bytes, critical: bool) -> rfc5280.Extension:
    """Prepare the altSignatureValue extension.

    :param signature: The alternative signature bytes.
    :param critical: Whether the extension is critical.
    :return: The prepared Extension object.
    """
    alt_signature_value_extension = rfc5280.Extension()
    alt_signature_value_extension["extnID"] = id_ce_altSignatureValue
    alt_signature_value_extension["critical"] = critical
    alt_signature_value_extension["extnValue"] = univ.OctetString(
        encoder.encode(AltSignatureValueExt.fromOctetString(signature))
    )
    return alt_signature_value_extension


def prepare_alt_signature_data(
    cert: rfc9480.CMPCertificate,
    exclude_alt_extensions: bool = False,
    only_tbs_cert: bool = False,
    exclude_signature_field: bool = False,
    exclude_first_spki: bool = False,
) -> bytes:
    """Prepare the data to be signed for the `altSignatureValue` extension by excluding the altSignatureValue extension.

    :param cert: The certificate to prepare data from.
    :param exclude_alt_extensions: Whether to exclude alternative extensions for the signature verification.
    :param only_tbs_cert: Whether to only include the `tbsCertificate` part of the certificate and
    exclude the `signatureAlgorithm` field.
    :return: DER-encoded bytes of the data to be signed.
    """
    tbs_cert = cert["tbsCertificate"]

    data = b""

    for field in tbs_cert.keys():
        if field == "extensions":
            pass
        elif field == "subjectPublicKeyInfo" and exclude_first_spki:
            pass
        elif field == "signature" and not exclude_signature_field:
            data += encoder.encode(tbs_cert[field])
        else:
            if tbs_cert[field].isValue:
                data += encoder.encode(tbs_cert[field])

    new_extn = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    exclude_extn = (
        [id_ce_altSignatureValue]
        if not exclude_alt_extensions
        else [id_ce_altSignatureValue, id_ce_altSignatureAlgorithm, id_ce_subjectAltPublicKeyInfo]
    )

    for x in cert["tbsCertificate"]["extensions"]:
        if x["extnID"] not in exclude_extn:
            new_extn.append(x)

    cert["tbsCertificate"]["extensions"] = new_extn
    data = encoder.encode(tbs_cert)

    if cert["signatureAlgorithm"].isValue and not only_tbs_cert:
        data += encoder.encode(cert["signatureAlgorithm"])

    return data


def sign_cert_catalyst(
    cert: rfc9480.CMPCertificate,
    pq_key: PQSignaturePrivateKey,
    trad_key,
    exclude_catalyst_extensions: bool = False,
    pq_hash_alg: Optional[str] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    critical: bool = False,
):
    """Sign the certificate with both traditional and alternative algorithms and adding the catalyst extensions.

    :param cert: The certificate to sign.
    :param pq_key: The post-quantum private key for alternative signing.
    :param trad_key: The traditional private key for native signing.
    :param exclude_catalyst_extensions: If True, exclude catalyst extensions (Not implemented).
    :param pq_hash_alg: Hash algorithm for the post-quantum signature.
    :param hash_alg: Hash algorithm for the native signature.
    :param use_rsa_pss: Whether to use RSA-PSS for native signing.
    :param critical: Whether the catalyst extensions are critical.
    :return: The signed certificate.
    """
    if exclude_catalyst_extensions:
        raise NotImplementedError("Excluding catalyst extensions is not implemented.")

    alt_alg_id = prepare_sig_alg_id(pq_key, hash_alg=pq_hash_alg, use_rsa_pss=use_rsa_pss)
    trad_alg_id = prepare_sig_alg_id(trad_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    cert["tbsCertificate"]["signature"] = trad_alg_id
    cert["signatureAlgorithm"] = trad_alg_id

    cert["tbsCertificate"]["extensions"].append(_prepare_sig_alt_extn(alt_alg_id, critical=critical))

    cert["tbsCertificate"]["extensions"].append(
        prepare_subject_alt_public_key_info_extn(public_key=pq_key.public_key(), critical=critical)
    )

    alt_sig_data = prepare_alt_signature_data(cert)

    alt_signature = sign_data(data=alt_sig_data, key=pq_key, hash_alg=pq_hash_alg)

    alt_extn = _prepare_alt_signature_value(signature=alt_signature, critical=critical)
    cert["tbsCertificate"]["extensions"].append(alt_extn)

    return sign_cert(signing_key=trad_key, cert=cert, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)


def validate_catalyst_extension(cert: rfc9480.CMPCertificate) -> Union[None, dict]:
    """Check if the certificate contains all required catalyst extensions.

    Required Extensions:
    - subjectAltPublicKeyInfo
    - altSignatureAlgorithm
    - altSignatureValue

    :param cert: The certificate to check.
    :return: A dictionary with extension values if all are present, else None.
    :raises ValueError: If only some catalyst extensions are present or if extensions are malformed.
    """
    required_extensions = {id_ce_subjectAltPublicKeyInfo, id_ce_altSignatureAlgorithm, id_ce_altSignatureValue}

    if not cert["tbsCertificate"]["extensions"].isValue:
        return None

    extensions = {}
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] in required_extensions:
            extensions[ext["extnID"]] = ext["extnValue"]

    if len(extensions) == 0:
        return None
    elif len(extensions) != 3:
        raise ValueError("Certificate must include either all or none of the catalyst extensions.")

    try:
        subject_alt_public_key_info = decoder.decode(
            extensions[id_ce_subjectAltPublicKeyInfo], asn1Spec=rfc5280.SubjectPublicKeyInfo()
        )[0]

        alt_signature_algorithm = decoder.decode(
            extensions[id_ce_altSignatureAlgorithm], asn1Spec=rfc5280.AlgorithmIdentifier()
        )[0]

        alt_signature_value, rest = decoder.decode(extensions[id_ce_altSignatureValue], asn1Spec=AltSignatureValueExt())

        if rest:
            raise ValueError("Invalid altSignatureValue extension content.")

        return {
            "signature": alt_signature_value.asOctets(),
            "spki": subject_alt_public_key_info,
            "alg_id": alt_signature_algorithm,
        }

    except pyasn1.error.PyAsn1Error as e:
        raise ValueError(f"Invalid extension content or verification error: {e}")


def verify_catalyst_signature_migrated(
    cert: rfc9480.CMPCertificate,
    issuer_pub_key: Optional[PrivateKeySig] = None,
    exclude_alt_extensions: bool = False,
    only_tbs_cert: bool = False,
) -> None:
    """Verify the alternative signature for migrated relying parties.

    First verify native signature to ensure certificate authenticity and then
    verify the alternative signature by excluding the altSignatureValue extension.

    :param cert: The certificate to verify.
    :param issuer_pub_key: The issuer's public key for native signature verification.
    :param exclude_alt_extensions: Whether to exclude alternative extensions for the signature verification.
    :param only_tbs_cert: Whether to only include the `tbsCertificate` part of the certificate and
    exclude the `signatureAlgorithm` field.
    :raises ValueError: If catalyst extensions are missing or verification fails.
    :raises InvalidSignature: If the traditional signature or the alternative signature verification fails.
    """
    catalyst_ext = validate_catalyst_extension(cert)
    if catalyst_ext is None:
        raise ValueError("Catalyst extensions are not present, cannot perform migrated verification.")

    # Step 1: Verify the native signature
    issuer_pub_key = issuer_pub_key or load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
    verify_cert_signature(cert=cert, issuer_pub_key=issuer_pub_key)

    # Step 2: Verify the alternative signature
    pq_pub_key = CombinedKeyFactory.load_public_key_from_spki(catalyst_ext["spki"])
    hash_alg = get_hash_from_oid(catalyst_ext["alg_id"]["algorithm"], only_hash=True)

    alt_sig_data = prepare_alt_signature_data(
        cert, exclude_alt_extensions=exclude_alt_extensions, only_tbs_cert=only_tbs_cert
    )

    verify_signature(public_key=pq_pub_key, hash_alg=hash_alg, data=alt_sig_data, signature=catalyst_ext["signature"])

    logging.info("Alternative signature verification succeeded.")


def verify_catalyst_signature(
    cert: rfc9480.CMPCertificate,
    issuer_pub_key: Optional[PrivateKeySig] = None,
    include_extensions: bool = True,
    migrated: bool = False,
):
    """Verify the certificate's signature, handling both native and alternative signatures.

    The verification is based on whether the relying party has migrated.

    :param cert: The certificate to verify.
    :param issuer_pub_key: The issuer's public key for native signature verification.
    :param include_extensions: Whether to include catalyst extensions in native verification.
    :param migrated: Whether the relying party has migrated to support alternative signatures.
    :raises ValueError: If verification fails due to missing extensions or signature mismatches.
    :raises NotImplementedError: If certain verification paths are not implemented.
    """
    catalyst_ext = validate_catalyst_extension(cert)
    public_key2 = load_public_key_from_spki(catalyst_ext["spki"])

    if not migrated:
        if catalyst_ext:
            logging.info("Catalyst extensions detected. Verifying native signature.")
            if include_extensions:
                verify_cert_signature(cert=cert, issuer_pub_key=issuer_pub_key)
            else:
                raise NotImplementedError("Excluding extensions is not supported for non-migrated parties.")
        else:
            raise ValueError("No catalyst extensions present.")

    else:
        if catalyst_ext:
            logging.info("Migrated relying party: Verifying alternative signature.")
            verify_catalyst_signature_migrated(cert, public_key2)
        else:
            logging.info("No catalyst extensions present. Verifying native signature.")
            verify_cert_signature(cert=cert, issuer_pub_key=issuer_pub_key)


def build_catalyst_cert(
    trad_key: TradSigPrivKey,
    pq_key: PQSignaturePrivateKey,
    client_key: PrivateKey,
    common_name: str = "CN=Hans Mustermann",
    use_pss: bool = False,
    extensions: Optional[rfc5280.Extensions] = None,
) -> CMPCertificate:
    """Generate a catalyst certificate combining traditional and post-quantum keys.

    :param trad_key: The traditional private key (e.g., RSA) used for signing the certificate.
    :param pq_key: The post-quantum private key.
    :param client_key: The client key to create the certificate for.
    :param common_name: The subject's common name (CN) for the certificate. Defaults to "CN=Hans Mustermann".
    :param use_pss: Whether to use RSA-PSS for signing. Defaults to `False`.
    :param extensions: Optional extensions to include in the certificate.
    :return: The created `CMPCertificate`.
    """
    tbs_cert = prepare_tbs_certificate(
        subject=common_name,
        signing_key=trad_key,
        public_key=client_key.public_key(),
        use_rsa_pss=use_pss,
        extensions=extensions,
    )

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_cert
    return sign_cert_catalyst(cert, trad_key=trad_key, pq_key=pq_key, use_rsa_pss=use_pss)


def load_catalyst_public_key(extensions: rfc9480.Extensions) -> PublicKey:
    """Load a public key from the newly defined AltPublicKeyInfo extension.

    :param extensions: The extensions to load the public key from.
    :return: The loaded public key.
    :raises ValueError: If the extension is not found.
    """
    extn_alt_spki = get_extension(extensions, id_ce_subjectAltPublicKeyInfo)
    if extn_alt_spki is None:
        raise ValueError("AltPublicKeyInfo extension not found.")

    spki, rest = decoder.decode(extn_alt_spki["extnValue"].asOctets(), SubjectAltPublicKeyInfoExt())
    if rest:
        raise BadAsn1Data("The alternative public key extension contains remainder data.", overwrite=True)
    alt_issuer_key = load_public_key_from_spki(spki)
    return alt_issuer_key
