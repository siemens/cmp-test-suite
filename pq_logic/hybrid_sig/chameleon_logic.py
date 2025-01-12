# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, List, Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480

from pq_logic.tmp_oids import id_ce_deltaCertificateDescriptor, id_at_deltaCertificateRequestSignature, \
    id_at_deltaCertificateRequest
from resources.certbuildutils import build_csr, prepare_name, prepare_sig_alg_id
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.copyasn1utils import copy_name
from resources.cryptoutils import sign_data
from resources.oid_mapping import get_hash_from_oid
from resources.typingutils import PrivateKeySig

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.hybrid_sig.certdiscovery import compare_alg_id_without_tag
from pq_logic.hybrid_structures import (
    DeltaCertificateDescriptor,
    DeltaCertificateRequestSignatureValue,
    DeltaCertificateRequestValue,
)
from pq_logic.pq_compute_utils import verify_csr_signature
from pq_logic.py_verify_logic import verify_signature_with_alg_id


def _prepare_issuer_and_subject(
    dcd: DeltaCertificateDescriptor, delta_cert: rfc9480.CMPCertificate, base_cert: rfc9480.CMPCertificate
):
    """Prepare the issuer and subject fields for the DCD extension, add them, if they differ.

    :param dcd: The `DeltaCertificateDescriptor` to populate.
    :param delta_cert: Parsed Delta Certificate structure.
    :param base_cert: Parsed Base Certificate structure.
    :return: The may updated `DeltaCertificateDescriptor` structure.
    """
    if not compare_pyasn1_names(delta_cert["tbsCertificate"]["issuer"], base_cert["tbsCertificate"]["issuer"]):
        issuer_obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        issuer = copy_name(delta_cert["tbsCertificate"]["issuer"], name=issuer_obj)
        dcd["issuer"] = issuer

    if not compare_pyasn1_names(delta_cert["tbsCertificate"]["subject"], base_cert["tbsCertificate"]["subject"]):
        subject_obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        subject = copy_name(delta_cert["tbsCertificate"]["subject"], name=subject_obj)
        dcd["subject"] = subject

    return dcd


def prepare_dcd_extension_from_delta(delta_cert, base_cert):
    """Prepare a Delta Certificate Descriptor (DCD) extension from a parsed Delta Certificate and Base Certificate.

    :param delta_cert: Parsed Delta Certificate structure.
    :param base_cert: Parsed Base Certificate structure.
    :return: A DeltaCertificateDescriptor instance.

    Fields:
    - `serialNumber`: Serial number of the Delta Certificate.
    - `signature`: Algorithm used for signing the Delta Certificate (if it differs from the Base Certificate).
    - `issuer`: Distinguished name of the issuer in the Delta Certificate (if it differs from the Base Certificate).
    - `validity`: Validity period of the Delta Certificate (if it differs from the Base Certificate).
    - `subject`: Subject name of the Delta Certificate (if it differs from the Base Certificate).
    - `subjectPublicKeyInfo`: Public key information specific to the Delta Certificate.
    - `extensions`: List of extensions that differ between the Delta and Base Certificates.
    - `signatureValue`: Signature of the Delta Certificate.
    """
    dcd = DeltaCertificateDescriptor()

    dcd["serialNumber"] = delta_cert["tbsCertificate"]["serialNumber"]

    same_alg_id = compare_alg_id_without_tag(
        delta_cert["tbsCertificate"]["signature"], base_cert["tbsCertificate"]["signature"]
    )

    if not same_alg_id:
        # TODO fix
        dcd["signature"]["algorithm"] = delta_cert["tbsCertificate"]["signature"]["algorithm"]

    same_issuer = compare_pyasn1_names(delta_cert["tbsCertificate"]["issuer"], base_cert["tbsCertificate"]["issuer"])

    if not same_issuer:
        obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        name_obj = copy_name(delta_cert["tbsCertificate"]["issuer"], name=obj)
        dcd["issuer"] = name_obj

    val1 = encoder.encode(delta_cert["tbsCertificate"]["validity"])
    val2 = encoder.encode(base_cert["tbsCertificate"]["validity"])

    if val1 != val2:
        dcd["validity"] = delta_cert["tbsCertificate"]["validity"]

    same_subject = compare_pyasn1_names(delta_cert["tbsCertificate"]["subject"], base_cert["tbsCertificate"]["subject"])

    if not same_subject:
        obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        name_obj = copy_name(delta_cert["tbsCertificate"]["subject"], name=obj)
        dcd["subject"] = name_obj

    dcd["subjectPublicKeyInfo"] = delta_cert["tbsCertificate"]["subjectPublicKeyInfo"]

    # Include differing extensions, if any
    differing_extensions = _prepare_dcd_extensions(delta_cert, base_cert)
    if differing_extensions:
        dcd["extensions"] = rfc5280.Extensions(differing_extensions)

    dcd["signatureValue"] = delta_cert["signature"]

    return dcd


def _prepare_dcd_extensions(
    delta_certificate, base_certificate, exclude_extensions: bool = False
) -> List[rfc5280.Extension]:
    """Prepare the extensions field of the DCD extension by comparing the base and delta certificate.

    :param delta_certificate: Parsed Delta Certificate structure.
    :param base_certificate: Parsed Base Certificate structure.
    :return: A list of differing extensions.
    """
    if exclude_extensions:
        return []

    base_extensions = {ext["extnID"]: ext for ext in base_certificate["tbsCertificate"]["extensions"]}
    delta_extensions = {ext["extnID"]: ext for ext in delta_certificate["tbsCertificate"]["extensions"]}

    """
    If the extensions field is absent, then all extensions in the Delta Certificate 
    MUST have the same criticality and DER-encoded value as the Base Certificate 
    (except for the DCD extension, which MUST be absent from the Delta Certificate)
    """

    differing_extensions = []
    for ext_id, ext in delta_extensions.items():
        if ext_id == id_ce_deltaCertificateDescriptor:
            continue  # Skip the DCD extension itself

        if ext_id not in base_extensions:
            differing_extensions.append(ext)
        elif base_extensions.get(ext_id) is not None:
            if encoder.encode(base_extensions[ext_id]) == encoder.encode(ext):
                differing_extensions.append(ext)

    # Ensure no invalid extensions are included
    #  pass

    return differing_extensions


### as of Section 4.2. Issuing a Base Certificate


def issue_base_certificate(
    delta_cert: rfc9480.CMPCertificate,
    base_tbs_cert: rfc5280.TBSCertificate,
    ca_key: PrivateKeySig,
    use_rsa_pss: bool = False,
) -> rfc9480.CMPCertificate:
    """Issue a Base Certificate with the Delta Certificate Descriptor (DCD) extension.

    :param use_rsa_pss:
    :param delta_cert: Parsed Delta Certificate structure.
    :param base_tbs_cert: TBSCertificate structure for the Base Certificate to be issued
    :param ca_key: Private key of the Certification Authority (CA) for signing the Base Certificate.
    :return: A fully signed Base Certificate structure.
    """
    # As of Section 4 Note:
    # The inclusion of the DCD extension within a Base Certificate is not a statement from the
    # issuing Certification Authority of the Base Certificate that the contents of the Delta
    # Certificate have been verified.

    # The Delta Certificate will necessarily need to be issued prior
    # to the issuance of the Base Certificate.

    # To simplify reconstruction of the Delta Certificate, the signatures for Base and Delta Certificates
    # MUST be calculated over the DER encoding of the TBSCertificate structure.

    # Some features are Policy dependent: For example, a policy may require that the
    # validity periods of the Base Certificate and Delta Certificate be identical, or that if the
    # Delta Certificate is revoked, the Base Certificate must also be revoked.

    hash_alg = get_hash_from_oid(delta_cert["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    base_cert = rfc9480.CMPCertificate()
    base_cert["tbsCertificate"] = base_tbs_cert

    dcd = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)

    dcd_extension = rfc5280.Extension()
    dcd_extension["extnID"] = id_ce_deltaCertificateDescriptor
    dcd_extension["critical"] = False
    dcd_extension["extnValue"] = univ.OctetString(encoder.encode(dcd))
    base_tbs_cert["extensions"].append(dcd_extension)

    tbs_base_der = encoder.encode(base_tbs_cert)
    base_signature = sign_data(data=tbs_base_der, key=ca_key, hash_alg=hash_alg)

    base_cert = rfc9480.CMPCertificate()
    sig_alg = prepare_sig_alg_id(use_rsa_pss=use_rsa_pss, signing_key=ca_key, hash_alg=hash_alg)
    base_cert["tbsCertificate"] = base_tbs_cert
    base_cert["signatureAlgorithm"] = sig_alg
    base_cert["signature"] = univ.BitString.fromOctetString(base_signature)

    return base_cert


def validate_dcd_extension(dcd_extensions: rfc5280.Extensions, base_cert_extensions: rfc5280.Extensions) -> None:
    """Validate the DCD extension to ensure it meets the defined constraints.

    :param dcd_extensions: Extensions contained in the DCD.
    :param base_cert_extensions: Extensions contained in the Base Certificate.
    :raises ValueError: If any invalid extension is detected in the DCD.
    """
    base_cert_ext_map = {ext["extnID"]: ext for ext in base_cert_extensions}

    for dcd_ext in dcd_extensions:
        ext_id = dcd_ext["extnID"]

        # Step 1: DCD MUST NOT contain the extension if it matches Base Certificate's criticality + value
        if ext_id in base_cert_ext_map:
            base_ext = base_cert_ext_map[ext_id]
            if dcd_ext["critical"] == base_ext["critical"] and dcd_ext.asOctets() == base_ext.asOctets():
                raise ValueError(
                    f"Invalid extension in DCD: Extension with ID {ext_id} is identical to one in the Base Certificate."
                )

        # Step 2: DCD MUST NOT contain extensions whose type does not appear in the Base Certificate
        # (i.e., extnID is not in the Base Certificate's extensions and is not the DCD extension type)
        if ext_id not in base_cert_ext_map and ext_id != id_ce_deltaCertificateDescriptor:
            raise ValueError(
                f"Invalid extension in DCD: Extension with ID {ext_id} is not present in the Base Certificate."
            )

        # Step 3: DCD MUST NOT contain an extension of the DCD type (recursive DCD extensions are forbidden)
        if ext_id == id_ce_deltaCertificateDescriptor:
            raise ValueError(f"Invalid extension in DCD: Recursive DCD extensions (ID {ext_id}) are not allowed.")


#################
# CSR
#################


def prepare_delta_cert_req(
    signing_key: PrivateKeySig,
    delta_common_name: Optional[str] = None,
    extensions: Optional[rfc5280.Extensions] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    omit_sig_alg_id: bool = False,
) -> DeltaCertificateRequestValue:
    if not signing_key:
        raise ValueError("SubjectPublicKeyInfo is required.")

    delta_req = DeltaCertificateRequestValue()

    if delta_common_name:
        name = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        parsed_name = prepare_name(delta_common_name, target=name)
        delta_req["subject"] = parsed_name

    delta_req["subjectPKInfo"] = subjectPublicKeyInfo_from_pubkey(signing_key.public_key())

    if extensions:
        delta_req["extensions"].extend(extensions)

    if not omit_sig_alg_id:
        sig_alg_id = prepare_sig_alg_id(signing_key=signing_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)
        alg_id = rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        )

        alg_id["algorithm"] = sig_alg_id["algorithm"]
        alg_id["parameters"] = sig_alg_id["parameters"]

        delta_req["signatureAlgorithm"] = alg_id

    return delta_req


def _prepare_attr(attr_type: univ.ObjectIdentifier, attr_value: Any) -> rfc5652.Attribute:
    """Prepare an attribute for a CSR.

    :param attr_type: The Object Identifier (OID) for the attribute.
    :param attr_value: The value of the attribute to be encoded.
    :return: The populated `Attribute` structure.
    """
    attr = rfc5652.Attribute()
    attr["attrType"] = attr_type
    attr["attrValues"][0] = encoder.encode(attr_value)
    return attr


def build_paired_csrs(
    base_private_key,
    delta_private_key,
    base_common_name: str = "CN=Hans Mustermann",
    delta_common_name: Optional[str] = None,
    base_extensions: Optional[rfc5280.Extensions] = None,
    delta_extensions: Optional[rfc5280.Extensions] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
) -> rfc6402.CertificationRequest:
    """Create a paired CSR for Paired Certificates.

    :param base_common_name: Subject of the Base Certificate.
    :param base_extensions: Extensions for the Base Certificate.
    :param base_private_key: Private key for signing the Base Certificate CSR.
    :param delta_common_name: Subject of the Delta Certificate (optional).
    :param delta_extensions: Extensions for the Delta Certificate (optional).
    :param delta_private_key: Private key for signing the Delta Certificate CSR.
    :param hash_alg: Hash algorithm used for signing.
    :param use_rsa_pss: Whether to use PSS-padding for signing.
    :return: Combined Certification Request for Paired Certificates.
    """
    # Step 1: Build certificationRequestInfo
    base_csr = build_csr(
        signing_key=base_private_key,
        extensions=base_extensions,
        common_name=base_common_name,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        exclude_signature=True,
    )

    # Step 2: Prepare attribute.
    delta_request = prepare_delta_cert_req(
        signing_key=delta_private_key,
        extensions=delta_extensions,
        delta_common_name=delta_common_name,
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
    )

    # Step 3: Add attribute.
    delta_cert_attr = _prepare_attr(id_at_deltaCertificateRequest, delta_request)
    base_csr["certificationRequestInfo"]["attributes"].append(delta_cert_attr)

    # Step 4: Sign the CertificationRequestInfo using the private key of the delta certificate
    # request subject
    tmp_der_data = encoder.encode(base_csr["certificationRequestInfo"])
    delta_signature = sign_data(data=tmp_der_data, key=delta_private_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    # Step 5: Prepare
    delta_sig_attr = _prepare_attr(
        id_at_deltaCertificateRequestSignature, DeltaCertificateRequestSignatureValue.fromOctetString(delta_signature)
    )

    # Step 6: Add attribute.
    base_csr["certificationRequestInfo"]["attributes"].append(delta_sig_attr)

    # Step 7: Sign.
    base_csr_info = encoder.encode(base_csr["certificationRequestInfo"])
    base_signature = sign_data(data=base_csr_info, key=base_private_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)

    base_csr["signatureAlgorithm"] = prepare_sig_alg_id(
        signing_key=base_private_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
    )

    base_csr["signature"] = univ.BitString.fromOctetString(base_signature)

    base_csr, _ = decoder.decode(encoder.encode(base_csr), rfc6402.CertificationRequest())

    return base_csr


###################
# Server side
###################


def _extract_attributes(attributes):
    """
    Extract attributes from the CSR, excluding the signature attribute.

    :param attributes: The list of attributes in the CertificationRequestInfo.
    :return: A tuple containing:
        - All attributes except the signature one.
        - The Delta Certificate Request attribute.
        - The Delta Certificate Request Signature attribute.
    """
    non_signature_attributes = []
    delta_cert_request = None
    delta_cert_request_signature = None

    for attr in attributes:
        if attr["attrType"] == id_at_deltaCertificateRequest:
            delta_cert_request = decoder.decode(attr["attrValues"][0], asn1Spec=DeltaCertificateRequestValue())[0]
            non_signature_attributes.append(attr)
        elif attr["attrType"] == id_at_deltaCertificateRequestSignature:
            delta_cert_request_signature = decoder.decode(
                attr["attrValues"][0], asn1Spec=DeltaCertificateRequestSignatureValue()
            )[0]

        else:
            non_signature_attributes.append(attr)

    return non_signature_attributes, delta_cert_request, delta_cert_request_signature


# TODO fix doc
def verify_paired_csr_signature(csr: rfc6402.CertificationRequest) -> None:
    """Verify the signature of a paired CSR.

    :param csr: The CertificationRequest to verify.
    :raises ValueError: If the Delta Certificate Request attribute is missing.

    """
    verify_csr_signature(csr=csr)
    attributes = csr["certificationRequestInfo"]["attributes"]
    attributes, delta_req, delta_sig = _extract_attributes(attributes)

    if delta_req is None:
        raise ValueError("Delta Certificate Request attribute is missing.")
    if delta_sig is None:
        raise ValueError("Delta Certificate Request Signature attribute is missing.")

    # Step 3: Remove the delta certificate request signature attribute
    # from the CertificationRequest template
    attr = univ.SetOf(componentType=rfc5652.Attribute()).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    attr.extend(attributes)
    csr["certificationRequestInfo"]["attributes"] = attr
    if delta_req["signatureAlgorithm"].isValue:
        sig_alg_id = delta_req["signatureAlgorithm"]
    else:
        sig_alg_id = csr["signatureAlgorithm"]

    if not delta_req["subjectPKInfo"].isValue:
        raise ValueError("Delta Certificate Request 'subjectPKInfo' is missing.")

    public_key = CombinedKeyFactory.load_public_key_from_spki(delta_req["subjectPKInfo"])

    data = encoder.encode(csr["certificationRequestInfo"])
    verify_signature_with_alg_id(alg_id=sig_alg_id, data=data, public_key=public_key, signature=delta_sig.asOctets())
