# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Logic for building/validating Chameleon certificates/certification requests."""

from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480
from resources.certbuildutils import (
    build_cert_from_csr,
    build_csr,
    csr_add_extensions,
    prepare_sig_alg_id,
    prepare_single_value_attr,
    sign_cert,
)
from resources.certextractutils import get_extension
from resources.compareutils import compare_alg_id_without_tag, compare_pyasn1_names
from resources.convertutils import copy_asn1_certificate, subjectPublicKeyInfo_from_pubkey
from resources.copyasn1utils import copy_name, copy_validity
from resources.cryptoutils import sign_data
from resources.exceptions import BadAsn1Data, BadPOP
from resources.oid_mapping import get_hash_from_oid
from resources.prepareutils import prepare_name
from resources.typingutils import PrivateKeySig
from robot.api.deco import not_keyword

from pq_logic import pq_compute_utils
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.hybrid_structures import (
    DeltaCertificateDescriptor,
    DeltaCertificateRequestSignatureValue,
    DeltaCertificateRequestValue,
)
from pq_logic.tmp_oids import (
    id_at_deltaCertificateRequest,
    id_at_deltaCertificateRequestSignature,
    id_ce_deltaCertificateDescriptor,
)


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


def prepare_dcd_extension_from_delta(delta_cert: rfc9480.CMPCertificate, base_cert: rfc9480.CMPCertificate):
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
        dcd["signature"]["algorithm"] = delta_cert["tbsCertificate"]["signature"]["algorithm"]

    same_issuer = compare_pyasn1_names(delta_cert["tbsCertificate"]["issuer"], base_cert["tbsCertificate"]["issuer"])

    if not same_issuer:
        obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        name_obj = copy_name(filled_name=delta_cert["tbsCertificate"]["issuer"], target=obj)
        dcd["issuer"] = name_obj

    val1 = encoder.encode(delta_cert["tbsCertificate"]["validity"])
    val2 = encoder.encode(base_cert["tbsCertificate"]["validity"])

    if val1 != val2:
        dcd["validity"] = delta_cert["tbsCertificate"]["validity"]

    same_subject = compare_pyasn1_names(delta_cert["tbsCertificate"]["subject"], base_cert["tbsCertificate"]["subject"])

    if not same_subject:
        obj = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        name_obj = copy_name(filled_name=delta_cert["tbsCertificate"]["subject"], target=obj)
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
    """  # noqa: W291 Trailing whitespace

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


def build_chameleon_base_certificate(
    delta_cert: rfc9480.CMPCertificate,
    base_tbs_cert: rfc5280.TBSCertificate,
    ca_key: PrivateKeySig,
    use_rsa_pss: bool = False,
    hash_alg: Optional[str] = None,
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

    hash_alg = hash_alg or get_hash_from_oid(delta_cert["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    base_cert = rfc9480.CMPCertificate()
    base_cert["tbsCertificate"] = base_tbs_cert

    dcd = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)

    dcd_extension = rfc5280.Extension()
    dcd_extension["extnID"] = id_ce_deltaCertificateDescriptor
    dcd_extension["critical"] = False
    dcd_extension["extnValue"] = univ.OctetString(encoder.encode(dcd))
    base_tbs_cert["extensions"].append(dcd_extension)

    base_cert = rfc9480.CMPCertificate()
    base_cert["tbsCertificate"] = base_tbs_cert
    base_cert = sign_cert(cert=base_cert, signing_key=ca_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)
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
    """Prepare a Delta Certificate Request.

    :param signing_key: The private key of the subject of the Delta Certificate.
    :param delta_common_name: The subject name of the Delta Certificate.
    :param extensions: The extensions for the Delta Certificate.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use PSS-padding for signing. Defaults to False.
    :param omit_sig_alg_id: Whether to omit the signature algorithm ID. Defaults to False.
    :return: The populated `DeltaCertificateRequestValue` structure.
    """
    if not signing_key:
        raise ValueError("SubjectPublicKeyInfo is required.")

    delta_req = DeltaCertificateRequestValue()

    if delta_common_name:
        name = rfc5280.Name().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        parsed_name = prepare_name(delta_common_name, target=name)
        delta_req["subject"] = parsed_name

    delta_req["subjectPKInfo"] = subjectPublicKeyInfo_from_pubkey(signing_key.public_key())

    if extensions is not None:
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
    delta_cert_attr = prepare_single_value_attr(id_at_deltaCertificateRequest, delta_request)
    base_csr["certificationRequestInfo"]["attributes"].append(delta_cert_attr)

    # Step 4: Sign the CertificationRequestInfo using the private key of the delta certificate
    # request subject
    tmp_der_data = encoder.encode(base_csr["certificationRequestInfo"])
    delta_signature = sign_data(data=tmp_der_data, key=delta_private_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    # Step 5: Prepare
    delta_sig_attr = prepare_single_value_attr(
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


@not_keyword
def extract_chameleon_attributes(
    csr: rfc6402.CertificationRequest,
) -> Tuple[List[rfc5652.Attribute], DeltaCertificateRequestValue, DeltaCertificateRequestSignatureValue]:
    """
    Extract attributes from the CSR, excluding the signature attribute.

    :param csr: The `CertificationRequest` to extract attributes from.
    :return: A tuple containing:
        - All attributes except the signature one.
        - The Delta Certificate Request attribute.
        - The Delta Certificate Request Signature attribute.
    """
    non_signature_attributes = []
    delta_cert_request = None
    delta_cert_request_signature = None

    attributes = csr["certificationRequestInfo"]["attributes"]

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


def verify_paired_csr_signature(  # noqa: D417 Missing argument description in the docstring
    csr: rfc6402.CertificationRequest,
) -> DeltaCertificateRequestValue:
    """Verify the signature of a paired CSR.

    Arguments:
    ---------
       - `csr`: The CertificationRequest to verify.

    Returns:
    -------
         - The Delta Certificate Request attribute.

    Raises:
    ------
        - ValueError: If the Delta Certificate Request attribute is missing.
        - BadPOP: If the signature is invalid.

    """
    pq_compute_utils.verify_csr_signature(csr=csr)
    attributes, delta_req, delta_sig = extract_chameleon_attributes(csr=csr)

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
    try:
        pq_compute_utils.verify_signature_with_alg_id(
            alg_id=sig_alg_id, data=data, public_key=public_key, signature=delta_sig.asOctets()
        )
    except InvalidSignature:
        raise BadPOP("Invalid signature")

    return delta_req


def build_delta_cert(
    csr: rfc6402.CertificationRequest,
    delta_value: DeltaCertificateRequestValue,
    ca_key: PrivateKeySig,
    ca_cert: rfc9480.CMPCertificate,
    alt_sign_key: Optional[PrivateKeySig] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
) -> rfc9480.CMPCertificate:
    """Prepare a Delta Certificate from a paired CSR.

    :param csr: The paired CSR.
    :param delta_value: The Delta Certificate Request attribute.
    :param ca_key: The CA key for signing the certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param alt_sign_key: An alternative signing key for the certificate.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use PSS-padding for signing. Defaults to False.
    :return: The populated `TBSCertificate` structure.
    """
    csr_tmp = rfc6402.CertificationRequest()

    if delta_value["subject"].isValue:
        csr_tmp["certificationRequestInfo"]["subject"] = delta_value["subject"]
    else:
        csr_tmp["certificationRequestInfo"]["subject"] = csr["certificationRequestInfo"]["subject"]

    csr_tmp["certificationRequestInfo"]["subjectPublicKeyInfo"] = delta_value["subjectPKInfo"]

    if delta_value["extensions"].isValue:
        csr_tmp = csr_add_extensions(
            csr_tmp,
            delta_value["extensions"],
        )

    return build_cert_from_csr(csr=csr_tmp, ca_key=ca_key, ca_cert=ca_cert, alt_sign_key=alt_sign_key)


def build_chameleon_cert_from_paired_csr(
    csr: rfc6402.CertificationRequest,
    ca_key: PrivateKeySig,
    ca_cert: rfc9480.CMPCertificate,
    alt_key: Optional[PrivateKeySig] = None,
    use_rsa_pss: bool = False,
    hash_alg: str = "sha256",
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a paired certificate from a paired CSR.

    :param csr: The paired CSR.
    :param ca_key: The CA key for signing the certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param alt_key: An alternative signing key for the certificate.
    :param hash_alg: The hash algorithm used for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use PSS-padding for signing.
    :return: The paired certificate.
    Starts with the Base and then Delta Certificate.
    """
    delta_req = verify_paired_csr_signature(csr=csr)
    cert = build_cert_from_csr(csr=csr, ca_key=ca_key, ca_cert=ca_cert, alt_sign_key=alt_key, use_rsa_pss=use_rsa_pss)

    delta_cert = build_delta_cert(
        csr=csr,
        delta_value=delta_req,
        ca_key=ca_key,
        ca_cert=ca_cert,
        alt_sign_key=alt_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
    )

    paired_cert = build_chameleon_base_certificate(
        delta_cert=delta_cert,
        base_tbs_cert=cert["tbsCertificate"],
        ca_key=ca_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=None,  # only supposed to be used for negative testing.
    )

    return paired_cert, delta_cert


def build_delta_cert_from_paired_cert(paired_cert: rfc9480.CMPCertificate) -> rfc9480.CMPCertificate:
    """Prepare a paired certificate from a Base Certificate with a Delta Certificate Descriptor (DCD) extension.

    :param paired_cert: The Base Certificate with the DCD extension.
    :return: The paired certificate.
    """
    paired_cert_tmp = copy_asn1_certificate(paired_cert)

    dcd = get_extension(paired_cert_tmp["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)

    if dcd is None:
        raise ValueError("DCD extension not found in the Base Certificate.")

    dcd, rest = decoder.decode(dcd["extnValue"], asn1Spec=DeltaCertificateDescriptor())

    if rest:
        raise BadAsn1Data("DeltaCertificateDescriptor")

    delta_cert = rfc9480.CMPCertificate()
    delta_cert["tbsCertificate"] = paired_cert_tmp["tbsCertificate"]

    # Remove the DCD extension from the Delta Certificate template
    extensions = []

    for ext in delta_cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] != id_ce_deltaCertificateDescriptor:
            extensions.append(ext)

    tmp_extn = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
    if extensions:
        tmp_extn.extend(extensions)
        delta_cert["tbsCertificate"]["extensions"] = tmp_extn

    delta_cert["tbsCertificate"]["extensions"] = tmp_extn

    # Replace fields based on the DCD extension
    delta_cert["tbsCertificate"]["serialNumber"] = int(dcd["serialNumber"])

    if dcd["signature"].isValue:
        delta_cert["tbsCertificate"]["signature"]["algorithm"] = dcd["signature"]["algorithm"]
        delta_cert["tbsCertificate"]["signature"]["parameters"] = dcd["signature"]["parameters"]
        delta_cert["signatureAlgorithm"]["algorithm"] = dcd["signature"]["algorithm"]
        delta_cert["signatureAlgorithm"]["parameters"] = dcd["signature"]["parameters"]

    else:
        delta_cert["signatureAlgorithm"]["algorithm"] = paired_cert_tmp["signatureAlgorithm"]["algorithm"]
        delta_cert["signatureAlgorithm"]["parameters"] = paired_cert_tmp["signatureAlgorithm"]["parameters"]

    if dcd["issuer"].isValue:
        issuer = copy_name(filled_name=dcd["issuer"], target=rfc5280.Name())
        delta_cert["tbsCertificate"]["issuer"] = issuer

    if dcd["validity"].isValue:
        validity = copy_validity(dcd["validity"])
        delta_cert["tbsCertificate"]["validity"] = validity

    delta_cert["tbsCertificate"]["subjectPublicKeyInfo"] = dcd["subjectPublicKeyInfo"]

    if dcd["subject"].isValue:
        subject = copy_name(filled_name=dcd["subject"], target=rfc5280.Name())
        delta_cert["tbsCertificate"]["subject"] = subject

    if dcd["extensions"].isValue:
        for dcd_ext in dcd["extensions"]:
            found = False
            for ext in delta_cert["tbsCertificate"]["extensions"]:
                if ext["extnID"] == dcd_ext["extnID"]:
                    ext["critical"] = dcd_ext["critical"]
                    ext["extnValue"] = dcd_ext["extnValue"]
                    found = True
                    break
            if not found:
                raise ValueError(f"Extension {dcd_ext['extnID']} not found in the Delta Certificate template.")

    delta_cert["signature"] = dcd["signatureValue"]

    return delta_cert


def get_chameleon_delta_public_key(paired_cert: rfc9480.CMPCertificate) -> rfc5280.SubjectPublicKeyInfo:
    """Extract the delta public key from a paired certificate.

    :param paired_cert: The paired certificate.
    :return: The extracted public key.
    """
    dcd = get_extension(paired_cert["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)

    if dcd is None:
        raise ValueError("DCD extension not found in the Base Certificate.")

    dcd, rest = decoder.decode(dcd["extnValue"], asn1Spec=DeltaCertificateDescriptor())

    if rest:
        raise BadAsn1Data("DeltaCertificateDescriptor")

    return dcd["subjectPublicKeyInfo"]
