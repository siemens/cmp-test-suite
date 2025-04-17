# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import List, Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5280, rfc9480

from resources.asn1_structures import PKIMessageTMP, PKIBodyTMP
from resources.cmputils import prepare_info_type_and_value
from resources.convertutils import copy_asn1_certificate

from unit_tests.utils_for_test import prepare_pki_header

# TODO refactor and move to ca_ra_utils.py

def build_genp_pkimessage(info_type_values: List[rfc9480.InfoTypeAndValue]) -> PKIMessageTMP:
    """Prepare and return a `PKIMessage` containing a general response `PKIBody`.

    :param info_type_values: A list of `InfoTypeAndValue` structures to include in the `GenRepContent`.
    :return: A decoded `PKIMessage` structure, to simulate a `genp` message sent over the wire.
    """
    gen_rep_content = rfc9480.GenRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 22))
    for info_type_value in info_type_values:
        gen_rep_content.append(info_type_value)

    pki_body = PKIBodyTMP()
    pki_body["genp"] = gen_rep_content

    pki_message = PKIMessageTMP()
    pki_message["header"] = prepare_pki_header(sender="CN=Hans the Tester", recipient="CN=Hans the Tester")
    pki_message.setComponentByName("body", pki_body)

    der_data = encoder.encode(pki_message)
    decoded_pki_message, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())

    if rest != b"":
        raise ValueError("The decoding of `genp` PKIMessage structure had a remainder!")

    return decoded_pki_message


def build_root_ca_key_update_content(
    new_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
    new_with_old_cert: Optional[rfc9480.CMPCertificate] = None,
    old_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.RootCaKeyUpdateValue:
    """Build and return a `RootCaKeyUpdateContent` structure containing the provided certificates.

    :param new_with_new_cert: The new Root certificate.
    :param new_with_old_cert: The new CA certificate signed by the old one.
    :param old_with_new_cert: The old CA certificate signed by the new one.
    :return: The populated `RootCaKeyUpdateValue` structure.
    """
    root_ca_update = rfc9480.RootCaKeyUpdateValue()

    if new_with_new_cert is not None:
        root_ca_update.setComponentByName("newWithNew", new_with_new_cert)

    if new_with_old_cert is not None:
        new_with_old = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        new_with_old_cert = copy_asn1_certificate(new_with_old_cert, new_with_old)
        root_ca_update.setComponentByName("newWithOld", new_with_old_cert)

    if old_with_new_cert is not None:
        old_with_new = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )

        old_with_new = copy_asn1_certificate(old_with_new_cert, old_with_new)
        root_ca_update.setComponentByName("oldWithNew", old_with_new)

    return root_ca_update


def build_pkimessage_root_ca_key_update_content(
    new_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
    new_with_old_cert: Optional[rfc9480.CMPCertificate] = None,
    old_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
) -> PKIMessageTMP:
    """Build and return a `PKIMessage` with `RootCaKeyUpdateContent` using the provided certificates.

    :param new_with_new_cert: The new CA certificate (optional).
    :param new_with_old_cert: The new CA certificate with the old one (optional).
    :param old_with_new_cert: The old CA certificate with the new one (optional).
    :return: A `PKIMessage` with the `RootCaKeyUpdateContent` set.
    """
    root_ca_update = build_root_ca_key_update_content(new_with_new_cert, new_with_old_cert, old_with_new_cert)
    info_type_value = prepare_info_type_and_value(oid=rfc9480.id_it_rootCaKeyUpdate,
                                                  value=root_ca_update)
    pki_message = build_genp_pkimessage([info_type_value])

    return pki_message


def prepare_genp_controls(rsa_key_len: int= None, alg_id: rfc9480.AlgorithmIdentifier=None) -> rfc9480.Controls:
    """Prepare a `Controls` structure for inclusion in a general response PKIMessage.

    :param rsa_key_len: Optional desired RSA key length to include in the controls.
    :param alg_id: Optional `AlgorithmIdentifier` object to specify in the controls.
    :return: The populated `Controls` structure.
    """
    controls = rfc9480.Controls()

    if rsa_key_len is not None:
        attr_and_val = rfc9480.AttributeTypeAndValue()
        attr_and_val["type"] = rfc9480.id_regCtrl_rsaKeyLen
        attr_and_val["value"] = rfc9480.RsaKeyLenCtrl(rsa_key_len)

        controls.append(attr_and_val)


    if alg_id is not None:
        attr_and_val = rfc9480.AttributeTypeAndValue()
        attr_and_val["type"] = rfc9480.id_regCtrl_algId
        attr_and_val["value"] = alg_id

        controls.append(attr_and_val)

    return controls

def prepare_cert_req_template_content(
        cert_template: rfc9480.CertTemplate, key_spec: rfc9480.Controls = None
) -> rfc9480.CertReqTemplateValue:
    """Prepare a `CertReqTemplateValue` structure for a certificate request.

    :param cert_template: The certificate template defining the desired certificate properties.
    :param key_spec: Optional controls for the request (e.g., RSA key length or algorithm ID).
    :return: The populated `CertReqTemplateValue` structure.
    """
    cert_req_template_content = rfc9480.CertReqTemplateValue()
    cert_req_template_content["certTemplate"] = cert_template
    if key_spec is not None:
        cert_req_template_content["keySpec"] = key_spec

    return cert_req_template_content


def build_genp_cert_req_template_content(
        cert_req_template_content: rfc9480.CertReqTemplateValue = None
) -> PKIMessageTMP:
    """Build a general response PKIMessage for a certificate request template.

    :param cert_req_template_content: Optional `CertReqTemplateValue` to include in the message.
    :return: The populated `PKIMessage`.
    """
    info_type_value = prepare_info_type_and_value(rfc9480.id_it_certReqTemplate, cert_req_template_content)
    return build_genp_pkimessage([info_type_value])


def _prepare_ca_cert_value(ca_certs: List[rfc9480.CMPCertificate]) -> rfc9480.CaCertsValue:
    """Prepare a `CaCertsValue` containing a list of CA certificates.

    :param ca_certs: A list of `CMPCertificate` objects representing the CA certificates.
    :return: The populated `CaCertsValue` structure.
    """
    ca_certs_value = rfc9480.CaCertsValue()
    for cert in ca_certs:
        ca_certs_value.append(cert)
    return ca_certs_value

def build_genp_get_ca_certs(ca_certs: List[rfc9480.CMPCertificate]) -> PKIMessageTMP:
    """Build a general response PKIMessage for retrieving CA certificates.

    :param ca_certs: A list of `CMPCertificate` objects representing the CA certificates.
    :return: The populated `PKIMessage`.
    """
    info_type_value = prepare_info_type_and_value(rfc9480.id_it_caCerts, _prepare_ca_cert_value(ca_certs))
    return build_genp_pkimessage([info_type_value])


def build_crl_update_retrieval_pkimessage(crl: Optional[rfc5280.CertificateList] = None) -> PKIMessageTMP:
    """Build a general response PKIMessage for retrieving a CRL update.

    :param crl: An optional `CertificateList` object representing the CRL.
    :return: The populated `PKIMessage`.
    """
    crls_value = rfc9480.CRLsValue()
    if crl is not None:
        crls_value.append(crl)

    info_type_and_value = rfc9480.InfoTypeAndValue()
    info_type_and_value["infoType"] = rfc9480.id_it_crls
    info_type_and_value["infoValue"] = crls_value

    return build_genp_pkimessage([info_type_and_value])
