# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Prepare the `PKIMessage` with a General Message Body and different types of messages.

Provides functionality for generating positive and negative structures for testing.
Also has the functionality for validating the Responses from the Server.

Note the functions all validate the message size and sometimes the responses item size
returned by the server/CA. This is to enforce LwCMP, per default, which was the
the target goal of the Test-Suite.

"""

import datetime
import logging
from typing import List, Optional, Set, Tuple, Union

import pyasn1.error
from pq_logic.migration_typing import HybridKEMPublicKey, KEMPrivateKey
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_private_key, is_kem_public_key
from pq_logic.tmp_oids import id_it_KemCiphertextInfo
from pq_logic.trad_typing import ECDHPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ, useful
from pyasn1_alt_modules import rfc4210, rfc4211, rfc5280, rfc5480, rfc9480, rfc9481
from robot.api.deco import keyword, not_keyword

from resources import certutils, cmputils, utils
from resources.asn1_structures import InfoTypeAndValueAsn1, KemCiphertextInfoAsn1, PKIMessageTMP
from resources.cmputils import get_value_from_seq_of_info_value_field, prepare_info_value
from resources.convertutils import copy_asn1_certificate, pyasn1_time_obj_to_py_datetime
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import CURVE_OIDS_2_NAME
from resources.suiteenums import GeneralInfoOID
from resources.typingutils import Strint

# TODO for the future, change references to new RFC.
# currently uses the Draft version for messages not mentioned in RFC9483.
# And for messages that are mentioned uses sections from the RFC9483.


def _get_crl_dpn(cert: rfc9480.CMPCertificate) -> Union[rfc5280.CRLDistributionPoints, None]:
    """Get the `CRLDistributionPoints` extension, DER-encoded, from a `rfc9480.CMPCertificate` object.

    :param cert: The object to get the extension from.
    :return: `None` if the extension is not present, else the `rfc5280.CRLDistributionPoints` structure.
    """
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == rfc5280.id_ce_cRLDistributionPoints:
            crl_pyasn1, _ = decoder.decode(ext["extnValue"], asn1Spec=rfc5280.CRLDistributionPoints())
            return crl_pyasn1

    return None


def _get_issuing_distribution_point(cert: rfc9480.CMPCertificate) -> Union[rfc5280.IssuingDistributionPoint, None]:
    """Get and decode the Issuing Distribution Point extension from a pyasn1 certificate object.

    :param cert: The certificate to extract the extension from.
    :return: `None` if the extension is not present, else the `rfc5280.IssuingDistributionPoint` structure.
    """
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == rfc5280.id_ce_issuingDistributionPoint:
            idp_pyasn1, _ = decoder.decode(ext["extnValue"], asn1Spec=rfc5280.IssuingDistributionPoint())
            return idp_pyasn1

    return None


def _prepare_get_ca_certs(fill_info_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` structure for the `genm` `Get CA Certificates`.

    :param fill_info_value: If set to `True` adds some random bytes to the `infoValue` field,
    because it **MUST** be absent.
    :return: The filled `InfoTypeAndValue` structure
    """
    # as of Section 4.3.1 Get CA Certificates infoValue of the Request must be Absent.
    return prepare_info_value(
        oid=rfc9480.id_it_caCerts,
        fill_random=fill_info_value,
    )


def validate_get_ca_certs(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    must_be_present: bool = False,
    ee_cert: Optional[rfc9480.CMPCertificate] = None,
    expected_size: Strint = 1,
    crl_check: bool = False,
    verbose: bool = True,
) -> Union[List[rfc9480.CMPCertificate], None]:
    """Validate if the general response message contains the CA answer.

    As of Section 4.3.1: "either contains a SEQUENCE of certificates populated with the
    available intermediate and issuing CA certificates or no content in case no CA certificate
    is available."

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` containing the general response.
        - `must_be_present`: If `True`, ensures the CA certificates must be present. Defaults to `False`.
        - `ee_cert`: Optional end-entity certificate to build the certificate chain for.
        - `expected_size`: The expected response messages to receive. Defaults to `1`.
        - `crl_check`: Whether the certificate chain should be validated with CRL check or not. Defaults to `False`.
        - `verbose`: Whether the OpenSSL `verify` command should be verbose or not.

    Raises:
    ------
        - `ValueError`: If the CA certificates are invalid or missing when required.
        - `ValueError`: If the newly formed certificates chain is invalid.

    Examples:
    --------
    | Validate Get CA Certs | ${pki_message} | must_be_present=True | ee_cert=${ee_cert} |
    | Validate Get CA Certs | ${pki_message} | expected_size=1 |

    """
    validate_general_response(pki_message, expected_size=expected_size)
    genp_content: rfc9480.GenRepContent() = pki_message["body"][pki_message["body"].getName()]
    if len(genp_content) != expected_size:
        logging.info("General Response: \n%s", genp_content.prettyPrint())

        logging.info("Expected to get exactly one Response message but got: %s", len(genp_content))
        return None

    value = cmputils.get_value_from_seq_of_info_value_field(genp_content, oid=rfc9480.id_it_caCerts)
    if value is None:
        logging.info("General Response: \n%s", genp_content.prettyPrint())
        raise ValueError("The CA did not contain the oid for `id-it-caCerts` as of Section 4.3.1 specified!")

    if not value.isValue and must_be_present:
        raise ValueError("The Server's response did not contain CA certificates.")

    try:
        ca_certs, _ = decoder.decode(value, asn1Spec=rfc9480.CaCertsValue())
        utils.log_certificates(ca_certs)
    except pyasn1.error.PyAsn1Error:
        raise ValueError(  # pylint: disable=raise-missing-from
            "The Response did not contain a valid `CaCertsValue` structure (SequenceOf(Certificates))"
        )

    if ee_cert is not None:
        cert_chain = certutils.build_chain_from_list(ee_cert, ca_certs)
    else:
        # because may return starting with ee or root.
        cert_chain1 = certutils.build_chain_from_list(ca_certs[0], ca_certs[1:])
        cert_chain2 = certutils.build_chain_from_list(ca_certs[-1], ca_certs[:-1])
        cert_chain = cert_chain2 if len(cert_chain2) > len(cert_chain1) else cert_chain1

    certutils.verify_cert_chain_openssl(cert_chain=cert_chain, crl_check=crl_check, verbose=verbose)
    return cert_chain


# As of RFC 4210bis-15 Section 5.3.19.15 Root CA Update:
# GenMsg:    {id-it 20}, RootCaCertValue | < absent >
# GenRep:    {id-it 18}, RootCaKeyUpdateValue | < absent >


def _prepare_get_root_ca_cert_update(root_cert: Optional[rfc9480.CMPCertificate] = None) -> rfc9480.InfoTypeAndValue:
    """Prepare the `pyasn1` `InfoTypeAndValue` for the `Get Root CA Certificate Update`message.

    As of Section 4.3.2 If needed for unique identification, the EE include the old root CA certificate in the message
    body. And This mechanism may also be used to update trusted non-root certificates, e.g., directly trusted
    intermediate or issuing CA certificates.

    :param root_cert: Optional root or trusted cert.
    :return: The filled structure.

    """
    value = rfc9480.InfoTypeAndValue()
    value["infoType"] = rfc9480.id_it_rootCaCert

    # maybe change to RootCaCertValue but does not matter
    if root_cert is not None:
        value["infoValue"] = root_cert

    return value


def validate_get_root_ca_cert_update(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, old_ca_cert: Optional[rfc9480.CMPCertificate] = None, expected_size: Strint = 1
):
    """Validate if the PKIMessage contains the correct root CA certificate update.

    Verify if the certificates were signed by each other, if present, as defined by the OID `id-it-rootCaKeyUpdate`.
    If the new root certificate is correctly signed and so on, then the certificate is validated with `pkilint`.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the root CA certificate update.
        - `old_ca_cert`: The previous root CA certificate, to validate against the new certificates,
        if not provided just validates the structure.
        - `expected_size`: The expected response messages to receive. Defaults to `1`.

    Raises:
    ------
        - `ValueError`: If the `PKIBody` is not of type "genp".
        - `ValueError`: If the response contains more messages than expected.
        - `ValueError`: If the root CA certificate update is invalid, or the oid is missing.

    Examples:
    --------
    | Validate Get Root CA Cert Update | ${pki_message} | old_ca_cert=${old_ca_cert} |

    """
    validate_general_response(pki_message, expected_size=expected_size)
    value = cmputils.get_value_from_seq_of_info_value_field(pki_message["body"]["genp"], rfc9480.id_it_rootCaKeyUpdate)

    if value is None:
        raise ValueError(
            "The General Message did not contain the `id_it_rootCaKeyUpdate` oid!"
            f"But was: {pki_message['body']['genp'][0]['infoType'].prettyPrint()}"
        )

    if value.isValue:
        root_ca_update, rest = decoder.decode(value, rfc9480.RootCaKeyUpdateValue())
        if rest != b"":
            raise ValueError("Error: Decoding 'RootCaKeyUpdateValue' structure left unexpected trailing data.")
        process_root_ca_update(root_ca_update, old_ca_cert)
    else:
        logging.warning("Provided CA Certificate was not Updated.")


@not_keyword
def process_root_ca_update(
    root_ca_update: rfc9480.RootCaKeyUpdateValue, old_ca_cert: Optional[rfc9480.CMPCertificate] = None
):
    """Validate the RootCaKeyUpdateValue structure, ensuring the presence of required certificates.

    :param root_ca_update: The already decoded RootCaKeyUpdateValue structure.
    :param old_ca_cert: Optional old CA certificate for validation.
    :raises ValueError: If any required certificates are missing.
    """
    if not root_ca_update["newWithOld"].isValue:
        raise ValueError("The `RootCaKeyUpdateValue` structure did not contain the `newWithOld` Certificate.")
    new_with_old = copy_asn1_certificate(root_ca_update["newWithOld"])  # remove the tag

    if not root_ca_update["newWithNew"].isValue:
        raise ValueError("The `RootCaKeyUpdateValue` structure did not contain the `newWithNew` Certificate.")

    if not root_ca_update["oldWithNew"].isValue:
        logging.info("Respond did not contain a value for `oldWithNew` value!")
        old_with_new = None
    else:
        old_with_new = root_ca_update["oldWithNew"]  # copy_asn1_certificate()  # to remove the tag

    if old_ca_cert is not None:
        validate_root_ca_key_update_value_structure(
            old_cert=old_ca_cert,
            new_with_old=new_with_old,
            new_with_new=root_ca_update["newWithNew"],
            old_with_new=old_with_new,
        )


# TODO fix to also allow intermediate as trusted.
@not_keyword
def validate_root_ca_key_update_value_structure(
    old_cert: rfc9480.CMPCertificate,
    new_with_new: rfc9480.CMPCertificate,
    new_with_old: rfc9480.CMPCertificate,
    old_with_new: Optional[rfc9480.CMPCertificate] = None,
):
    """Validate the structure of Root CA Key Update Value.

    :param old_cert: The old root certificate.
    :param new_with_new: The new self-signed root certificate.
    :param new_with_old: The new certificate which was signed with the private key of the old certificate.
    :param old_with_new: Optional the old cert signed with the private key of the new certificate.
    :return: `None` if all checks pass.
    """
    if not certutils.check_is_cert_signer(new_with_new, poss_issuer=new_with_new):
        raise ValueError("Signature Validation NewWithNew failed!")

    if not certutils.check_is_cert_signer(new_with_old, poss_issuer=old_cert):
        raise ValueError("Signature Validation NewWithOld failed!")

    if old_with_new is not None:
        if not certutils.check_is_cert_signer(old_with_new, poss_issuer=new_with_new):
            raise ValueError("Signature Validation NewWithNew failed!")

        public_key = certutils.load_public_key_from_cert(old_cert)
        public_key2 = certutils.load_public_key_from_cert(old_with_new)
        if public_key != public_key2:
            raise ValueError("The OldWithNew Certificate has a different public then the Original Provided Certificate")

    certutils.validate_certificate_pkilint(encoder.encode(new_with_new))


# As of RFC4210bis-15 Section 5.3.19.16 Certificate Request Template:
#   GenMsg: {id-it 19}, < absent >
#   GenRep: {id-it 19}, CertReqTemplateContent | < absent >
def _prepare_get_certificate_request_template(fill_info_val: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the Get Certificate Request Template structure for the `General Message`.

    :param fill_info_val: If set to `True` adds some random bytes to the `infoValue` field,
    because it MUST be absent.Defaults to `False`.
    :return: The filled `InfoTypeAndValue` structure
    """
    return prepare_info_value(oid=rfc9480.id_it_certReqTemplate, fill_random=fill_info_val)


def _get_type_inside_controls(controls, oid: univ.ObjectIdentifier) -> Union[None, univ.Any]:
    for x in controls:
        if x["type"] == oid:
            return x["value"]
    return None


@not_keyword
def check_controls_for_cert_temp(
    controls: rfc9480.Controls, must_be_present: bool = False, rsa_length_min: int = 2048
) -> None:
    """Validate the `Controls` structure inside the `pyasn1` `rfc9480.CertReqTemplateValue` structure.

    According to the rfc9483 Section 4.3.3, it checks the presence and validity of RSA key length and
    algorithm identifier constraints.

    :param controls: The structure objects to validate.
    :param must_be_present: Whether the structure must be present or not. Defaults to `False`.
    :param rsa_length_min: The minimal key length expected for the RSA Algorithm. Defaults to `2048`.
    :raises: ValueError If the `Controls` is missing, when required or Invalid RsaKeyLenCtrl decoding or value, or
    invalid/unsupported algorithm in `AlgIdCtrl`
    """
    if not controls.isValue:
        if not must_be_present:
            logging.info("No Requirements for the public key are available.")
        else:
            raise ValueError("The CertReqTemplate Response did not contain a value.")

    if len(controls) != 1:
        raise ValueError(
            "Controls is either supposed to be `id-reg-Ctrl-algId` or `id-regCtrl-rsaKeyLen`, but both were present"
        )

    value = _get_type_inside_controls(controls, oid=rfc9480.id_regCtrl_rsaKeyLen)
    if value is not None:
        val, rest = decoder.decode(value, asn1Spec=rfc9480.RsaKeyLenCtrl())
        if rest != b"":
            raise ValueError("Decoding of `RsaKeyLenCtrl` had some rest!")

        if int(val) < rsa_length_min:
            raise ValueError(f"The `RsaKeyLen` must be a integer at least of size: {rsa_length_min}.")

        logging.info("`RsaKeyLen` is %s", str(int(val)))

    value = _get_type_inside_controls(controls, oid=rfc9480.id_regCtrl_algId)
    if value is not None:
        _validate_id_reg_ctrl_alg_id(value.asOctets())  # type: ignore


def _validate_id_reg_ctrl_alg_id(value: bytes) -> None:
    """Validate the `AlgIdCtrl` structure within the `Controls` field.

    If present must contain a valid algorithm, and is not allowed to be RSA.

    :param value: The DER encoded `AlgIdCtrl` structure.
    :raises ValueError: If the structure specifies RSA as the algorithm,
    contains unexpected parameters for Ed25519 or Ed448, or specifies an
    unsupported or unknown EC curve or contains unexpected data after decoding.
    """
    alg_id, rest = decoder.decode(value, asn1Spec=rfc9480.AlgIdCtrl())

    if rest != b"":
        raise ValueError("The decoding of `AlgIdCtrl` structure had a remainder!")

    if alg_id["algorithm"] in {rfc9481.id_Ed448, rfc9481.id_Ed25519}:
        if not alg_id["parameters"].isValue:
            raise ValueError("The parameters field for `Ed448` and `Ed25519` must be absent.")

    elif alg_id["algorithm"] == rfc9481.rsaEncryption:
        raise ValueError("AlgorithmIdentifier must not be RSA!")

    elif alg_id["algorithm"] == rfc5480.id_ecPublicKey:
        if not alg_id["parameters"].isValue:
            raise ValueError(
                "The `Controls` structure for the `CertTemplateReq` got ecPublicKey as structure but no curve."
            )

        ec_param, rest = decoder.decode(alg_id["parameters"], asn1Spec=rfc5480.ECParameters())

        if rest != b"":
            raise ValueError("The decoding of `ECParameters` structure had a remainder!")

        if ec_param["namedCurve"] not in CURVE_OIDS_2_NAME:
            raise ValueError("ecPublicKey got a unknown `ECParameters` ec-curve.")

        logging.info("ECC curve was: %s", CURVE_OIDS_2_NAME[ec_param["namedCurve"]])

    else:
        raise ValueError(
            f"The `Controls` structure for the `CertTemplateReq` got a unknown or wrong OID: {alg_id.prettyPrint()}"
        )


def _check_cert_template_for_cert_temp_req(cert_req_temp: rfc9480.CertReqTemplateValue) -> None:
    """Check the `pyasn1` CertTemplate structure parsed from the ` rfc9480.CertReqTemplateValue` structure.

    :param cert_req_temp: The structure to check.
    :raise: ValueError if any of the following attributes are present: 'publicKey','serialNumber', 'signingAlg',
    'issuerUID', 'subjectUID'
    """
    cert_temp: rfc4211.CertTemplate = cert_req_temp["certTemplate"]

    # Must be absent as of Section 4.3.3
    if cert_temp["publicKey"].isValue:
        raise ValueError("The `SubjectPublicKeyInfo` must be absent inside the `CertReqTemplateValue`")

    if cert_temp["serialNumber"].isValue:
        raise ValueError("The `serialNumber` must be absent inside the `CertReqTemplateValue`")

    if cert_temp["signingAlg"].isValue:
        raise ValueError("The `signingAlg` must be absent inside the `CertReqTemplateValue`")

    if cert_temp["issuerUID"].isValue:
        raise ValueError("The `issuerUID` must be absent inside the `CertReqTemplateValue`")

    if cert_temp["subjectUID"].isValue:
        raise ValueError("The `subjectUID` must be absent inside the `CertReqTemplateValue`")


def validate_get_certificate_request_template(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    must_be_present: bool = False,
    control_presents: bool = False,
    expected_size: Strint = 1,
) -> None:
    r"""Validate if the `genp` response contains the certificate request template.

    It checks the `id-it-certReqTemplate` OID is present and ensures the structure is valid,
    according to Rfc9483 Section 4.3.3.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the general response.
        - `must_be_present`: If `True`, ensures the certificate request template must be present.
        - `control_presents`: If `True`, ensures the control structure is present in the template.
        - `expected_size`:The expected response messages to receive. Defaults to `1`.

    Raises:
    ------
        - `ValueError`: If the certificate request template contains not allowed fields. ('publicKey','serialNumber',
        'signingAlg','issuerUID', 'subjectUID')
        - `ValueError`: If the control structure contains an invalid algorithm identifier. (e.g., "rsa" as algorithm.)

    Examples:
    --------
    | Validate Get Certificate Request Template | ${pki_message} | must_be_present=True | control_presents=True |
    | Validate Get Certificate Request Template | ${pki_message} | must_be_present=True |
    | Validate Get Certificate Request Template | ${pki_message} |

    """
    validate_general_response(pki_message, expected_size=expected_size)
    body_name = pki_message["body"].getName()
    genp_content: rfc9480.GenRepContent() = pki_message["body"][body_name]

    value = cmputils.get_value_from_seq_of_info_value_field(genp_content, oid=rfc9480.id_it_certReqTemplate)
    if value is None:
        logging.info("General Response: \n%s", genp_content.prettyPrint())

        raise ValueError(
            "The Server response did not contain the oid for `id-it-caCerts` as of Section 4.3.4 specified!"
        )

    if not value.isValue:
        if not must_be_present:
            logging.info("No Requirements are available")
        else:
            raise ValueError("The CertReqTemplate Response did not contain a value.")

    cert_req_temp, rest = decoder.decode(value, asn1Spec=rfc9480.CertReqTemplateValue())

    if rest != b"":
        raise ValueError("Was not able to properly decode the `CertReqTemplateValue` structure")

    check_controls_for_cert_temp(controls=cert_req_temp["keySpec"], must_be_present=control_presents)
    _check_cert_template_for_cert_temp_req(cert_req_temp=cert_req_temp)


@not_keyword
def prepare_distribution_point_name(
    ca_crl_url: Optional[str] = None, ca_name: Optional[str] = None
) -> rfc9480.DistributionPointName:
    """Prepare the `pyasn1` `DistributionPointName` if the certificate does not contain a extension for it.

    This is used for the CRL Update Retrieval message so that the PKI Management Entity can identify the needed CRL

    :param ca_crl_url: The CRL url address, which is used to set the `uniformResourceIdentifier` choice.
    :param ca_name: The name which will be used to create the `rfc822Name` choice.
    :return: The filled structure.
    """
    if ca_name is None and ca_crl_url is None:
        raise ValueError(
            "Either the `ca_name` or the `ca_crl_url` needs to be provided, to "
            "populate `DistributionPointName` structure"
        )

    gen_type = "rfc822Name" if ca_name is not None else "uniformResourceIdentifier"
    value = ca_name if ca_name is not None else ca_crl_url

    dist_point_name = rfc9480.DistributionPointName().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    gen_names = rfc9480.GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    gen_name = cmputils.prepare_general_name(gen_type, value)
    gen_names.append(gen_name)
    dist_point_name["fullName"] = gen_names
    return dist_point_name


@not_keyword
def prepare_dpn_from_cert(
    cert: rfc9480.CMPCertificate, crl_dp_index: int = 0
) -> Union[None, rfc5280.DistributionPointName]:
    """Prepare the pyasn1 `DistributionPointName` from a certificate, if possible.

    :param cert: The certificate to extract either the CRLDistributionPoints extension
    or the IssuingDistributionPoint
    :param crl_dp_index: if there are more DistributionPointNames inside the
    `CRLDistributionPoints` extension then an index should be provided.
    :return: None or the parsed `DistributionPointName`
    """
    new_dpn = None
    extension = _get_crl_dpn(cert)
    if extension is not None:
        # inside here has tag 0 the same as inside CRLSource.
        dpn: rfc5280.DistributionPointName = extension[crl_dp_index]["distributionPoint"]
        new_dpn = dpn
    else:
        issuing_dp = _get_issuing_distribution_point(cert)
        if issuing_dp is not None:
            new_dpn = issuing_dp["distributionPoint"]

    return new_dpn


def _prepare_time_for_crl_update_retrieval(negative: bool, crl_filepath: Union[str, None]):
    """Prepare the 'thisUpdate' time for CRL update retrieval.

    :param negative: If `True`, adds an extra day to the calculated time for negative testing.
    :param crl_filepath: Optional file path to the CRL. If provided, retrieves the `thisUpdate`
                         time from the file. If not provided, uses the current utc time.
    :return: A `rfc9480.Time` object populated with the calculated `thisUpdate` time.
    """
    if crl_filepath is None:
        dt_object = datetime.datetime.now()
    else:
        crl_object = utils.load_crl_from_file(crl_filepath)
        last_update = crl_object["tbsCertList"]["thisUpdate"]
        dt_object = pyasn1_time_obj_to_py_datetime(last_update)

    if negative:
        dt_object = dt_object + datetime.timedelta(days=1)

    time_obj = rfc9480.Time()
    time_obj.setComponentByName("generalTime", useful.GeneralizedTime().fromDateTime(dt_object))

    return time_obj


@keyword(name="Prepare CRL Update Retrieval")
def prepare_crl_update_retrieval(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    ca_name: Optional[str] = None,
    ca_crl_url: Optional[str] = None,
    crl_filepath: Optional[str] = None,
    crl_dp_index: int = 0,
    negative: bool = False,
) -> rfc9480.InfoTypeAndValue:
    """Prepare CRL update retrieval information for a 'General Message'.

    Constructs an `InfoTypeAndValue` structure with information for the CA needed to
    know the source of the CRL list.

    Arguments:
    ---------
        - `cert`: An optional `rfc9480.CMPCertificate` object to extract CRL distribution
                  points. If provided, this is the primary source for CRL data.
        - `ca_name`: An optional string specifying the name of the CA to use if no CRL
                     distribution points are available in the certificate.
        - `ca_crl_url`: An optional string representing the URL for the CA's CRL
                        distribution point, used as a fallback when no distribution
                        points are available in the certificate.
        - `crl_filepath`: A string representing the file path to a CRL. If provided, it
                          is used to retrieve the `thisUpdate` field from the CRL.
        - `crl_dp_index`: An integer specifying the index of the CRL distribution point
                          to use in the certificate. Defaults to `0`.
        - `negative`: A boolean flag for negative testing. If `True`, simulates invalid CRL
                      data by adjusting the `thisUpdate` field.

    Returns:
    -------
        - A `InfoTypeAndValue` structure populated with CRL update retrieval information.

    Raises:
    ------
        - `ValueError`: If neither a certificate nor sufficient distribution point
                        information is provided to prepare CRL retrieval data.

    Examples:
    --------
    | ${crl_update}= | Prepare CRL Update Retrieval | cert=${certificate} | crl_dp_index=1 |
    | ${crl_update}= | Prepare CRL Update Retrieval | ca_name={ca_name} | \
    ca_crl_url=https://example.com/crl |
    | ${crl_update}= | Prepare CRL Update Retrieval | crl_filepath=/path/to/crl.pem | negative=True |

    """
    crl_source = rfc9480.CRLSource()
    # MUST Be the extension otherwise use the ca_name
    if cert is not None:
        new_dpn = prepare_dpn_from_cert(cert, crl_dp_index=crl_dp_index)
        if new_dpn is not None:
            crl_source["dpn"] = new_dpn

    if not crl_source["dpn"].isValue:
        dpn = prepare_distribution_point_name(ca_crl_url=ca_crl_url, ca_name=ca_name)
        crl_source["dpn"] = dpn

    status = rfc9480.CRLStatus()
    status["source"] = crl_source

    if negative or crl_filepath is not None:
        status["thisUpdate"] = _prepare_time_for_crl_update_retrieval(negative=negative, crl_filepath=crl_filepath)

    status_list_val = rfc9480.CRLStatusListValue()
    status_list_val.append(status)
    return prepare_info_value(rfc9480.id_it_crlStatusList, value=status_list_val)


def _validate_crls(
    crl_value: rfc9480.CRLsValue, ca_certs: str, trustanchors: str, allow_os_store: bool, timeout: int = 60
) -> None:
    """Validate a sequence of CRLs against the provided CA certificates.

    :param crl_value: The CRLs to validate.
    :param ca_certs: The path to the CA certificates directory.
    :param allow_os_store: Whether to allow the OS truststore or not.
    :param trustanchors: The path to the trustanchors directory.
    :param timeout: The timeout for the validation process. Defaults to 60 seconds.
    :return: None
    """
    ca_certs = certutils.load_certificates_from_dir(path=ca_certs)
    trust_anchors = certutils.load_truststore(path=trustanchors, allow_os_store=allow_os_store)

    certs = ca_certs + trust_anchors
    for i, crl in enumerate(crl_value):
        crl: rfc9480.CertificateList
        crl_chain = certutils.build_crl_chain_from_list(crl=crl, certs=certs)
        try:
            certutils.verify_openssl_crl(crl_chain, timeout=timeout)
        except ValueError:
            # TODO fix for better logging.
            logging.info("CRL at index: %d\n %s", i, crl.prettyPrint())
            raise ValueError(f"The CRL at index: {i} was invalid")


@keyword(name="Validate CRL Update Retrieval")
def validate_crl_update_retrieval(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    must_be_present: bool = False,
    expected_size: Strint = 1,
    expected_crl_size: int = 1,
    ca_certs: str = "../data/cert_logs",
    trustanchors: str = "./data/trustanchors",
    allow_os_store: bool = True,
    timeout: Strint = 60,
):
    """Validate the presence and structure of the `CRL Update Retrieval` response in a PKIMessage.

    Checks whether a PKIMessage contains the `id-it-crls` OID as specified in RFC 9483, Section 4.3.4.
    It validates the structure of the `CRLsValue`. The oid must be returned, but the `infoValue` field must
    not be set.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to check for the `id-it-crls` OID and structure.
        - `must_be_present`: Indicates whether the `CRL Update Retrieval` value must be present in the
          response. Defaults to `False`.
        - `expected_size`: The expected response messages to receive. Defaults to `1`.
        - `expected_crl_size`: The number of expected entries inside the `CRLsValue` structure. Defaults to `1`.
        - `allow_os_store`: Whether to allow the OS truststore or not. Defaults to `True`.
        - `timeout`: The timeout for the validation process. Defaults to 60 seconds.

    Raises:
    ------
        - `ValueError`: If the `id-it-crls` OID is missing.
        - `ValueError`: If the structure is invalid.
        - `ValueError`: If the CRL sequence does not contain exactly one CRL.


    Examples:
    --------
    | Validate CRL Update Retrieval | ${pki_message} | must_be_present=True |
    | Validate CRL Update Retrieval | ${pki_message} |

    """
    validate_general_response(pki_message, expected_size=expected_size)
    body_name = pki_message["body"].getName()
    genp_content: rfc9480.GenRepContent() = pki_message["body"][body_name]

    value = cmputils.get_value_from_seq_of_info_value_field(genp_content, oid=rfc9480.id_it_crls)
    if value is None:
        logging.info("General Response: \n%s", genp_content.prettyPrint())
        raise ValueError(
            "The Server response did not contain the oid for `id-it-caCerts` as of Section 4.3.4 specified!"
        )

    if value.isValue:
        crl_values, rest = decoder.decode(value, rfc9480.CRLsValue())
        if rest != b"":
            raise ValueError("Did not contained a valid `CRLsValue` structure!")

        if len(crl_values) != expected_crl_size:
            raise ValueError(
                "For CRL Update Retrieval, is present and did not contain the "
                "number of expected "
                f"entries. Expected: {expected_crl_size} Got: {len(crl_values)}"
            )

        _validate_crls(
            crl_value=crl_values,
            ca_certs=ca_certs,
            trustanchors=trustanchors,
            timeout=int(timeout),
            allow_os_store=allow_os_store,
        )

    else:
        if not must_be_present:
            logging.info("Did not contain crl_update_retrieval")
        else:
            raise ValueError("General Response did not contain a value for `CRL Update Retrieval`")


@not_keyword
def prepare_current_crl(fill_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` structure for the General Message `current CRL`.

    :param fill_value: A Boolean indicating if adds useless data to a MUST be absent structure.
    :return: The filled `InfoTypeAndValue` structure.
    """
    # As of Section 4.3.4:
    # Note: If the EE does not want to request a specific CRL, it
    # instead use a general message with OID id-it-currentCrl as specified in Section 5.3.19.6 of [RFC4210]
    return prepare_info_value(oid=rfc9480.id_it_currentCRL, fill_random=fill_value)


# TODO maybe Update check
@keyword(name="Validate Current CRL")
def validate_current_crl(pki_message: rfc9480.PKIMessage, expected_size: Strint = 1):  # noqa D417 undocumented-param
    """Validate the presence and structure of the `id-it-currentCRL` in a `PKIMessage`.

    Checks if the provided PKIMessage contains the 'id-it-currentCRL' value, as specified in
    Rfc 9483, Section 4.3.1. It first verifies that the PKIMessage is a valid general response (`genp`) using
    and then it checks for the presence of the `id-it-currentCRL` OID in the response
    content. If found, it ensures that the `CurrentCRLValue` structure is valid.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to check for the `id-it-currentCRL` OID and structure.
        - `expected_size`: The expected response messages to receive. Defaults to `1`.

    Raises:
    ------
        - `ValueError`: If the general response contains more messages than expected.
        - `ValueError`: If the general response does not contain the `id-it-currentCRL` OID.
        - `ValueError`: If the structure of the `CurrentCRLValue` has a remainder after decoding.

    Examples:
    --------
    | Validate Current CRL | ${genp} |
    | Validate Current CRL | ${genp} | expected_size=1 |

    """
    validate_general_response(pki_message, expected_size)
    body_name = pki_message["body"].getName()
    genp_content: rfc9480.GenRepContent() = pki_message["body"][body_name]

    val = cmputils.get_value_from_seq_of_info_value_field(genp_content, oid=rfc9480.id_it_currentCRL)
    if val is None:
        logging.info("General Response: \n%s", genp_content.prettyPrint())
        raise ValueError("The CA did not contain the oid for `id-it-currentCRL` as Section 4.3.1 specified!")

    _, rest = decoder.decode(val, rfc9480.CurrentCRLValue())
    if rest != b"":
        raise ValueError("Did not contain a valid `CurrentCRLValue` structure!")


def validate_general_response(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: Strint = 1
):
    """Validate that the provided PKIMessage contains a general response (`genp`) body and message size is correct.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` to validate, expected to contain a general response (`genp`).
        - `expected_size`: The expected response messages to receive. Defaults to `1`.

    Raises:
    ------
        - `ValueError`: If the PKIMessage does not contain a general response body.
        - `ValueError`: If the response content does not have the expected message size

    Examples:
    --------
    | Validate General Response | ${genp} |

    """
    body_name = pki_message["body"].getName()
    if body_name != "genp":
        logging.info("General Message got Response body: \n%s", pki_message["body"].prettyPrint())
        raise ValueError(f"Expected to get a general Response but got type: {pki_message['body'].getName()}")

    genp_content: rfc9480.GenRepContent() = pki_message["body"][body_name]
    if len(genp_content) != expected_size:
        logging.info("General Response: \n%s", genp_content.prettyPrint())


# TODO maybe change to MUST prepare crl_update_retrieval by the user before hand.
def build_general_message(  # noqa D417 undocumented-param
    add_messages: Optional[str] = None,
    recipient: str = "test-cmp-srv@example.com",
    sender: str = "test-cmp-cli@example.com",
    exclude_fields: Optional[str] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    crl_cert: Optional[rfc9480.CMPCertificate] = None,
    info_values: Optional[Union[rfc9480.InfoTypeAndValue, List[rfc9480.InfoTypeAndValue]]] = None,
    negative: bool = False,
    ca_name: Optional[str] = None,
    ca_crl_url: Optional[str] = None,
    crl_filepath: Optional[str] = None,
    crl_dp_index: int = 0,
    **params,
) -> rfc9480.PKIMessage:
    """Build a general PKIMessage (`genm`) with optional support messages.

    Constructs a `genm` PKIMessage with various optional message types controlled
    by the `add_messages` argument. To check if the Server, if supported response to important
    messages for other PKI Management Entities.

    Arguments:
    ---------
        - `add_messages`: A comma-separated string of message types to include
        - `recipient`: The recipient of the request. Defaults to "test-cmp-srv@example.com".
        - `sender`: The sender of the request. Defaults to "test-cmp-cli@example.com".
        - `exclude_fields`: Optional comma-separated names to omit in the `PKIHeader`.
        - `ca_cert`: The CA certificate for relevant message types, such as `get_ca_certs`.
        - `crl_cert`: Certificate used for CRL updates or status retrieval.
        - `info_values`: Optional list of `InfoTypeAndValue` structures to include in the message.
        - `negative`: If `True`, sets values for the `infoValue` `Get CA Certs` message or \
        `Get Certificate Request Template` which must be absent, also manipulates the time for the \
        `CRL Update Retrieval`. Defaults to `False`.
        - `ca_crl_url`: The URL which is set for the `CRL Update Retrieval` message. Which will be populated
        inside the `DistributionPointName` structure.
        - `ca_name`: CA name for the CRL distribution point. Will be set as `rfc822Name`.
        - `crl_filepath`: Filepath for the CRL, used when generating CRL retrieval messages.
        - `crl_dp_index`: Index of the CRL distribution point to use. Defaults to `0`.
        If the certificate has the `CRLDistributionPoints` extension.
        - `**params` (Additional optional parameters for customizing the PKIHeader and fields).

    Supported Messages:
        - `"get_ca_certs"`: Request for CA certificates.
        - `"crl_update_ret"`: CRL update retrieval message.
        - `"get_cert_template"`: Request for a certificate template.
        - `"get_root_ca_cert_update"`: Request for root CA certificate updates.
        - `"current_crl"`: Request for the current CRL.

    Returns:
    -------
        - The constructed PKIMessage (`genm`) with the set message types.

    Raises:
    ------
        - `ValueError`: If required parameters for a specific message type are missing.

    Examples:
    --------
    | ${genm} = | Build General Message | add_messages=get_ca_certs,current_crl \
    | ca_cert=${ca_cert} |
    | ${genm} = | Build General Message | add_messages=get_cert_template,crl_update_ret | ca_name=TestCA |
    | ${genm} = | Build General Message | add_messages=get_ca_certs | negative=True |

    """
    body_content = rfc4210.GenMsgContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 21))

    if add_messages is None:
        messages = set()
    else:
        messages = set(add_messages.strip().split(","))

    if "crl_update_ret" in messages:
        body_content.append(
            prepare_crl_update_retrieval(
                cert=crl_cert,
                crl_filepath=crl_filepath,
                ca_name=ca_name,
                ca_crl_url=ca_crl_url,
                negative=negative,
                crl_dp_index=crl_dp_index,
            )
        )

    if info_values is not None:
        if isinstance(info_values, rfc9480.InfoTypeAndValue):
            info_values = [info_values]

        body_content.extend(info_values)

    body_content = _append_messages(messages=messages, body_content=body_content, fill_value=negative, ca_cert=ca_cert)

    pki_message = cmputils._prepare_pki_message(
        sender=sender, recipient=recipient, exclude_fields=exclude_fields, **params
    )
    pki_body = rfc9480.PKIBody()
    pki_body["genm"] = body_content
    pki_message["body"] = pki_body
    return pki_message


# Section 5.3.19.1 CA Protocol Encryption Certificate:
# GenMsg: {id-it 1}, < absent >
# GenRep: {id-it 1}, Certificate | < absent >


def prepare_ca_protocol_enc_cert(fill_value: bool = False):
    """Prepare the `InfoTypeAndValue` to ask for a certificate to be used.

    This MAY be used by the EE to get a certificate from the CA to use to protect sensitive
    information during the protocol.

    Note:
    Could be used by including the certificate of the EE inside the `extraCerts` field.
    EEs MUST ensure that the correct certificate is used for this purpose.

    :param fill_value: Whether to fill the `infoValue` field, which MUST be absent.
    :return: The populated `InfoTypeAndValue` structure.

    """
    return prepare_info_value(rfc9480.id_it_caProtEncCert, fill_random=fill_value)


def validate_preferred_ca_prot_enc_cert(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    expected_size: Strint = 1,
    index: int = 0,
    trustanchors: str = "./data/trustanchors",
    cert_chain_dir: str = "./data/cert_logs",
) -> Optional[rfc9480.CAProtEncCertValue]:
    """Validate the response for the CA Protocol Encryption Certificate message.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: Expected number of elements in the general response. Defaults to `1`.
        - `index`: Index of the message to validate.

    Returns:
    -------
        - The CA Protocol Encryption Certificate if present, otherwise `None`.

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)
    data = pki_message["body"]["genp"][index]
    if data["infoType"] != rfc9480.id_it_caProtEncCert:
        raise ValueError()

    if data["infoValue"].isValue:
        # is a single cert, CMPCertificate
        ca_prot_cert = decoder.decode(data["infoValue"], rfc9480.CAProtEncCertValue())

        cert_chain = certutils.build_cert_chain_from_dir(
            ee_cert=ca_prot_cert, cert_chain_dir=cert_chain_dir, root_dir=trustanchors
        )

        certutils.certificates_are_trustanchors(cert_chain[-1], trustanchors=trustanchors, verbose=True)
        certutils.verify_cert_chain_openssl(cert_chain=cert_chain)

        return ca_prot_cert

    logging.debug("The server did not respond with a certificate.")
    return None


# 5.3.19.2 Signing Key Pair Types
# GenMsg: {id-it 2}, < absent >
# GenRep: {id-it 2}, SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier


def prepare_signing_key_types(fill_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to request supported signing algorithms.

    This request is used by the client to retrieve the list of algorithms whose
    subject public key values the CA is willing to certify for signing purposes.

    :param fill_value: Whether to fill the `infoValue` field, which MUST be absent.
    :return: The populated `InfoTypeAndValue` structure.
    """
    return prepare_info_value(rfc9480.id_it_signKeyPairTypes, fill_random=fill_value)


def validate_signing_key_types(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: int = 1, index: int = 0
) -> None:
    """
    Validate the response for signing key pair types message.

    Note: For the purposes of this exchange, rsaEncryption and sha256WithRSAEncryption,
    for example, are considered to be equivalent;
    the question being asked is, "Is the CA willing to certify an RSA public key?

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: Expected number of elements in the general response. Defaults to `1`.
        - `index`: Index of the message to validate.

    Raises:
    ------
        - `ValueError`: If the response did not have the expected size.
        - `ValueError`: If the response does not contain the expected `infoType`.

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)

    data = pki_message["body"]["genp"][index]
    if data["infoType"] != rfc9480.id_it_signKeyPairTypes:
        raise ValueError("Unexpected infoType in response.")

    alg_list = decoder.decode(data["infoValue"], asn1Spec=rfc9480.SignKeyPairTypesValue())

    for alg_id in alg_list:
        name = may_return_oid_to_name(alg_id["algorithm"])
        logging.info("Supported signing algorithm: %s", name)


# 5.3.19.3. Encryption/Key Agreement Key Pair Types
# GenMsg: {id-it 3}, < absent >
# GenRep: {id-it 3}, SEQUENCE SIZE (1..MAX) OF AlgorithmIdentifier


def prepare_enc_key_agreement_types(fill_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to request supported encryption/key agreement algorithms.

    This request is used by the client to retrieve the list of algorithms whose
    subject public key values the CA is willing to certify.

    :param fill_value: Whether to fill the `infoValue` field, which MUST be absent.
    :return: The populated `InfoTypeAndValue` structure.
    """
    return prepare_info_value(rfc9480.id_it_keyPairParamReq, fill_random=fill_value)


def validate_key_agreement_types(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: int = 1, index: int = 0
):
    """
    Validate the response for encryption/key agreement key pair types.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: Expected number of elements in the response (default is 1).
        - `index`: Index of the `genRep` to validate.

    Returns:
    -------
        - A list of supported algorithms.

    Raises:
    ------
        - `ValueError`: If the response did not have the expected size.
        - `ValueError`: If the response does not contain the expected `infoType`.

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)

    data = pki_message["body"]["genp"][index]
    if data["infoType"] != rfc9480.id_it_keyPairParamReq:
        raise ValueError("Unexpected infoType in response.")

    alg_list = decoder.decode(data["infoValue"], asn1Spec=rfc9480.AlgorithmIdentifier())

    supported_algorithms = []
    for alg_id in alg_list:
        name = may_return_oid_to_name(alg_id["algorithm"])
        logging.info("Supported encryption/key agreement algorithm: %s", name)
        supported_algorithms.append(name)

    return supported_algorithms


# Section 5.3.19.4 Preferred Symmetric Algorithm:
# GenMsg: {id-it 4}, < absent >
# GenRep: {id-it 4}, AlgorithmIdentifier


def prepare_preferred_sym_alg(fill_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to ask for a preferred Symmetric Algorithm.

    As of Section RFC4210bis-15: 5.3.19.4. Preferred Symmetric Algorithm
    So the Client can use this one, whenever any confidential information that needs to be
    exchanged between the EE and the CA. As an example, send the private key to the CA.

    :param fill_value: Whether to fill the `infoValue` field, which MUST be absent.
    :return: The populated `InfoTypeAndValue` structure.
    """
    return prepare_info_value(rfc9480.id_it_preferredSymmAlg, fill_random=fill_value)


def validate_preferred_sym_alg(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: Strint = 1, index: int = 0
) -> str:
    """
    Validate the response for the preferred symmetric algorithm request.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: The expected response messages to receive. Defaults to `1`.
        - `index`: The index of the expected message. Defaults to `0`.

    Returns:
    -------
        - The name of the preferred symmetric algorithm.

    Raises:
    ------
        - `ValueError`: If the response does not have the expected size.
        - `ValueError`: If the response does not contain the expected `infoType

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)
    data = pki_message["body"]["genp"][index]
    if data["infoType"] != rfc9480.id_it_preferredSymmAlg:
        raise ValueError()

    alg_id = decoder.decode(data["infoValue"], rfc9480.AlgorithmIdentifier())
    name = may_return_oid_to_name(alg_id["algorithm"])
    logging.info("The preferred symmetric AlgorithmIdentifier is: %s", name)

    return name


# MAY TODO As of rfc9480 2.13. Replace Section 5.3.19.9 - Revocation Passphrase
# Can be sent at any time. copy prepare functions from ./unit_test and then implement.
# GenMsg:    {id-it 12}, EncryptedKey
# GenRep:    {id-it 12}, < absent >


def _prepare_revocation_passphrase(env_data: rfc9480.EnvelopedData) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to send a revocation passphrase.

    This is used by the EE to send a passphrase to a CA/RA for authenticating a
    later revocation request in case the signing private key is no longer available.

    :param env_data: The passphrase encrypted as per the specified mechanism.
    :return: The populated `InfoTypeAndValue` structure.
    """
    enc_key = rfc9480.EncryptedKey()
    enc_key["envelopedData"] = env_data
    return prepare_info_value(rfc9480.id_it_revPassphrase, value=enc_key)


def validate_revocation_passphrase_response(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: int = 1, index: int = 0
):
    """Validate the response for the revocation passphrase request.

    This function validates that the GenRep response for id-it 12 complies with
    the specification, ensuring that no infoValue is present.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: Expected number of messages.
        - `index`: The index of the expected message. Defaults to `0`.

    Raises:
    ------
        - `ValueError`: If the response does not have the expected size.
        - `ValueError`: If the response contains an unexpected `infoType`.
        - `ValueError`: If the response contains an `infoValue`.

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)

    data = pki_message["body"]["genp"][index]

    if data["infoType"] != rfc9480.id_it_revPassphrase:
        raise ValueError(f"The `infoType` was not `id_it_revPassphrase`. Got: {data['infoType']}")

    if data["infoValue"].isValue:
        raise ValueError("Unexpected infoValue in response for revocation passphrase.")


# 5.3.19.13. Supported Language Tags
# GenMsg: {id-it 16}, SEQUENCE SIZE (1..MAX) OF UTF8String
# GenRep: {id-it 16}, SEQUENCE SIZE (1) OF UTF8String
def prepare_supported_language_tags(langs: Union[str, List[str]]) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` to request supported language tags.

    The sender specifies its list of supported languages in order of preference (most preferred to least).

    As of Section RFC4210bis-15: 5.3.19.13 Supported Language Tags

    :param langs: A list or single supported language tag.
    :return: The populated `InfoTypeAndValue` structure.
    """
    if isinstance(langs, str):
        langs = [langs]

    info_val = rfc9480.InfoTypeAndValue()
    info_val["infoType"] = rfc9480.id_it_suppLangTags

    lang_tags = rfc9480.SuppLangTagsValue()
    for lang in langs:
        lang_tags.append(char.UTF8String(lang))

    info_val["infoValue"] = encoder.encode(lang_tags)

    return info_val


def validate_supported_language_tags(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, expected_size: int = 1, index: int = 0
) -> None:
    """
    Validate the response for supported language tags.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the response.
        - `expected_size`: Expected number of messages.
        - `index`: The index of the expected message.

    Raises:
    ------
        - `ValueError`: If the response does not have the expected size.
        - `ValueError`: If the response contains an unexpected `infoType`.
        - `ValueError`: If the response contains more than one language tags.

    """
    validate_general_response(pki_message=pki_message, expected_size=expected_size)

    data = pki_message["body"]["genp"][index]
    if data["infoType"] != rfc9480.id_it_suppLangTags:
        raise ValueError("Unexpected infoType in response.")

    lang_list = decoder.decode(data["infoValue"], asn1Spec=rfc9480.SuppLangTagsValue())

    if len(lang_list) != 1:
        raise ValueError(f"Expected {expected_size} language tags, got {len(lang_list)}.")

    logging.info("Chosen language tag: %s", lang_list[0])


def validate_genm_message_size(  # noqa: D417 Missing argument description in the docstring
    genm: rfc9480.PKIMessage,
    expected_size: int = 1,
) -> None:
    """Validate the General Message PKIMessage.

    Validates only the size and the body name.

    Arguments:
    ---------
        - `genm`: The General Message PKIMessage.
        - `expected_size`: The expected number of messages in the response.

    Raises:
    ------
        - `ValueError`: If the PKIMessage does not contain a General Message body.
        - `ValueError`: If the response does not have the expected size.

    """
    if genm["body"].getName() != "genm":
        raise ValueError("The PKIMessage does not contain a General Message body.")

    if len(genm["body"]["genm"]) != expected_size:
        raise ValueError(f"Expected {expected_size} messages in the General Message body.")


def build_genp_kem_ct_info_from_genm(  # noqa: D417 Missing argument description in the docstring
    genm: PKIMessageTMP, expected_size: int = 1, ca_key: Optional[ECDHPrivateKey] = None, **kwargs
) -> Tuple[bytes, PKIMessageTMP]:
    """Build the KEMCiphertextInfo from a General Message PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The General Message PKIMessage.
        - `expected_size`: The expected number of messages in the response.
        - `ca_key`: The CA's private key to perform the decapsulation with.
        - `**kwargs`: Additional parameters for the PKIHeader.

    Returns:
    -------
        - The shared secret and the General Response PKIMessage.

    Raises:
    ------
        - `ValueError`: If the response does not contain the `KEMCiphertextInfo` OID.
        - `ValueError`: If the `KEMCiphertextInfo` value was not absent.
        - `ValueError`: If the response does not contain the `extraCerts` field.
        - `ValueError`: If the public key was not a KEM public key.

    """
    validate_genm_message_size(genm=genm, expected_size=expected_size)

    value = get_value_from_seq_of_info_value_field(genm["body"]["genm"], oid=id_it_KemCiphertextInfo)

    if value is None:
        raise ValueError("The response did not contain the `KEMCiphertextInfo`.")

    if len(genm["extraCerts"]) < 1:
        raise ValueError("The response did not contain the extraCerts field.")

    cert: rfc9480.CMPCertificate = genm["extraCerts"][0]
    public_key = load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not is_kem_public_key(public_key):
        raise ValueError("The public key was not a KEM public key.")

    if isinstance(public_key, HybridKEMPublicKey):
        ss, ct = public_key.encaps(ca_key)
    else:
        ss, ct = public_key.encaps()

    kem_oid = get_kem_oid_from_key(public_key)

    genm = cmputils._prepare_pki_message(**kwargs)

    kem_ct_info = KemCiphertextInfoAsn1()
    kem_ct_info["ct"] = univ.OctetString(ct)
    kem_ct_info["kem"]["algorithm"] = kem_oid

    info_val = InfoTypeAndValueAsn1()
    info_val["infoType"] = id_it_KemCiphertextInfo
    info_val["infoValue"] = encoder.encode(kem_ct_info)

    genm2 = PKIMessageTMP()
    for field in genm["header"].keys():
        genm2["header"][field] = genm["header"][field]

    genm2["body"]["genp"].append(info_val)
    return ss, genm2


def validate_genp_kem_ct_info(  # noqa: D417 Missing argument description in the docstring
    genp: PKIMessageTMP,
    client_private_key: Optional[KEMPrivateKey],
    expected_size: int = 1,
) -> bytes:
    """Validate the KEMCiphertextInfo in a General Response PKIMessage.

    For more information, please look at the workflow of RFC4210bis-16,
    Appendix E. Variants of Using KEM Keys for PKI Message Protection

    Arguments:
    ---------
        - `genp`: The General Response PKIMessage.
        - `client_private_key`: The client's private key, to perform the decapsulation with.
        - `expected_size`: The expected number of messages in the response.

    Returns:
    -------
        - The shared secret.

    Raises:
    ------
        - `ValueError`: If the response did not contain the `KEMCiphertextInfo` OID.
        - `ValueError`: If the `KEMCiphertextInfo` value was absent.
        - `ValueError`: If the private key was not a KEM private key.

    """
    validate_general_response(pki_message=genp, expected_size=expected_size)

    value = get_value_from_seq_of_info_value_field(genp["body"]["genp"], oid=id_it_KemCiphertextInfo)

    if value is None:
        raise ValueError("The response did not contain the KEMCiphertextInfo OID.")

    if not value.isValue:
        raise ValueError("The KEMCiphertextInfo value was absent.")

    kem_ct_info, rest = decoder.decode(value.asOctets(), KemCiphertextInfoAsn1())

    if not is_kem_private_key(client_private_key):
        raise ValueError("The private key was not a KEM private key.")

    ss = client_private_key.decaps(kem_ct_info["ct"].asOctets())

    return ss


# TODO add params.
def add_general_messages(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage, add_messages: str, rev_passphrase: Optional[rfc9480.EnvelopedData] = None
) -> rfc9480.PKIMessage:
    """
    Add general messages to the PKIMessage `genm` body.

    This function appends various types of general messages to the `genm` field in the PKIMessage body.

    Arguments:
    ---------
        - `pki_message`: The `PKIMessage` to which the general messages will be added.
        - `add_messages`: A comma-separated string of message types to include, such as "get_ca_certs"
        - or "supp_lang_tags".
        - `rev_passphrase`: An optional `EnvelopedData` object representing a revocation passphrase to include.

    Returns:
    -------
        - The updated PKIMessage with the specified general messages appended to the `genm` field.

    Supported Messages:
    -------------------
        - `"get_ca_certs"`: Request for CA certificates.
        - `"current_crl"`: Request for the current CRL.
        - `"preferred_sym_alg"`: Request for the preferred symmetric algorithm.
        - `"enc_key_agree"`: Request for encryption/key agreement types.
        - `"sign_key_types"`: Request for signing key pair types.
        - `"supp_lang_tags"`: Request for supported language tags.

    """
    if add_messages is None:
        messages = set()
    else:
        messages = set(add_messages.strip().split(","))

    pki_message["body"]["genm"] = _append_messages(messages, pki_message["body"]["genm"], rev_passphrase=rev_passphrase)
    return pki_message


# TODO fix doc
def _append_messages(
    messages: Set[str],
    body_content: rfc9480.GenMsgContent,
    fill_value: bool = False,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    supp_lang_tags: str = "DE",
    rev_passphrase: Optional[rfc9480.EnvelopedData] = None,
):
    """Append specified support messages to the GenMsgContent structure.

    :param messages: Set of message types to include, such as "get_ca_certs" or "current_crl".
    :param body_content: The GenMsgContent object to populate.
    :param fill_value: Enables negative testing if `True` and populates absent values with a random `OctetString`.
    :param ca_cert: A certificate for relevant messages.
    :param supp_lang_tags: A list or a single language tag.
    :return: Populated GenMsgContent structure with appended messages.
    """
    if "get_ca_certs" in messages:
        body_content.append(_prepare_get_ca_certs(fill_info_value=fill_value))

    if "get_root_ca_cert_update" in messages:
        body_content.append(_prepare_get_root_ca_cert_update(root_cert=ca_cert))

    if "get_cert_template" in messages:
        body_content.append(_prepare_get_certificate_request_template(fill_info_val=fill_value))

    if "current_crl" in messages:
        body_content.append(prepare_current_crl(fill_value=fill_value))

    if "preferred_sym_alg" in messages:
        body_content.append(prepare_preferred_sym_alg(fill_value=fill_value))

    if "enc_key_agree" in messages:
        body_content.append(prepare_enc_key_agreement_types(fill_value=fill_value))

    if "sign_key_types" in messages:
        body_content.append(prepare_signing_key_types(fill_value=fill_value))

    if "supp_lang_tags" in messages:
        body_content.append(prepare_supported_language_tags(langs=supp_lang_tags))

    if "rev_passphrase" in messages:
        if rev_passphrase is None:
            raise ValueError("The `envelopedData` structure MUST be parsed for the `rev_passphrase` message.")
        body_content.append(_prepare_revocation_passphrase(env_data=rev_passphrase))

    if "kem_ct_info" in messages:
        body_content.append(prepare_info_value(id_it_KemCiphertextInfo, fill_random=fill_value))

    return body_content


# TODO verify with Alex,
# if I misunderstood the RFC, or the RFC is to LAX written.
def prepare_simple_info_types(  # noqa D417 undocumented-param
    name: str, value: Optional[bytes] = None, fill_random: bool = False
) -> rfc9480.InfoTypeAndValue:
    """Prepare a simple `InfoTypeAndValue` structure using a stringified name for the OID.

    This function should only be used for the following OIDs (but can be used for simple
    negative testing for other OIDs).

    These OIDs have a **MUST** be absent `infoValue` field. For some, it does not explicitly say MUST be absent,
    just absent, so it may differ by implementation.

    **MUST** be absent:
    ---------------------
    - "ca_prot_enc_cert"
    - "sign_key_pair_types"
    - "enc_key_agreement_types"
    - "preferred_symm_alg"
    - "ca_certs"
    - "current_crl" (CRL)
    - "implicit_confirm"
    - "cert_req_template"
    - "kem_ct"

    **MAY** be absent:
    ------------------
    - "root_ca_update"

    Supported names (case-insensitive):
    ----------------------------------
    - "ca_prot_enc_cert"
    - "sign_key_pair_types"
    - "enc_key_agreement_types"
    - "preferred_symm_alg"
    - "ca_certs"
    - "cert_req_template"
    - "root_ca_cert_update"
    - "current_crl"
    - "crl_status_list"
    - "rev_passphrase"
    - "supported_lang_tags"
    - "orig_pki_message"

    Arguments:
    ---------
        - `name`: The stringified name of the OID.
        - `value`: Optional bytes to populate the `infoValue` field. If `None`, the field is left absent.
        - `fill_random`: Whether to fill the `infoValue` field with random bytes. If `True`,
        the `value` parameter is ignored.

    Returns:
    -------
        - A populated `InfoTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: If the name does not match a valid OID.

    """
    oid = GeneralInfoOID.get_oid(name)
    return prepare_info_value(oid, value, fill_random=fill_random)


# TODO fix implementation
def prepare_ca_message(messages: str) -> List[rfc9480.InfoTypeAndValue]:
    """Prepare a correctly sending from the CA inside a general message or response.

    :param messages: The messages to include in the general message. Which are comma-separated.
    :return: The prepared list of info types and values.
    """
    if "update_ca" in messages:
        # GenMsg:    {id-it 18}, RootCaKeyUpdateValue
        raise NotImplementedError("Not implemented yet")

    if "unsupported_oid" in messages:
        # GenRep:    {id-it 7}, SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER
        raise NotImplementedError("Not implemented yet")

    raise NotImplementedError("Not implemented yet")
