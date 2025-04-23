# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Logic for building CMP messages for certificate announcements, revocation announcements, and CRL announcements."""

from datetime import datetime
from typing import List, Optional, Union

from pyasn1.type import tag
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword

from resources import ca_ra_utils, certutils, cmputils, prepareutils, utils
from resources.asn1_structures import PKIBodyTMP, PKIMessageTMP
from resources.convertutils import copy_asn1_certificate
from resources.typingutils import SignKey, Strint


def _prepare_cert_id(
    cert: Optional[rfc9480.CMPCertificate] = None,
    cert_id: Optional[rfc9480.CertId] = None,
    cert_id_issuer: Optional[rfc9480.GeneralName] = None,
    serial_number: Optional[int] = None,
) -> rfc9480.CertId:
    """Return the certificate ID.

    :param cert: The certificate to be used for the ID.
    :param cert_id: The certificate ID to be used.
    :param cert_id_issuer: The issuer of the certificate ID.
    :param serial_number: The serial number of the certificate ID.
    :return: The certificate ID.
    """
    if cert is None and cert_id is None and not (cert_id_issuer or serial_number):
        raise ValueError("Either cert or cert_id must be provided.")

    if cert_id is None:
        if cert is None and (cert_id_issuer is None or serial_number is None):
            raise ValueError("Either cert or cert_id_issuer and serial_number must be provided.")

        if cert_id_issuer is None:
            cert_id_issuer = prepareutils.prepare_general_name_from_name(
                cert,  # type: ignore
                extract_subject=False,
            )

        if serial_number is None:
            serial_number = int(cert["tbsCertificate"]["serialNumber"])  # type: ignore

        cert_id = rfc9480.CertId()
        cert_id["issuer"] = cert_id_issuer
        cert_id["serialNumber"] = serial_number
    return cert_id


@keyword(name="Build CMP Certificate Announcement")
def build_cmp_cann_announcement(
    cert: rfc9480.CMPCertificate,
    **kwargs,
) -> PKIMessageTMP:
    """Build a CMP Certificate Announcement (CANN) message.

    Arguments:
    ---------
        cert: The certificate to be announced.
        **kwargs: Additional keyword arguments for the `PKIHeader`.

    Returns:
    -------
        - The CMP Certificate Announcement (CANN) PKIMessage.

    Examples:
    --------
    | ${cann}= | Build CMP Certificate Announcement | ${cert} |

    """
    cert_ann_con = rfc9480.CertAnnContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 16)
    )

    cert_ann_con = copy_asn1_certificate(
        cert=cert,
        target=cert_ann_con,
    )

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"]["cann"] = cert_ann_con  # codespell:ignore

    return pki_message


@keyword(name="Build CMP Revocation Announcement")
def build_cmp_rann_announcement(
    cert: Optional[rfc9480.CMPCertificate] = None,
    status: str = "accepted",
    will_be_revoked_at: Optional[Union[str, datetime]] = None,
    bad_since_date: Optional[Union[str, datetime]] = None,
    cert_id: Optional[rfc9480.CertId] = None,
    cert_id_issuer: Optional[rfc5280.GeneralName] = None,
    serial_number: Optional[int] = None,
    crl_details: Optional[rfc5280.Extensions] = None,
    **kwargs,
) -> PKIMessageTMP:
    """Build a CMP Revocation Announcement (RANN) message.

    Arguments:
    ---------
        cert: The certificate to be revoked.
        status: The status of the certificate.
        will_be_revoked_at: The date when the certificate will be revoked.
        bad_since_date: The date since the certificate is bad.
        cert_id: The certificate ID.
        cert_id_issuer: The issuer of the certificate ID.
        serial_number: The serial number of the certificate.
        crl_details: Details about the CRL.
        **kwargs: Additional keyword arguments for the `PKIHeader`.

    Returns:
    -------
        - The CMP Revocation Announcement (RANN) PKIMessage.

    Raises:
    ------
        - `ValueError`: If the date format is invalid.
        - `ValueError`: If the certificate ID is not provided or cannot be built.

    Examples:
    --------
    | ${rann}= | Build CMP Revocation Announcement | ${cert} | accepted | will_be_revoked_at=2024-01-01T12:00:00Z |

    """
    cert_id = _prepare_cert_id(
        cert=cert,
        cert_id=cert_id,
        cert_id_issuer=cert_id_issuer,
        serial_number=serial_number,
    )

    rev_ann_con = rfc9480.RevAnnContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 17)
    )

    rev_ann_con["certId"] = cert_id
    rev_ann_con["status"] = rfc9480.PKIStatus(status)
    rev_ann_con["willBeRevokedAt"] = prepareutils.prepare_generalized_time(will_be_revoked_at)
    rev_ann_con["badSinceDate"] = prepareutils.prepare_generalized_time(bad_since_date)
    if crl_details is not None:
        rev_ann_con["crlDetails"] = crl_details

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"]["rann"] = rev_ann_con

    return pki_message


@keyword(name="Build CMP CRL Announcement")
def build_crlann_cmp_message(
    crls: Union[str, rfc5280.CertificateList, List[rfc5280.CertificateList]],
    **kwargs,
) -> PKIMessageTMP:
    """Build a CMP CRL Announcement (CRLANN) message.

    Arguments:
    ---------
        crls: The CRL or CRLs to be announced. It Can be a single CRL or a list of CRLs.
        **kwargs: Additional keyword arguments for the `PKIHeader`.

    Returns:
    -------
        - The CMP CRL Announcement (CRLANN) PKIMessage.

    Examples:
    --------
    | ${crlann}= | Build CMP CRL Announcement | ${crl} |

    """
    if isinstance(crls, rfc5280.CertificateList):
        crls = [crls]

    elif isinstance(crls, str):
        der_data = utils.load_and_decode_pem_file(crls)
        crls = [certutils.parse_crl(der_data)]

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"]["crlann"].extend(crls)

    return pki_message


@keyword(name="Build CMP ckuann Message")
def build_cmp_ckuann_message(  # noqa: D417 undocumented-params
    root_ca_key_update: Optional[rfc9480.RootCaKeyUpdateValue] = None,
    new_cert: Optional[rfc9480.CMPCertificate] = None,
    old_cert: Optional[rfc9480.CMPCertificate] = None,
    new_key: Optional[SignKey] = None,
    old_key: Optional[SignKey] = None,
    use_new: bool = False,
    sender: str = "tests@example.com",
    recipient: str = "testr@example.com",
    pvno: Strint = 3,
    **kwargs,
) -> PKIMessageTMP:
    """Build a `CAKeyUpdAnnContent` PKIMessage.

    Arguments:
    ---------
        - `root_ca_key_update`: The root CA key update value. Defaults to `None`.
        - `new_cert`: The new CA certificate to be installed as trust anchor. Defaults to `None`.
        - `old_cert`: The old CA certificate, which was the trust anchor. Defaults to `None`.
        - `new_key`: The private key corresponding to the new CA certificate. Defaults to `None`.
        - `old_key`: The private key corresponding to the old CA certificate. Defaults to `None`.
        - `use_new`: Whether to use the new structure or the old one. Defaults to `False`.
        - `sender`: The sender of the message. Defaults to "tests@example.com".
        - `recipient`: The recipient of the message.  Defaults to "testr@example.com".
        - `pvno`: The version of the message. Defaults to `3`.

    Returns:
    -------
        - The populated `PKIMessage` structure.

    Raises:
    ------
        - `ValueError`: If neither `root_ca_key_update` nor the old certificate and the keys are provided.

    Examples:
    --------
    | ${ckuann}= | Build CMP ckuann | ${root_ca_key_update} |
    | ${ckuann}= | Build CMP ckuann | old_cert=${new_cert} | new_key=${new_key} | old_key=${old_key} |

    """
    body = PKIBodyTMP()

    if root_ca_key_update is None and not (old_cert and new_key and old_key):
        raise ValueError("Either `root_ca_key_update` or `old_cert`, `new_key`, and `old_key` must be provided.")

    if root_ca_key_update is None:
        if old_key is None:
            raise ValueError("If `root_ca_key_update` is not provided, `old_key` must be provided.")

        if new_key is None:
            new_key = old_key

        if old_cert is None:
            raise ValueError("If `root_ca_key_update` is not provided, `old_cert` must be provided.")

        root_ca_key_update = ca_ra_utils.prepare_new_root_ca_certificate(
            new_cert=new_cert,
            old_cert=old_cert,
            new_priv_key=new_key,
            old_priv_key=old_key,
            hash_alg=kwargs.get("hash_alg", "sha256"),
            use_rsa_pss=kwargs.get("use_rsa_pss", True),
            use_pre_hash=kwargs.get("use_pre_hash", False),
        )

    if use_new:
        body["ckuann"]["cAKeyUpdAnnV3"]["newWithNew"] = root_ca_key_update["newWithNew"]
        body["ckuann"]["cAKeyUpdAnnV3"]["oldWithNew"] = root_ca_key_update["oldWithNew"]
        body["ckuann"]["cAKeyUpdAnnV3"]["newWithOld"] = root_ca_key_update["newWithOld"]
    else:
        body["ckuann"]["cAKeyUpdAnnV2"]["newWithNew"] = root_ca_key_update["newWithNew"]
        body["ckuann"]["cAKeyUpdAnnV2"]["oldWithNew"] = copy_asn1_certificate(root_ca_key_update["oldWithNew"])
        body["ckuann"]["cAKeyUpdAnnV2"]["newWithOld"] = copy_asn1_certificate(root_ca_key_update["newWithOld"])

    pki_message = cmputils.prepare_pki_message(pvno=pvno, sender=sender, recipient=recipient, **kwargs)
    pki_message["body"] = body
    return pki_message
