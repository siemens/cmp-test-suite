# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility to simulate a CA PKIMessage response, so that the functions for the Server validation can be tested.

Has functionality to create a certificate, can with prepare_cert_response, generate more responses.
Together with the prepare_envelope_data_utils used to prepare valid `privateKey` field and an encrypted certificate.

If as an example used:
cert, key = build_certificate()
ca_message = build_ca_pki_message(body_type="ip", cert=cert)

Then would this be the structure.

PKIMessage:
 header=PKIHeader:
  pvno=2
  sender=GeneralName:
   rfc822Name=CN=Hans the Tester

  recipient=GeneralName:
   rfc822Name=CN=Hans the Tester


 body=PKIBody:
  ip=CertRepMessage:
   response=SequenceOf:
    CertResponse:
     certReqId=0
     status=PKIStatusInfo:
      status=accepted

     certifiedKeyPair=CertifiedKeyPair:
      certOrEncCert=CertOrEncCert:
       certificate=CMPCertificate:
        tbsCertificate=TBSCertificate:
         version=v3
         serialNumber=468990787293038462999958623892460323717439325250
         signature=AlgorithmIdentifier:
          algorithm=1.2.840.10045.4.3.2

         issuer=Name:
          rdnSequence=RDNSequence:
           RelativeDistinguishedName:
            AttributeTypeAndValue:
             type=2.5.4.3
             value=0x0c0448616e73


         validity=Validity:
          notBefore=Time:
           utcTime=241111071638Z

          notAfter=Time:
           utcTime=251111071638Z


         subject=Name:
          rdnSequence=RDNSequence:
           RelativeDistinguishedName:
            AttributeTypeAndValue:
             type=2.5.4.3
             value=0x0c0448616e73


         subjectPublicKeyInfo=SubjectPublicKeyInfo:
          algorithm=AlgorithmIdentifier:
           algorithm=1.2.840.10045.2.1
           parameters=0x06082a8648ce3d030107

          subjectPublicKey=...


        signatureAlgorithm=AlgorithmIdentifier:
         algorithm=1.2.840.10045.4.3.2

        signature=...

"""

from typing import List, Optional

from pyasn1.codec.der import encoder
from pyasn1.type import constraint, tag, univ
from pyasn1_alt_modules import rfc5652, rfc9480
from resources.cmputils import patch_extra_certs, prepare_pkistatusinfo
from resources.convertutils import copy_asn1_certificate
from resources.envdatautils import prepare_enveloped_data, prepare_signed_data
from resources.typingutils import PrivateKey

from unit_tests.utils_for_test import prepare_pki_header

# TODO refactor this to ca_ra_utils.py

def prepare_enc_key(env_data: rfc5652.EnvelopedData, explicit_tag: int = 0) -> rfc9480.EncryptedKey:
    """Prepare an EncryptedKey structure by encapsulating the provided EnvelopedData.

    :param env_data: The EnvelopedData to wrap in the `EncryptedKey` structure.
    :param explicit_tag: The explicitTag id set for the `EncryptedKey` structure
    :return: An `EncryptedKey` object with encapsulated EnvelopedData.
    """
    enc_key = rfc9480.EncryptedKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, explicit_tag)
    )

    enc_key["envelopedData"] = env_data
    return enc_key


def prepare_cert_or_enc_cert(
    cert: rfc9480.CMPCertificate, enc_cert: rfc5652.EnvelopedData = None
) -> rfc9480.CertOrEncCert:
    """Prepare a CertOrEncCert structure containing either a certificate or encrypted certificate.

    :param cert: A certificate object representing the certificate to include.
    :param enc_cert: An optional EnvelopedData object representing an encrypted certificate.
    :return: A populated CertOrEncCert structure.
    """
    cert_or_enc_cert = rfc9480.CertOrEncCert()
    if cert is not None:
        cert2 = rfc9480.CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        cert_or_enc_cert["certificate"] = copy_asn1_certificate(cert, cert2)

    if enc_cert is not None:
        enc_key = prepare_enc_key(env_data=enc_cert, explicit_tag=1)
        cert_or_enc_cert["encryptedCert"] = enc_key

    return cert_or_enc_cert


def prepare_certified_key_pair(
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
) -> rfc9480.CertifiedKeyPair:
    """Prepare a CertifiedKeyPair structure containing certificate or encrypted certificate and an optional private key.

    :param cert: An optional certificate representing the certificate.
    :param enc_cert: An optional EnvelopedData object for the encrypted certificate.
    :param private_key: An optional EnvelopedData object representing the private key.
    :raises ValueError: If both cert and enc_cert are not provided.
    :return: A populated CertifiedKeyPair structure.
    """
    if not cert and not enc_cert:
        raise ValueError("At least one of `cert` or `enc_cert` must be provided to prepare a CertifiedKeyPair.")

    certified_key_pair = rfc9480.CertifiedKeyPair()
    certified_key_pair["certOrEncCert"] = prepare_cert_or_enc_cert(cert=cert, enc_cert=enc_cert)

    if private_key is not None:
        enc_key = rfc9480.EncryptedKey().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        enc_key["envelopedData"] = private_key
        certified_key_pair["privateKey"] = enc_key

    return certified_key_pair


def prepare_cert_response(
    cert_req_id: int = 0,
    status: str = "accepted",
    text: str = None,
    failinfo: str = None,
    cert=None,
    enc_cert=None,
    private_key=None,
) -> rfc9480.CertResponse:
    """Prepare a CertResponse structure for responding to a certificate request.

    :param cert_req_id: The ID of the certificate request being responded to.
    :param status: The status of the certificate request (e.g., "accepted" or "rejected").
    :param text: Optional status text.
    :param failinfo: Optional failure information.
    :param cert: An optional certificate object.
    :param enc_cert: Optional encrypted certificate as EnvelopedData.
    :param private_key: Optional private key as EnvelopedData.
    :return: A populated CertResponse structure.
    """
    cert_response = rfc9480.CertResponse()
    cert_response["certReqId"] = univ.Integer(cert_req_id)
    cert_response["status"] = prepare_pkistatusinfo(texts=text, status=status, failinfo=failinfo)

    if cert or enc_cert or private_key:
        cert_response["certifiedKeyPair"] = prepare_certified_key_pair(cert, enc_cert, private_key)

    cert_response["rspInfo"] = univ.OctetString("")

    return cert_response


def _prepare_resp_seq(cert: Optional[rfc9480.CMPCertificate], **params) -> univ.SequenceOf:
    """Prepare a sequence of CertResponse structures.

    :param cert: An optional certificate object to include in the response sequence.
    :param params: Additional parameters to pass to prepare_cert_response.
    :return: A sequence of CertResponse structures.
    """
    response_seq = univ.SequenceOf(componentType=rfc9480.CertResponse())
    response_seq.append(prepare_cert_response(cert=cert, **params))
    return response_seq


def _prepare_ca_pubs(cert_list: List[rfc9480.CMPCertificate]) -> univ.SequenceOf:
    """Prepare a sequence of CMPCertificates for CA publication.

    :param cert_list: A list of CMPCertificate objects to include in the CA publication.
    :return: A sequence of CMPCertificates.
    """
    ca_pubs = univ.SequenceOf(componentType=rfc9480.CMPCertificate()).subtype(
        sizeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX),
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
    )
    ca_pubs.extend(cert_list)
    return ca_pubs


def prepare_cert_rep_msg(
    body_type: str,
    ca_pubs_list: Optional[List[rfc9480.CMPCertificate]] = None,
    exclude_resp: bool = False,
    cert: Optional[rfc9480.CMPCertificate] = None,
    responses: Optional[List[rfc9480.CertResponse]] = None,
    cert_req_id: int = 0,
    status: str = "accepted",
    text: Optional[str] = None,
    failinfo: Optional[str] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
) -> rfc9480.CertRepMessage:
    """
    Prepare a CertRepMessage structure for PKI communication.

    This function constructs a CertRepMessage of the specified body type, containing certificate
    responses and optional CA certificates. It allows for adding custom status, fail information,
    and a private key.

    :param body_type: Type of the message body, such as "ip", "cp", or "kup".
    :param ca_pubs_list: Optional list of CA certificate objects for inclusion.
    :param exclude_resp: Exclude the response component if `True`.
    :param cert: Optional end-entity certificate to include in the response.
    :param responses: List of `CertResponse` objects to include in the message.
    :param cert_req_id: Certificate request ID for the response, defaults to 0.
    :param status: Status of the certificate request, defaults to "accepted".
    :param text: Optional additional text information about the status.
    :param failinfo: Optional failure information for the certificate request.
    :param private_key: Optional private key in `EnvelopedData` format.
    :raises ValueError: If `body_type` is unknown or unsupported.
    :return: A populated `CertRepMessage` structure.
    """
    types_to_id = {"ip": 1, "cp": 3, "kup": 8}
    if body_type not in types_to_id:
        raise ValueError(f"Unsupported body_type: '{body_type}'. Expected one of {list(types_to_id.keys())}.")

    cert_rep_msg = rfc9480.CertRepMessage().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, types_to_id[body_type])
    )

    if not exclude_resp:
        if responses:
            response_seq = univ.SequenceOf(componentType=rfc9480.CertResponse())
            response_seq.extend(responses)
        else:
            response_seq = _prepare_resp_seq(
                cert=cert,
                cert_req_id=cert_req_id,
                status=status,
                text=text,
                failinfo=failinfo,
                private_key=private_key,
                enc_cert=enc_cert,
            )
        cert_rep_msg.setComponentByName("response", response_seq)

    if ca_pubs_list is not None:
        ca_pubs = _prepare_ca_pubs(ca_pubs_list)
        cert_rep_msg.setComponentByName("caPubs", ca_pubs)

    return cert_rep_msg


def build_ca_pki_message(
    body_type: str = "ip",
    ca_pubs: Optional[List[rfc9480.CMPCertificate]] = None,
    exclude_resp: bool = False,
    cert: Optional[rfc9480.CMPCertificate] = None,
    responses: Optional[List[rfc9480.CertResponse]] = None,
    cert_req_id: int = 0,
    status: str = "accepted",
    text: Optional[str] = None,
    failinfo: Optional[str] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    sender_kid: Optional[bytes] = None,
    pvno: int = 2,
) -> rfc9480.PKIMessage:
    """Prepare a `PKIMessage` structure containing a `CertRepMessage`.

    This function creates a `PKIMessage` for certificate management, populating it with details such as
    certificate response information, certification authorities (CAs), and response components.


    :param body_type: The type of message body, indicating the type of response
                      ("ip" for initialization, "cp" for certificate, "kup" for key update).
    :param ca_pubs: Optional list of `CMPCertificate` objects from certification authorities (CAs) to include
    in the message.
    :param exclude_resp: If `True`, the response component will be excluded from the message.
    :param cert: The certificate to include in the CertRepMessage.
    :param responses: Optional list of `CertResponse` objects to include in the CertRepMessage.
    :param cert_req_id: The ID associated with the certificate request. Default is `0`.
    :param status: Status of the certificate, such as "accepted" or "rejected". Default is `"accepted"`.
    :param text: Optional status text to accompany the certificate status.
    :param failinfo: Optional failure information if the certificate request is rejected.
    :param private_key: Optional private key wrapped in `EnvelopedData`, typically used for further
    certificate management.
    :param sender_kid: Optional sender key identifier, required for remote key generation response checks.
    :param pvno: The protocol version number of the PKIMessage header. Default is `2`.
    :param enc_cert: A EnvelopeData structure. Currently, no real logic there for encrypted certificates.
    :raises ValueError: If the provided `body_type` is not one of the supported values ("ip", "cp", "kup").
    :return: A populated `PKIMessage` structure with a CertRepMessage in the body.
    """
    pki_message = rfc9480.PKIMessage()
    pki_message["header"] = prepare_pki_header(pvno=pvno, sender_kid=sender_kid)
    pki_message["body"][body_type] = prepare_cert_rep_msg(
        body_type=body_type,
        ca_pubs_list=ca_pubs,
        exclude_resp=exclude_resp,
        cert=cert,
        responses=responses,
        cert_req_id=cert_req_id,
        status=status,
        text=text,
        failinfo=failinfo,
        private_key=private_key,
        enc_cert=enc_cert,
    )
    return pki_message


def build_complete_envelope_data_ca_msg(
    kga_certificate: rfc9480.CMPCertificate,
    kga_signing_key: PrivateKey,
    kga_cert_chain: List[rfc9480.CMPCertificate],
    private_keys: List[PrivateKey],
    issued_cert: rfc9480.CMPCertificate,
    content_encryption_key: bytes,
    version: int,
    recipient_infos: List[rfc5652.RecipientInfo],
    extra_certs: List[rfc9480.CMPCertificate],
    sender_kid: Optional[bytes] = None,
) -> rfc9480.PKIMessage:
    """Build a complete PKIMessage with `EnvelopedData` for CA response.

    Assembles a complete PKIMessage containing the `EnvelopedData` structure
    with the encrypted content and recipient information. It's used in the context of
    non-local key generation in CMP to deliver the generated private keys securely.

    :param kga_certificate: KGA certificate for signing the `SignedData`.
    :param kga_signing_key: Private key corresponding to the KGA certificate.
    :param kga_cert_chain: Certificate chain for the KGA (if applicable).
    :param private_keys: Newly generated private keys to include in the `AsymmetricKeyPackage`.
    :param issued_cert: Issued certificate to include in the PKIMessage.
    :param content_encryption_key: Key for encrypting the content in `EnvelopedData`.
    :param version: CMS version to use in `EnvelopedData`.
    :param recipient_infos: Recipient information structures specifying how recipients can decrypt the content.
    :param extra_certs: Additional certificates to include in the PKIMessage (e.g., issued certificates).
    :param sender_kid: Optional sender key identifier (e.g., SubjectKeyIdentifier of the sender's certificate).
    :return: A `PKIMessage` containing the complete `EnvelopedData` structure ready to be sent to the recipient.
    """
    signed_data = prepare_signed_data(
        signing_key=kga_signing_key,
        cert=kga_certificate,
        private_keys=private_keys,
        sig_hash_name="sha256",
        cert_chain=kga_cert_chain,
    )
    signed_data_der = encoder.encode(signed_data)

    enveloped_data = prepare_enveloped_data(
        recipient_infos=recipient_infos,
        data_to_protect=signed_data_der,
        cek=content_encryption_key,
        version=version,
    )

    ca_message = build_ca_pki_message(pvno=3, private_key=enveloped_data, cert=issued_cert, sender_kid=sender_kid)
    ca_message = patch_extra_certs(ca_message, certs=extra_certs)
    return ca_message
