import logging
import os
import sys
from datetime import datetime, timezone
from typing import Union, Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, useful, constraint, base, char
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed, tagFormatSimple
from pyasn1_alt_modules import rfc4210, rfc9480, rfc6402, rfc5280, rfc8018, rfc5480, rfc4211, rfc2986, rfc2459
from pyasn1_alt_modules.rfc2314 import SignatureAlgorithmIdentifier, Signature, Attributes
from pyasn1_alt_modules.rfc2459 import GeneralName, Extension, Extensions, Attribute, AttributeValue
from pyasn1_alt_modules.rfc2511 import CertTemplate

from cryptoutils import (compute_hmac, compute_pbmac1, get_hash_from_signature_oid, compute_hash,
                         compute_password_based_mac, sign_data, get_sig_oid_from_key_hash,
                         get_alg_oid_from_key_hash)
from certutils import parse_certificate

# from utils import load_and_decode_pem_file
import utils
from cmp_enums import PKIStatus

# When dealing with post-quantum crypto algorithms, we encounter big numbers, which wouldn't be pretty-printed
# otherwise. This is just for cosmetic convenience.
sys.set_int_max_str_digits(0)

# from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))

# revocation reasons http://www.alvestrand.no/objectid/2.5.29.21.html#
REASON_UNSPECIFIED = 0
REASON_KEY_COMPROMISE = 1
REASON_CA_COMPROMISE = 2
REASON_AFFILIATION_CHANGED = 3
REASON_SUPERSEDED = 4
REASON_CESSATION_OF_OPERATION = 5
REASON_CERTIFICATE_HOLD = 6
REASON_REMOVE_FROM_CRL = 8

# PKIStatus meanings http://www.ietf.org/rfc/rfc4210.txt page 86
PKISTATUS_ACCEPTED = 0
PKISTATUS_GRANTED_WITH_MODS = 1
PKISTATUS_REJECTION = 2
PKISTATUS_WAITING = 3
PKISTATUS_REVOCATION_WARNING = 4
PKISTATUS_REVOCATION_NOTIFICATION = 5
PKISTATUS_KEY_UPDATE_WARNING = 6


def build_cmp_revive_request(serial_number, sender='test-cmp-cli@example.com', recipient='test-cmp-srv@example.com'):
    return build_cmp_revoke_request(serial_number, sender=sender, recipient=recipient, reason=REASON_REMOVE_FROM_CRL)


def build_cmp_revoke_request(serial_number, sender='test-cmp-cli@example.com',
                             recipient='test-cmp-srv@example.com',
                             reason=REASON_UNSPECIFIED):
    """Creates a certificate revocation request, based on the given serial#
    :param serial_number: str, serial number of certificate to revoke
    :param sender: optional str, sender to use in the request
    :param recipient: optional str, recipient of the request
    :param reason: optional int, one of the REASON_* constants
    :returns: pyasn1 PKIMessage """

    # PKIHeader
    pvno = univ.Integer(2)  # cmp2000
    sender = GeneralName().setComponentByName('rfc822Name', sender)
    recipient = GeneralName().setComponentByName('rfc822Name', recipient)

    pki_header = rfc4210.PKIHeader()
    pki_header.setComponentByName('pvno', pvno)
    pki_header.setComponentByName('sender', sender)
    pki_header.setComponentByName('recipient', recipient)

    # PKIBody
    pki_body = rfc4210.PKIBody()

    # for `rr` revocation requests we need to build a structure of the form
    # RevReqContent/RevDetails/CertTemplate
    rev_req_content = rfc4210.RevReqContent()
    rev_details = rfc4210.RevDetails()
    cert_template = CertTemplate()
    cert_template.setComponentByName('serialNumber', serial_number)
    rev_details.setComponentByName('certDetails', cert_template)

    # create an extension that explicitly specifies the reason for revoking the cert.
    # this is also how you specify whether you set it on HOLD or RESUME a held cert.
    crl_entry_details = Extensions()
    crl_reason = Extension()
    crl_reason.setComponentByName('extnID', univ.ObjectIdentifier((2, 5, 29, 21)))  # 2.5.29.21 CRL reason
    crl_reason.setComponentByName('extnValue', REASON_UNSPECIFIED)
    crl_entry_details.setComponentByPosition(0, crl_reason)

    rev_details.setComponentByName('crl_entry_details', crl_entry_details)

    rev_req_content.setComponentByPosition(0, rev_details)

    # this `magic` is required because `[11] RevReqContent` has the explicit 11 tag
    # thus we create an ad-hoc subtype, just like we did in BuildCmpFromPkcs10
    # explained http://sourceforge.net/mailarchive/message.php?msg_id=31787332
    ctag11 = Tag(tagClassContext, tagFormatConstructed, 11)
    rev_req_content_tagged = rev_req_content.subtype(explicitTag=ctag11, cloneValueFlag=True)
    pki_body.setComponentByName('rr', rev_req_content_tagged)

    pki_message = rfc4210.PKIMessage()
    pki_message.setComponentByName('body', pki_body)
    pki_message.setComponentByName('header', pki_header)
    return pki_message


def _prepare_password_based_mac_parameters(salt=None, iterations=1000, hash_alg="sha256"):
    """Helper function to construct the ASN1 structures required for using password-based-mac protection

    :param salt: optional bytes, salt to use for the password-based-mac protection, if not given, will generate 16 random bytes
    :param iterations: optional int, number of iterations of the OWF (hashing) to perform
    :param hash_alg: optional str, name of hashing algorithm to use, "sha256" by default
    :return: pyasn1 rfc9480.PBMParameter structure
    """
    salt = salt or os.urandom(16)

    match hash_alg:
        case "sha256":
            hmac_alg_oid = rfc8018.id_hmacWithSHA256
            hash_alg_oid = rfc5480.id_sha256
        case "sha384":
            hmac_alg_oid = rfc8018.id_hmacWithSHA384
            hash_alg_oid = rfc5480.id_sha384
        case "sha512":
            hmac_alg_oid = rfc8018.id_hmacWithSHA512
            hash_alg_oid = rfc5480.id_sha512
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

    pbm_parameter = rfc9480.PBMParameter()
    pbm_parameter['salt'] = univ.OctetString(salt).subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 128))
    pbm_parameter['iterationCount'] = iterations

    pbm_parameter['owf'] = rfc8018.AlgorithmIdentifier()
    pbm_parameter['owf']['algorithm'] = hash_alg_oid
    pbm_parameter['owf']['parameters'] = univ.Null()

    pbm_parameter['mac'] = rfc8018.AlgorithmIdentifier()
    pbm_parameter['mac']['algorithm'] = hmac_alg_oid
    pbm_parameter['mac']['parameters'] = univ.Null()

    return pbm_parameter


def _prepare_pbmac1_parameters(salt=None, iterations=1, length=32, hash_alg="sha256"):
    salt = salt or os.urandom(16)

    match hash_alg:
        case "sha256":
            hmac_alg = rfc8018.id_hmacWithSHA256
        case "sha384":
            hmac_alg = rfc8018.id_hmacWithSHA384
        case "sha512":
            hmac_alg = rfc8018.id_hmacWithSHA512
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

    outer_params = rfc8018.PBMAC1_params()
    outer_params['keyDerivationFunc'] = rfc8018.AlgorithmIdentifier()

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params['salt']['specified'] = univ.OctetString(salt)
    pbkdf2_params['iterationCount'] = iterations
    pbkdf2_params['keyLength'] = length
    pbkdf2_params['prf'] = rfc8018.AlgorithmIdentifier()
    pbkdf2_params['prf']['algorithm'] = hmac_alg
    pbkdf2_params['prf']['parameters'] = univ.Null()

    outer_params['keyDerivationFunc']['algorithm'] = rfc8018.id_PBKDF2
    outer_params['keyDerivationFunc']['parameters'] = pbkdf2_params

    outer_params['messageAuthScheme']['algorithm'] = hmac_alg
    outer_params['messageAuthScheme']['parameters'] = univ.Null()

    return outer_params


def _prepare_implicit_confirm_general_info_structure():
    """This is a helper function to prepare the `generalInfo` field of a PKIHeader structure,
    if we want to tell the server that we want the implicitConfirm feature"""
    implicit_confirm = rfc9480.InfoTypeAndValue()
    implicit_confirm['infoType'] = rfc9480.id_it_implicitConfirm
    implicit_confirm['infoValue'] = univ.Null("")
    # TODO ask Russ about it, if use the line below instead of the one above, the structure is not present in the final
    # pkiheader. When stepping through it with the debugger I noticed that with `""` the structure isValue=True, whereas
    # without it isValue=False and the thing is a schema, rather than a value object; what's the logic?
    # implicit_confirm['infoValue'] = univ.Null()

    general_info_wrapper = univ.SequenceOf(componentType=rfc9480.InfoTypeAndValue()).subtype(
        subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX)).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 8))

    general_info_wrapper.setComponentByPosition(0, implicit_confirm)
    return general_info_wrapper


def _prepare_pki_message(sender='tests@example.com', recipient='testr@example.com', protection='pbmac1',
                         omit_fields=None, transaction_id=None, sender_nonce=None, recip_nonce=None,
                         implicit_confirm=False, extra_certs=None):
    """Generic function for preparing the skeleton structure of a PKIMessage, the body of which must be
    set later.

    :param omit_fields: optional str, comma-separated list of field names not to include in the resulting PKIMMessage
    :param extra_certs extraCerts parsed to the PKIMessage structure, for out-of-bounds means or signing.
    :returns: pyasn1 PKIMessage structure without a body"""
    # since pyasn1 does not give us a way to remove an attribute from a structure after it was added to it,
    # we proactively check whether a field should be omitted (e.g. when crafting bad inputs) and skip adding
    # it in the first place
    if omit_fields is None:
        omit_fields = set()
    else:
        omit_fields = set(omit_fields.strip().split(','))

    pki_header = rfc9480.PKIHeader()

    if 'pvno' not in omit_fields:
        pvno = univ.Integer(2)
        pki_header['pvno'] = pvno

    if 'sender' not in omit_fields:
        sender = rfc5280.GeneralName().setComponentByName('rfc822Name', sender)
        pki_header['sender'] = sender

    if 'recipient' not in omit_fields:
        recipient = rfc5280.GeneralName().setComponentByName('rfc822Name', recipient)
        pki_header['recipient'] = recipient

    if 'transactionID' not in omit_fields:
        transaction_id = transaction_id or os.urandom(16)
        wrapper_transaction_id = univ.OctetString(transaction_id).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 4)
        )
        pki_header['transactionID'] = wrapper_transaction_id

    if 'senderNonce' not in omit_fields:
        sender_nonce = sender_nonce or os.urandom(16)
        wrapper_sender_nonce = univ.OctetString(sender_nonce).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 5)
        )
        pki_header['senderNonce'] = wrapper_sender_nonce

    if 'recipNonce' not in omit_fields:
        # works well, but I'm not sure we need it for now
        recip_nonce = recip_nonce or os.urandom(16)
        wrapper_recipient_nonce = univ.OctetString(recip_nonce).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 6)
        )
        pki_header['recipNonce'] = wrapper_recipient_nonce

    # SHOULD NOT be required
    # TODO later - set to some bad time and see what happens
    if 'messageTime' not in omit_fields:
        now = datetime.now(timezone.utc)
        message_time = useful.GeneralizedTime().fromDateTime(now)
        message_time_subtyped = message_time.subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
        )
        pki_header['messageTime'] = message_time_subtyped

    if 'senderKID' not in omit_fields:
        pki_header['senderKID'] = rfc9480.KeyIdentifier(b'CN=CloudCA-Integration-Test-User').subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
        )

    if 'recipKID' not in omit_fields:
        pki_header['recipKID'] = rfc9480.KeyIdentifier(b'CN=CloudPKI-Integration-Testl').subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 3)
        )

    if 'protection' not in omit_fields:
        prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
        )

        if protection == 'pbmac1':
            prot_alg_id['algorithm'] = rfc8018.id_PBMAC1
            pbmac1_parameters = _prepare_pbmac1_parameters(salt=None, iterations=262144, length=32, hash_alg="sha512")
            prot_alg_id['parameters'] = pbmac1_parameters

        elif protection == 'password-based-mac':
            prot_alg_id['algorithm'] = rfc4210.id_PasswordBasedMac
            pbm_parameters = _prepare_password_based_mac_parameters(salt=None, iterations=1000, hash_alg="sha256")
            prot_alg_id['parameters'] = pbm_parameters

        elif protection == 'signature':
            # TODO this depends on the signature algorithm, which implies we'd have to pass in the key or some
            # information about it
            pass

        pki_header['protectionAlg'] = prot_alg_id

    if 'generalInfo' not in omit_fields and implicit_confirm:
        # If implicitConfirm is used, it is featured in the `generalInfo` field of the structure
        general_info = _prepare_implicit_confirm_general_info_structure()
        # pki_header['generalInfo'].setComponentByPosition(0, general_info)
        pki_header['generalInfo'] = general_info

    if 'freeText' not in omit_fields:
        # this freeText attribute bears no functionality, but we include it here for the sake of
        # having a complete example of a PKIHeader structure
        free_text = rfc9480.PKIFreeText().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 7)
        )
        free_text.setComponentByPosition(0, 'This text is free, so let us have it')
        pki_header['freeText'] = free_text



    # PKIMessage
    pki_message = rfc9480.PKIMessage()
    pki_message['header'] = pki_header

    return pki_message


def build_p10cr_from_csr(csr, sender='tests@example.com', recipient='testr@example.com', protection='pbmac1',
                         omit_fields=None, transaction_id=None, sender_nonce=None, recip_nonce=None,
                         implicit_confirm=False):
    """Creates a pyasn1 p10cr pkiMessage from a pyasn1 PKCS10 CSR,

    :param csr: pyasn1 rfc6402.CertificationRequest
    :param omit_fields: optional str, comma-separated list of field names not to include in the resulting PKIMEssage

    :returns: pyasn1 PKIMessage structure with a body set to p10cr"""
    pki_message = _prepare_pki_message(sender=sender, recipient=recipient, protection=protection,
                                       omit_fields=omit_fields, transaction_id=transaction_id,
                                       sender_nonce=sender_nonce, recip_nonce=recip_nonce,
                                       implicit_confirm=implicit_confirm)

    # Prepare PKIBody of type p10cr
    pki_body = rfc9480.PKIBody()
    pki_body['p10cr']['certificationRequestInfo'] = csr['certificationRequestInfo']
    pki_body['p10cr']['signatureAlgorithm'] = csr['signatureAlgorithm']
    pki_body['p10cr']['signature'] = csr['signature']

    pki_message['body'] = pki_body
    return pki_message


def build_cr_from_csr(csr, signing_key, hash_alg='sha256', cert_req_id=0,
                      sender='tests@example.com', recipient='testr@example.com',
                      protection='pbmac1', omit_fields=None, transaction_id=None, sender_nonce=None,
                      recip_nonce=None, implicit_confirm=False):
    """Create a PKIMessage of type CR, given a CSR and a signing key

    :param csr: pyasn1 rfc6402.CertificationRequest
    :param signing_key: cryptography.hazmat.primitives.asymmetric key object
    :param hash_alg: optional str, name of the hashing algorithm to use for proof of possession (sha256 by default)
    :param cert_req_id: optional int, value for certReqId, 0 by default

    :returns: pyasn1 PKIMessage structure with a body set to p10cr"""

    pki_message = _prepare_pki_message(sender=sender, recipient=recipient, protection=protection,
                                       omit_fields=omit_fields, transaction_id=transaction_id,
                                       sender_nonce=sender_nonce, recip_nonce=recip_nonce,
                                       implicit_confirm=implicit_confirm)

    # ask Russ: why can't I write `cert_template['subject'] = csr['certificationRequestInfo']['subject']`?
    # or at least `cert_template['subject'] = csr['certificationRequestInfo']['subject'].subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 5))`?
    # this is related to the schema-vs-value matter
    cert_template = rfc9480.CertTemplate()
    subject = rfc5280.Name().subtype(
        implicitTag=Tag(tagClassContext, tagFormatConstructed, 5))
    subject.setComponentByName('rdnSequence', csr['certificationRequestInfo']['subject']['rdnSequence'])
    cert_template['subject'] = subject
    # cert_template['subject'] = csr['certificationRequestInfo']['subject'].subtype(
    #     implicitTag=Tag(tagClassContext, tagFormatConstructed, 5))
    # cert_template['subject'] = csr['certificationRequestInfo']['subject']
    # subject = csr['certificationRequestInfo']['subject']

    pub_key_info = rfc5280.SubjectPublicKeyInfo().subtype(
        implicitTag=Tag(tagClassContext, tagFormatConstructed, 6))
    pub_key_info.setComponentByName('algorithm', csr['certificationRequestInfo']['subjectPublicKeyInfo']['algorithm'])
    pub_key_info.setComponentByName('subjectPublicKey',
                                    csr['certificationRequestInfo']['subjectPublicKeyInfo']['subjectPublicKey'])
    cert_template['publicKey'] = pub_key_info
    # ask Russ: this is what I had before - it ran without error, but the resulting pki_message did not contain this
    # section in the end
    # cert_template['publicKey'] = csr['certificationRequestInfo']['subjectPublicKeyInfo'].subtype(
    #     implicitTag=Tag(tagClassContext, tagFormatConstructed, 6))

    cert_request = rfc4211.CertRequest()
    cert_request['certReqId'] = cert_req_id
    cert_request['certTemplate'] = cert_template

    # DER-encode the CertRequest and calculate its signature
    der_cert_request = encoder.encode(cert_request)
    signature = sign_data(der_cert_request, signing_key, hash_alg=hash_alg)

    popo_key = rfc4211.POPOSigningKey().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 1))
    popo_key['signature'] = univ.BitString().fromOctetString(signature)

    # patch the algorithm inside algorithmIdentifier, instead of re-creating the structure from scratch
    popo_key['algorithmIdentifier'] = csr['certificationRequestInfo']['subjectPublicKeyInfo']['algorithm'].clone()
    popo_sig_oid = get_sig_oid_from_key_hash(csr['certificationRequestInfo']['subjectPublicKeyInfo']['algorithm']['algorithm'], hash_alg)
    popo_key['algorithmIdentifier']['algorithm'] = popo_sig_oid

    popo = rfc4211.ProofOfPossession()
    popo['signature'] = popo_key

    cert_request_msg = rfc4211.CertReqMsg()
    cert_request_msg['certReq'] = cert_request
    cert_request_msg['popo'] = popo

    # cert_request_messages = rfc9480.CertReqMessages()
    # cert_request_messages.append(cert_request_msg)

    pki_body = rfc9480.PKIBody()
    pki_body['cr'] = rfc9480.CertReqMessages().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 2))
    pki_body['cr'].append(cert_request_msg)
    pki_message['body'] = pki_body
    # cert_request_messages = rfc9480.CertReqMessages()
    # cert_request_messages.append(cert_request_msg)
    #
    #
    # pki_body = rfc9480.PKIBody()
    # pki_body['cr'] = cert_request_messages.subtype(
    #         explicitTag=Tag(tagClassContext, tagFormatSimple, 2))
    # pki_message['body'] = pki_body

    return pki_message


def build_cert_conf(cert, cert_req_id=-1, sender='tests@example.com', recipient='testr@example.com',
                    protection='pbmac1',
                    omit_fields=None, transaction_id=None, sender_nonce=None, recip_nonce=None,
                    implicit_confirm=False):
    """Create a PKIMessage of certConf type

    :param cert: pyasn1 certificate object
    :param omit_fields: optional str, comma-separated list of field names not to include in the resulting PKIMessage

    :returns: pyasn1 PKIMessage structure with a body set to certConf based on the given cert"""
    pki_message = _prepare_pki_message(sender=sender, recipient=recipient, protection=protection,
                                       omit_fields=omit_fields, transaction_id=transaction_id,
                                       sender_nonce=sender_nonce, recip_nonce=recip_nonce,
                                       implicit_confirm=implicit_confirm)

    sig_algorithm = str(cert['signature']['algorithm'])
    hash_alg = get_hash_from_signature_oid(sig_algorithm)
    der_cert = encode_to_der(cert)
    hash = compute_hash(hash_alg, der_cert)

    cert_status = rfc9480.CertStatus()
    cert_status['certHash'] = univ.OctetString(hash)
    cert_status['certReqId'] = cert_req_id

    cert_conf = rfc9480.CertConfirmContent().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 24)
    )
    cert_conf.append(cert_status)

    pki_body = rfc9480.PKIBody()
    pki_body['certConf'] = cert_conf
    pki_message['body'] = pki_body
    return pki_message


def protect_pkimessage_hmac(pki_message, password):
    """Protects a PKIMessage with a HMAC, based on a password, returning the updated pyasn1 PKIMessage structure
    :param pki_message: pyasn1 PKIMessage
    :param password: optional str, password to use for calculating the HMAC protection
    :returns: pyasn1 PKIMessage structure with the prorection included"""
    protected_part = rfc9480.ProtectedPart()
    protected_part['header'] = pki_message['header']
    protected_part['body'] = pki_message['body']

    encoded = encoder.encode(protected_part)
    protection = compute_hmac(encoded, password, hash_alg="sha512")
    wrapped_protection = rfc9480.PKIProtection().fromOctetString(protection).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['protection'] = wrapped_protection
    return pki_message


def protect_pkimessage_pbmac1(pki_message, password, iterations=262144, salt=None, length=32, hash_alg="sha512"):
    """Protects a PKIMessage with a PBMAC1, based on a password, returning the updated pyasn1 PKIMessage structure
    :param pki_message: pyasn1 PKIMessage
    :param password: optional str, password to use for calculating the HMAC protection
    :returns: pyasn1 PKIMessage structure with the protection included"""

    # Prepare the parameters for protectionAlg to update the header, because the incoming pki_message may have another
    # type of protection, or no protection at all.
    prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
    )

    prot_alg_id['algorithm'] = rfc8018.id_PBMAC1
    pbmac1_parameters = _prepare_pbmac1_parameters(salt=salt, iterations=iterations, length=length, hash_alg=hash_alg)
    prot_alg_id['parameters'] = pbmac1_parameters

    pki_message['header']['protectionAlg'] = prot_alg_id

    protected_part = rfc9480.ProtectedPart()
    protected_part['header'] = pki_message['header']
    protected_part['body'] = pki_message['body']

    encoded = encoder.encode(protected_part)
    protection = compute_pbmac1(encoded, password, iterations=iterations, salt=salt, length=length, hash_alg=hash_alg)
    wrapped_protection = rfc9480.PKIProtection().fromOctetString(protection).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['protection'] = wrapped_protection
    return pki_message


def protect_pkimessage_password_based_mac(pki_message, password, iterations=1000, salt=None, hash_alg="sha256"):
    """Protects a PKIMessage with a password-based-mac (defined in RFC 4210), based on a password, returning
    the updated pyasn1 PKIMessage structure

    :param pki_message: pyasn1 PKIMessage to protect
    :param password: optional, password to use for calculating the password-based-mac protection
    :returns: pyasn1 PKIMessage structure with the protection included"""

    if type(salt) is str:
        # if it came as a string, it was passed directly through RobotFramework; we accept that and transform it
        # to have better readability in RF test cases
        salt = bytes(salt, 'utf-8')

    # If protection parameters are already set in the message, we have to override that
    # because sometimes we're dealing not with messages we produced ourselves, but with messages
    # loaded from somewhere else as a template
    prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
    )
    prot_alg_id['algorithm'] = rfc4210.id_PasswordBasedMac
    pbm_parameters = _prepare_password_based_mac_parameters(salt=salt, iterations=iterations, hash_alg=hash_alg)
    prot_alg_id['parameters'] = pbm_parameters
    pki_message['header']['protectionAlg'] = prot_alg_id

    protected_part = rfc9480.ProtectedPart()
    protected_part['header'] = pki_message['header']
    protected_part['body'] = pki_message['body']

    encoded = encoder.encode(protected_part)
    protection = compute_password_based_mac(encoded, password, iterations=iterations, salt=salt, hash_alg=hash_alg)

    wrapped_protection = rfc9480.PKIProtection().fromOctetString(protection).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['protection'] = wrapped_protection
    return pki_message


def protect_pkimessage_with_signature(pki_message, signing_key, extra_certs=None, hash_alg="sha256"):
    """Protects a PKIMessage with a signature, returning the updated pyasn1 PKIMessage structure

    :param pki_message: pyasn1 PKIMessage to protect
    :param signing_key: cryptography.hazmat.primitives.asymmetric key object to use for signing
    :param hash_alg: optional str, name of the hashing algorithm to use with the signature (sha256 by default)
    :returns: pyasn1 PKIMessage structure with the protection included"""

    # Prepare the parameters for protectionAlg to update the header, because the incoming pki_message may have another
    # type of protection, or no protection at all.
    prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
    )

    prot_alg_id['algorithm'] = get_alg_oid_from_key_hash(signing_key, hash_alg)

    # TODO create different parameter structures depending on what the signing key is
    parameters = univ.Null("")
    prot_alg_id['parameters'] = parameters

    pki_message['header']['protectionAlg'] = prot_alg_id

    protected_part = rfc9480.ProtectedPart()
    protected_part['header'] = pki_message['header']
    protected_part['body'] = pki_message['body']

    encoded = encoder.encode(protected_part)
    protection = sign_data(encoded, signing_key, hash_alg)

    wrapped_protection = rfc9480.PKIProtection().fromOctetString(protection).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['protection'] = wrapped_protection

    # TODO: add extraCerts here
    # - if it is a path string - load it and parse it
    # - it could also be the raw DER-encoded or PEM-encoded bytes; for now we assume it is a path
    if extra_certs:
        raw = utils.load_and_decode_pem_file(extra_certs)
        cert = parse_certificate(raw)
        extra_certs_wrapper = univ.SequenceOf(
            componentType=rfc9480.CMPCertificate()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, rfc9480.MAX)).subtype(
                    explicitTag=Tag(tagClassContext, tagFormatSimple, 1))
        extra_certs_wrapper.append(cert)

        pki_message['extraCerts'] = extra_certs_wrapper

    return pki_message


def encode_to_der(asn1_structure):
    """Generic tool for DER-encoding a pyasn1 data structure"""
    return encoder.encode(asn1_structure)


def csr_attach_signature(csr, signature):
    """Takes a pyasn1 CSR object and attaches the signature to it, returning a
    signed pyasn1 CSR object. The signature is a buffer of raw data (not base64, etc.)"""
    sig_alg_id = SignatureAlgorithmIdentifier()
    algorithm = rfc5480.sha1WithRSAEncryption
    parameters = encoder.encode(univ.Null())  # no params are used

    sig_alg_id['algorithm'] = algorithm
    sig_alg_id['parameters'] = parameters

    # take the raw signature and turn it into a BitString representations
    signature = Signature("'%s'H" % ''.join("%02X" % ord(c) for c in signature))

    csr['signature'] = signature
    csr['signatureAlgorithm'] = sig_alg_id
    return csr


def csr_add_extensions(csr, extensions):
    """Takes a pyasn1 CSR and adds pyasn1-structured extensions, passed
    as a list"""
    # extensions are kept in a `SetOf Attributes` and are explicitly tagged 0
    extension_set = univ.SetOf()
    attributes = Attributes().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))

    # the attribute type we need is a `x509 v3 extension` with the corresponding OID
    attribute = Attribute()
    attribute['type'] = univ.ObjectIdentifier('1.2.840.113549.1.9.14')

    # the extensions are wrapped in a sequence before they go into the set
    wrapping_sequence = univ.Sequence()
    for index, extension in enumerate(extensions):
        wrapping_sequence[index] = AttributeValue(encoder.encode(extension))

    extension_set[0] = wrapping_sequence
    attribute['vals'] = extension_set
    attributes[0] = attribute

    csr['certificationRequestInfo']['attributes'] = attributes
    return csr


def csr_extend_subject(csr, rdn):
    """Extends the SubjectName in a pyasn1-structured CSR with a
    pyasn1 RelativeDistinguishedName structure"""
    original_subject = csr['certificationRequestInfo']['subject'][0]
    current_length = len(original_subject)
    original_subject[current_length] = rdn
    return csr


def parse_pki_message(data: bytes) -> rfc9480.PKIMessage:
    """Parse input data to PKIMessage structure and return a pyasn1 parsed object.

    Arguments:
        data (bytes): The raw input data to be parsed.

    Returns:
        pyasn1 parsed object: Represents the PKIMessage structure.

    Raises:
        ValueError: If the input is not of type `bytes` and cannot be cast to `bytes`.
    """

    try:
        pki_message, _remainder = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    except PyAsn1Error as err:
        # Suppress detailed pyasn1 error messages; they are typically too verbose and
        # not helpful for non-pyasn1 experts. If debugging is needed, retrieve the server's
        # response from Robot Framework's log and manually pass it into this function.
        raise ValueError("Failed to parse PKIMessage: %s ..." % str(err)[:100])

    return pki_message


def get_cmp_status_from_pki_message(pki_message, response_index=0):
    """Takes pyasn1 PKIMessage object and returns its status as a string

    :param response_index: optional int, index of response to get from the sequence, 0 by default
    """
    message_type = get_cmp_response_type(pki_message)  # e.g., rp, ip, etc.
    response = pki_message['body'][message_type]['response'][response_index]
    status = response['status']['status']
    return str(status)


def get_cmp_response_type(pki_message):
    """Returns the body type of a pyasn1 object representing a PKIMessage as a string, e.g., rp, ip"""
    return pki_message['body'].getName()


def get_cert_from_pki_message(pki_message, cert_number=0):
    """Takes a pyasn1-object representing a response to a CSR,
    containing the PKIMessage structure with the issued certificate in it,
    and returns the actual certificate
    :param pki_message: pyasn1 PkiMessage
    :param cert_number: optional int, index of certificate to extract, will only extract the first certificate
                        from the sequence by default

    :return:    pyasn1 object representing a certificate
    """
    message_type = get_cmp_response_type(pki_message)
    # TODO throw an error if this is not a type of message that contains certificates

    response = pki_message['body'][message_type]['response'][cert_number]
    # status = response['status']['status']

    cert = response['certifiedKeyPair']['certOrEncCert']['certificate']['tbsCertificate']
    # serial_number = str(cert['tbsCertificate']['serialNumber'])
    # return serial_number, cert
    return cert


def parse_csr(raw_csr: bytes) -> rfc6402.CertificationRequest:
    """Builds a pyasn1-structured CSR out of a raw, base-64 request."""
    csr, _ = decoder.decode(raw_csr, asn1Spec=rfc6402.CertificationRequest())
    return csr


def patch_transaction_id(pki_message, new_id=None, prefix=None):
    """Patches the transactionId of a PKIMessage structure with a new ID, this is useful when you load a request
    from a file and send it multiple times to the CA. It would normally reject it because the transactionId is
    repeated - hence the patching.

    :param pki_message: pyasn1 PKIMessage structure, but raw DER-encoded blobs are also accepted, will be converted
                        automatically, this is to make it easier to use this function in RobotFramework
    :param new_id: optional bytes, new transactionId to use, will generate a random one by default
    :param prefix: optional bytes or str, prefix to use for the transactionId, you will need this if you want the
                   transactionId to be random, but still easily identifiable in the logs; we allow it to be a string
                   so it can be passed directly from RobotFramework tests
    :returns: a pyasn1 PKIMessage structure with the updated transactionId
    """
    if type(pki_message) is bytes:
        pki_message = parse_pki_message(pki_message)

    new_id = new_id or os.urandom(16)

    if prefix:
        new_id = bytes(prefix, 'utf-8') + new_id

    wrapper_transaction_id = univ.OctetString(new_id).subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 4)
    )
    pki_message['header']['transactionID'] = wrapper_transaction_id
    return pki_message


def patch_message_time(pki_message, new_time=None):
    """Patches the messageTime field of a PKIMessage structure with a new time,
    or the current time if none is provided

    :param pki_message: pyasn1 PKIMessage structure, but raw DER-encoded blobs are also accepted, will be converted
                        automatically, this is to make it easier to use this function in RobotFramework
    :param new_time: optional datetime, time to use for the messageTime field, will use the current time by default
    """
    if type(pki_message) is bytes:
        pki_message = parse_pki_message(pki_message)

    new_time = new_time or datetime.now(timezone.utc)
    message_time = useful.GeneralizedTime().fromDateTime(new_time)
    message_time_subtyped = message_time.subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['header']['messageTime'] = message_time_subtyped
    return pki_message


def find_oid_in_general_info(pki_message, oid):
    """Check if a given OID is present in the generalInfo part of a PKIMessage header

    :param pki_message: pyasn1 object representing a PKIMessage
    :param oid: str, OID we're looking for
    :returns: bool
    """
    # generalInfo [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue OPTIONAL
    # generalInfo is a sequence, we iterate through it and look for the OID we need
    general_info = pki_message['header']['generalInfo']
    oid = univ.ObjectIdentifier(oid)
    for entry in general_info:
        if entry['infoType'] == oid:
            return True

    return False


def add_implicit_confirm(pki_message):
    """Set the generalInfo part of a PKIMessage header to a structure that contains implicitConfirm; overriding
    other parts of generalInfo, if any!

    :param pki_message: pyasn1 object representing a PKIMessage
    :returns: updated pyasn1 object"""
    # TODO consider refactoring so that implicitConfirm is added if the list already exists, rather than rewrite it.
    general_info = _prepare_implicit_confirm_general_info_structure()
    pki_message['header']['generalInfo'] = general_info
    return pki_message





if __name__ == '__main__':
    pass


# this is a Python implementation of the RobotFramework keyword `Try to Log PKIMessage as ASN1`. Viewing
# its output of this one requires fewer clicks in the reports.
def try_to_log_pkimessage(data):
    """Given the input data and assuming it is a DER-encoded PKIMessage, try to decode it and log the ASN1 structure
    in a human-readable way. Will also accept inputs that are pyasn1 objects or strings, for convenience of invocation
    from RF tests.

    :param data: bytes, str or pyasn1 - something that is assumed to be a PKIMessage structure, either DER-encoded or
                 a pyasn1 object.
    """
    if isinstance(data, base.Asn1Item):
        logging.info(data.prettyPrint())
        return

    if isinstance(data, str):
        data = bytes(data, 'utf-8')

    try:
        parsed = parse_pki_message(data)
    except:
        logging.info("Cannot prettyPrint this, it does not seem to be a valid PKIMessage")

    logging.info(parsed.prettyPrint())



def modify_csr_cn(csr: rfc9480.CertificationRequest, new_cn: Optional[str] = "Hans Mustermann") -> rfc9480.CertificationRequest:
    """Modifies the Common Name (CN) in a CSR. Expects a CN to be present in the certificate; otherwise, raises a ValueError.

    Args:
        csr: pyasn1 `rfc9480.CertificationRequest` object.
        new_cn: The new Common Name (CN) to be set. Defaults to "Hans Mustermann".

    Returns:
         returns the modified `rfc9480.CertificationRequest` object.

    Raises:
        ValueError: If no Common Name (CN) is found in the CSR.
    """

    # Access the subject field from the CSR, which contains the RDNSequence.
    subject = csr["certificationRequestInfo"]["subject"]

    # Flag to check if a CN was found and modified.
    found_cn = False

    # Iterate through the Relative Distinguished Names (RDN) sequence to find the CN.
    for rdn in subject["rdnSequence"]:  # rdnSequence is a Sequence OF RDN.
        # Each RDN can contain multiple AttributeTypeAndValue pairs.
        attribute: rfc2986.AttributeTypeAndValue
        for attribute in rdn:
            # Check if the current attribute is a Common Name (CN).
            if attribute["type"] == rfc2459.id_at_commonName:
                # Modify the CN by setting a new PrintableString value.
                found_cn = True
                attribute['value'] = char.PrintableString(new_cn)

    if not found_cn:
        raise ValueError("No Common Name (CN) found in the provided CSR.")


    return csr

def _generate_pki_status_info(bit_string: str | None = None, info_type: PKIStatus = PKIStatus.rejection) -> rfc9480.PKIStatusInfo:
    """
    Generates a `rfc9480.PKIStatusInfo` object with the specified status and failure information.

    :param bit_string: Optional bit string representing failure information. If `None`, an empty `BitString` is used.
                       Defaults to `None`.
    :param info_type: The type of PKI status to set, represented by a `PKIStatus` enumeration value. Defaults to `PKIStatus.rejection`.
    :return: A `rfc9480.PKIStatusInfo` object with the specified status and failure information.
    """
    # Access the pkiStatusInfo within the PKIMessage
    status_info = rfc9480.PKIStatusInfo()

    # Set the status (e.g., rejection which might be represented by 2 in your schema)
    status_info.setComponentByName('status', info_type.value)

    if bit_string is None:
        fail_info = rfc9480.PKIFailureInfo()
    else:
        # Set the failInfo (BitString)
        fail_info = rfc9480.PKIFailureInfo(f"'{bit_string}'B")  # Example BitString value

    status_info.setComponentByName('failInfo', fail_info)

    return status_info




def _generate_pki_message_fail_info(failInfo: Union[str, None] = None) -> rfc9480.PKIMessage:
    """
    Generates a `rfc9480.PKIMessage` object with a failure information status.

    :param failInfo: Optional failure information to include in the message, represented as a bit string.
                     Defaults to `None`.
    :return: A `rfc9480.PKIMessage` object with the provided failure information.
    """
    pki_msg = rfc9480.PKIMessage()
    value = _generate_pki_status_info(bit_string=failInfo, info_type=PKIStatus.rejection)
    pki_msg["body"]["error"].setComponentByName('pKIStatusInfo', value)
    return pki_msg

