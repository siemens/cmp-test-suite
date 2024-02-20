from datetime import datetime
import sys
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, useful, constraint
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed, tagFormatSimple
from pyasn1_alt_modules import rfc4210, rfc9480, rfc6402, rfc5280, pem
from pyasn1_alt_modules.rfc2314 import CertificationRequest, SignatureAlgorithmIdentifier, Signature, Attributes
from pyasn1_alt_modules.rfc2459 import GeneralName, Extension, Extensions, Attribute, AttributeValue
from pyasn1_alt_modules.rfc2511 import CertTemplate
from cryptoutils import compute_hmac, compute_pbmac1

# When dealing with post-quantum crypto algorithms, we encounter big numbers, which wouldn't be pretty-printed
# otherwise. This is just for cosmetic convenience.
sys.set_int_max_str_digits(0)


# from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))

# PKIMessage ::= SEQUENCE {
#     body             PKIBody,
#     protection   [0] PKIProtection OPTIONAL,
# extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
#                      OPTIONAL
# }
#
# PKIHeader ::= SEQUENCE {
#     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
#     sender              GeneralName,
#     recipient           GeneralName,
#     messageTime     [0] GeneralizedTime         OPTIONAL,
#     protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
#     senderKID       [2] KeyIdentifier           OPTIONAL,
#     recipKID        [3] KeyIdentifier           OPTIONAL,
#     transactionID   [4] OCTET STRING            OPTIONAL,
#     senderNonce     [5] OCTET STRING            OPTIONAL,
#     recipNonce      [6] OCTET STRING            OPTIONAL,
#     freeText        [7] PKIFreeText             OPTIONAL,
#     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
#                         InfoTypeAndValue     OPTIONAL
# }


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


def build_p10cr_from_csr(csr, sender='tests@example.com', recipient='testr@example.com', protection='pbmac1',
                         omit_fields=None):
    """Creates a pyasn1 pkiMessage from a pyasn1 PKCS10 CSR,

    :param csr: pyasn1 rfc6402.CertificationRequest
    :param omit_fields: optional str, comma-separated list of field names not to include in the resulting PKIMEssage

    :returns: pyasn1 PKIMessage structure"""
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
        transaction_id = univ.OctetString('0123456789abcdef').subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 4)
        )
        pki_header['transactionID'] = transaction_id

    if 'senderNonce' not in omit_fields:
        sender_nonce = univ.OctetString('1111111122222222').subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 5)
        )
        pki_header['senderNonce'] = sender_nonce

    if 'recipNonce' not in omit_fields:
        # works well, but I'm not sure we need it for now
        recipient_nonce = univ.OctetString('0000000000111111').subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 6)
        )
        pki_header['recipNonce'] = recipient_nonce


    # SHOULD NOT be required
    # TODO later - set to some bad time and see what happens
    if 'messageTime' not in omit_fields:
        now = datetime.now()
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

    if protection not in omit_fields and protection == 'pbmac1':
        prot_alg_id = rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
        )

        prot_alg_id['algorithm'] = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 5, 14))  # PBMAC1
        # prot_alg_id['parameters'] = encoder.encode(univ.Null())  # if no params are used

        parameters = rfc9480.PBMParameter()
        parameters['salt'] = univ.OctetString(b'1234567890abcdef').subtype(
            # TODO ask Russ why this is necessary and could not have been inferred?
            subtypeSpec=constraint.ValueSizeConstraint(0, 128)
        )

        owf_alg_id = rfc5280.AlgorithmIdentifier()  # .subtype(
            # explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
        # )
        owf_alg_id['algorithm'] = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))  # SHA512
        # owf_alg_id['parameters'] = encoder.encode(univ.Null())  # if no params are used
        parameters['owf'] = owf_alg_id

        parameters['iterationCount'] = 262144

        mac_alg_id = rfc5280.AlgorithmIdentifier()  # .subtype(
            # explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
        # )
        mac_alg_id['algorithm'] = univ.ObjectIdentifier((1, 2, 840, 113549, 2, 11))  # HMACWithSHA512
        # mac_alg_id['parameters'] = encoder.encode(univ.Null())  # if no params are used

        parameters['mac'] = mac_alg_id
        prot_alg_id['parameters'] = parameters

        pki_header['protectionAlg'] = prot_alg_id


    # PKIBody
    pki_body = rfc9480.PKIBody()
    pki_body['p10cr']['certificationRequestInfo'] = csr['certificationRequestInfo']
    pki_body['p10cr']['signatureAlgorithm'] = csr['signatureAlgorithm']
    pki_body['p10cr']['signature'] = csr['signature']


    # PKIMessage
    pki_message = rfc9480.PKIMessage()
    pki_message['body'] = pki_body
    pki_message['header'] = pki_header
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
    :returns: pyasn1 PKIMessage structure with the prorection included"""
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


def encode_to_der(asn1_structure):
    """Generic tool for DER-encoding a pyasn1 data structure"""
    return encoder.encode(asn1_structure)


def csr_attach_signature(csr, signature):
    """Takes a pyasn1 CSR object and attaches the signature to it, returning a
    signed pyasn1 CSR object. The signature is a buffer of raw data (not base64, etc.)"""
    sig_alg_id = SignatureAlgorithmIdentifier()
    algorithm = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 5))  # RSA_SIGN
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


def parse_pki_message(raw):
    """Takes a raw, DER-encoded PKIMessage structure and returns a
    pyasn1 parsed object"""
    try:
        pki_message, _remainder = decoder.decode(raw, asn1Spec=rfc9480.PKIMessage())
    except PyAsn1Error as err:
        # Here we suppress the details of the error returned by pyasn1, because they are usually extremely verbose
        # and barely helpful to a non-pyasn1 expert. If you have to debug a payload, get the server's response from
        # RobotFramework's log and feed it into this function manually.
        raise ValueError("Failed to parse PKIMessage: %s ...", str(err)[:100])
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
    """
    message_type = get_cmp_response_type(pki_message)
    # TODO throw an error if this is not a type of message that contains certificates

    response = pki_message['body'][message_type]['response'][cert_number]
    # status = response['status']['status']

    cert = response['certifiedKeyPair']['certOrEncCert']['certificate']
    serial_number = str(cert['tbsCertificate']['serialNumber'])
    return serial_number, cert


def parse_csr(raw_csr):
    """Builds a pyasn1-structured CSR out of a raw, base-64 request."""
    csr, _ = decoder.decode(raw_csr, asn1Spec=rfc6402.CertificationRequest())
    return csr


def patch_message_time(pki_message, new_time=None):
    """Patches the messageTime field of a PKIMessage structure with a new time,
    or the current time if none is provided

    :param pki_message: pyasn1 PKIMessage structure, but raw DER-encoded blobs are also accepted, will be converted
                        automatically, this is to make it easier to use this function in RobotFramework
    :param new_time: optional datetime, time to use for the messageTime field, will use the current time by default
    """
    if type(pki_message) is bytes:
        pki_message = parse_pki_message(pki_message)

    new_time = new_time or datetime.now()
    message_time = useful.GeneralizedTime().fromDateTime(new_time)
    message_time_subtyped = message_time.subtype(
        explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
    )
    pki_message['header']['messageTime'] = message_time_subtyped
    return pki_message



if __name__ == '__main__':
    from utils import decode_pem_string

    raw = """	-----BEGIN CERTIFICATE REQUEST-----
MIIC1TCCAb0CAQAwXDELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExDzAN
BgNVBAcMBk11bmljaDEQMA4GA1UECgwHQ01QIExhYjEYMBYGA1UEAwwPSGFucyBN
dXN0ZXJtYW5uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtaRNCb2X
OnYeG6zcKS03x5wpJz2vputiGuGtyynCBEt7emJcUe8EwY8e1poMZm8ZfjvjJ/0B
rtR4ozJkxWd2yyR4k8pbfDe2XuoSGLP0Dr4kts7TKpxjp9wLVj/TaAWnlZYCAaS9
KJ/ZjkJrijeaQRIqImkMjD9bO69R9t8anv829vXV9Ux1y4qHMjPkhmo7LoXn6fOY
WwHjz/pxY+g+OiuLa4ZCuqGgm5PAwQa+EfkbqBrH0KKz2IyyoeMwpr9vNT72dyej
qEHKBS0zSwRdXm2Z/VWgOKc755vjjEHjuVenqcvHI0LwpUg9H7r5LW2u5MZF20z2
8wungl5qSaSdDwIDAQABoDQwMgYJKoZIhvcNAQkOMSUwIzAhBgNVHREEGjAYggho
YW5zLmNvbYIMd3d3LmhhbnMuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBWHmVCkIPw
Ye/Hr9Hsh3T9fJmma8BQiaG46Obsx40MruzlTdwb+KvDEELgVPOLU6nbiKJMSS93
jBlK/mSOkHMIbKj9y/hwIxIGTv15ol/CTYyNUMB7tW0x6KQW1qAYFsI0YXUP+kV6
jozNZe7ji7OJyoAaMYQiZCJUE9kbf6FxRU0pIL8Lu6TYt/UQ/ukK9dnr4rIRKvdt
g8vxmqAWlyg5MTTQ0DfmLAwCUYaVfTgsl8TEVUiCwgdB++Hw+W96g8OFLWNr7+nc
830ekfQElpSt9Vb9PkaeNF4hX7EsISLAITfY1+i6knpLlbbXqNA0abrxtVMWo5db
LJPchrUaU95b
-----END CERTIFICATE REQUEST-----"""
    csr = decode_pem_string(raw)
    csr, _ = decoder.decode(csr, asn1Spec=CertificationRequest())
    # csr = parse_csr(csr)
    print(csr.prettyPrint())

    # result = encode_to_der(csr)
    # print(result)

    # ctag4 = Tag(tagClassContext, tagFormatConstructed, 4)
    # tagged_csr = csr.subtype(explicitTag=ctag4, cloneValueFlag=True)
    # print(tagged_csr)

    p10cr = build_p10cr_from_csr(csr)
    print(p10cr.prettyPrint())
    protected_pki_message = protect_pkimessage_hmac(p10cr, b"test")
    print(protected_pki_message.prettyPrint())

    # from base64 import b64encode
    # print(b64encode(encode_to_der(protected_pki_message)))

