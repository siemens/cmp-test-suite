import base64
from io import BytesIO
from pyasn1 import debug
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed
from pyasn1_alt_modules import rfc4210, pem
from pyasn1_alt_modules.rfc2314 import CertificationRequest, SignatureAlgorithmIdentifier, Signature, Attributes
from pyasn1_alt_modules.rfc2459 import GeneralName, Extension, Extensions, Attribute, AttributeValue
from pyasn1_alt_modules.rfc2511 import CertTemplate


debug.setLogger(debug.Debug('all'))

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


def build_cmp_p10cr_request_from_csr(csr, sender='test-cmp-cli@example.com', recipient='test-cmp-srv@example.com'):
    """Creates a pyasn1 pkiMessage from a pyasn1 PKCS10 CSR

    :returns: pyasn1 PKIMessage structure"""
    import sys, pdb; pdb.Pdb(stdout=sys.__stdout__).set_trace()
    # PKIHeader
    pvno = univ.Integer(2)
    sender = GeneralName().setComponentByName('rfc822Name', sender)
    recipient = GeneralName().setComponentByName('rfc822Name', recipient)

    pki_header = rfc4210.PKIHeader()
    pki_header['pvno'] = pvno
    pki_header['sender'] = sender
    pki_header['recipient'] = recipient

    # PKIBody
    pki_body = rfc4210.PKIBody()

    # explained http://sourceforge.net/mailarchive/message.php?msg_id=31787332
    ctag4 = Tag(tagClassContext, tagFormatConstructed, 4)
    pkcs10_tagged = csr.subtype(explicitTag=ctag4, cloneValueFlag=True)
    pki_body['p10cr'] = pkcs10_tagged
    # pki_body['p10cr'] = csr

    # PKIMessage
    pki_message = rfc4210.PKIMessage()
    pki_message['body'] = pki_body
    pki_message['header'] = pki_header
    return pki_message


def encode_to_der(asn1_structure):
    """Generic tool for DER-encoding a pyasn1 data structure"""
    return encoder.encode(asn1_structure)


def csr_attach_signature(csr, signature):
    """Takes a pyasn1 CSR object and attaches the signature to it, returning a
    signed pyasn1 CSR object. The signature is a buffer of raw data (not base64, etc)"""
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
    """Takes a raw, ASN1 encoded PKIMessage structure and returns a
    pyasn1 parsed object"""
    pki_message, _ = decoder.decode(raw, asn1Spec=rfc4210.PKIMessage())
    # header = pkiMessage['header']
    # body = pkiMessage['body']
    return pki_message  # , header, body


def get_cmp_status_from_pki_message(pki_message, response_index=0):
    """Takes pyasn1 PKIMessage object and returns its status as a string

    :param response_index: optional int, index of response to get from the sequence, 0 by default
    """
    response = pki_message['body']['rp']['response'][response_index]
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
    response = pki_message['body']['cp']['response'][cert_number]
    status = response['status']['status']

    assert PKISTATUS_ACCEPTED == status
    cert = response['certifiedKeyPair']['certOrEncCert']['certificate']
    serial_number = str(cert['tbsCertificate']['serialNumber'])
    return serial_number, cert


def strip_header(raw):
    """Get rid of -----BEGIN CERTIFICATE REQUEST-----', '-----END CERTIFICATE REQUEST----- markers
    :param raw: bytes, input structure"""
    result = raw.decode('ascii')
    result = result.replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").replace("\n", "")
    return bytes(result, 'ascii')


def parse_csr(raw_csr, header_included=False):
    """Builds a pyasn1-structured CSR out of a raw, base-64 request. If header_included
    is true, it is assumed that the request is enclosed in markers, that will be removed
    -----BEGIN CERTIFICATE REQUEST-----', '-----END CERTIFICATE REQUEST-----"""
    # import sys, pdb; pdb.Pdb(stdout=sys.__stdout__).set_trace()

    if header_included:
        raw_csr = strip_header(raw_csr)

    raw_csr = base64.b64decode(raw_csr)
        # raw_csr = pem.readPemFromFile(BytesIO(raw_csr))


    csr, _ = decoder.decode(raw_csr, asn1Spec=CertificationRequest())
    return csr


if __name__ == '__main__':
    raw = b"""-----BEGIN CERTIFICATE REQUEST-----
MIICfTCCAWUCAQAwODELMAkGA1UEBhMCREUxDzANBgNVBAcMBk11bmljaDEYMBYG
A1UEAwwPSGFucyBNdXN0ZXJtYW5uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAn0Id1aUXllUOamUiaYFFvrsURBwaUzyTb8Z9UnFmlSYD9czTpQKt5bL9
VbwlSEm30J6h4Y1LMIU/y2idWWBkK7yI749Ql8q4zh4NQ4NcBd3IRzkgZxiQDdiI
iSvc3fkvWLDY3waOIk1hPW9Yb6SmH3S4F8DcLmXNccoa/fWjqHEKnEonQlMMfPWs
tKmAAFljejBU7h6nJUcPRNjEnjNydmx9D25oM/iu1XAIWugnYoSqyFCfD3oN5Pui
Mmr/F7WBj0e16ImINn54HzjtpHmtMR4r/5OYIHEwoaP7drQblSNKoc49kM1FlCa6
DZDGYEx4zFxPPcaDTfWnzoOlBlYwsQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEB
AJs8DtRWYt9cJ1dU6YAyDEG2iCKlfVb6Dk6Hl3cic63iGyvOPcZSpAwxkkSqG+tU
cTlX6Qu3ORAjCVGeUoXCxwsGysFXUqEHYoUo2GpZiZvdg8yzXd2LVBzSWh7kNu3z
3TEcdFwamA/cWAXjJNg1AMLdo8bMa+jjduIHqSyvUzPKq5SiRmdAT+rMsZAOC65E
PPecU9SVCMELD6rY46KnhDuL5ydD5GuN9K1KEP9CScELxu8T+vK+Wk5U9rUSz84K
U9AdPI4bJKAneUvtA00I0FvofvqGronaCgl1n3z8OunimESh6+3yNkcCaVjmW+Lm
a+6aleaT4eMGuJC7IVhpwrs=
-----END CERTIFICATE REQUEST-----"""


    result = parse_csr(raw, header_included=True)
    print(result)

    #data = build_cmp_revoke_request(12345)
    #debug.setLogger(debug.Debug('all'))

    #structure, _ = decoder.decode(data, asn1Spec=rfc4210.PKIMessage())
    #print(structure)

    #data = build_cmp_revoke_request(12345)
    #open('cmp-revoke.bin', 'wb').write(data)

    #data = build_cmp_revive_request(54321)
    #open('cmp-revive.bin', 'wb').write(data)

    #data = build_cmp_revoke_request(11111, reason=REASON_CERTIFICATE_HOLD)
    #open('cmp-hold.bin', 'wb').write(data)
