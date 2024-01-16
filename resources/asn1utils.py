from io import StringIO

from pyasn1.type import univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480, rfc2459, rfc2314, pem

from pyasn1_alt_modules.rfc2459 import GeneralName, Extension, Extensions, Attribute, AttributeValue, \
    RelativeDistinguishedName
from pyasn1_alt_modules.rfc2314 import CertificationRequest, SignatureAlgorithmIdentifier, Signature, Attributes
from pyasn1_alt_modules.rfc2511 import CertTemplate

'''
	 PKIMessage ::= SEQUENCE {
		 body             PKIBody,
		 protection   [0] PKIProtection OPTIONAL,
		 extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
						  OPTIONAL
	 }

	 PKIHeader ::= SEQUENCE {
		 pvno                INTEGER     { cmp1999(1), cmp2000(2) },
		 sender              GeneralName,
		 recipient           GeneralName,
		 messageTime     [0] GeneralizedTime         OPTIONAL,
		 protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
		 senderKID       [2] KeyIdentifier           OPTIONAL,
		 recipKID        [3] KeyIdentifier           OPTIONAL,
		 transactionID   [4] OCTET STRING            OPTIONAL,
		 senderNonce     [5] OCTET STRING            OPTIONAL,
		 recipNonce      [6] OCTET STRING            OPTIONAL,
		 freeText        [7] PKIFreeText             OPTIONAL,
		 generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
							 InfoTypeAndValue     OPTIONAL
	 }
'''

# revocation reasons
# http://www.alvestrand.no/objectid/2.5.29.21.html#
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

'''
AlgorithmIdentifier ::= SEQUENCE 
{
  algorithm           OBJECT IDENTIFIER,
  parameters          ANY OPTIONAL    
}'''


def CsrAttachSignature(csr, signature):
    '''Takes a pyasn1 CSR object and attaches the signature to it, returning a
    signed pyasn1 CSR object. The signature is a buffer of raw data (not base64, etc)'''
    sigAlgId = SignatureAlgorithmIdentifier()
    algorithm = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 5))  # RSA_SIGN
    parameters = encoder.encode(univ.Null())  # no params are used

    sigAlgId['algorithm'] = algorithm
    sigAlgId['parameters'] = parameters

    # take the raw signature and turn it into a BitString representations
    signature = Signature("'%s'H" % ''.join("%02X" % ord(c) for c in signature))

    csr['signature'] = signature
    csr['signatureAlgorithm'] = sigAlgId
    return csr


def CsrAddExtensions(csr, extensions):
    '''Takes a pyasn1 CSR and adds pyasn1-structured extensions, passed
    as a list'''
    # extensions are kept in a `SetOf Attributes` and are explicitly tagged 0
    extensionSet = univ.SetOf()
    attributes = Attributes().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))

    # the attribute type we need is a `x509 v3 extension` with the corresponding OID
    attribute = Attribute()
    attribute['type'] = univ.ObjectIdentifier('1.2.840.113549.1.9.14')

    # the extensions are wrapped in a sequence before they go into the set
    wrappingSequence = univ.Sequence()
    for index, extension in enumerate(extensions):
        wrappingSequence[index] = AttributeValue(encoder.encode(extension))

    extensionSet[0] = wrappingSequence
    attribute['vals'] = extensionSet
    attributes[0] = attribute

    csr['certificationRequestInfo']['attributes'] = attributes
    return csr


def CsrExtendSubject(csr, rdn):
    '''Extends the SubjectName in a pyasn1-structured CSR with a
    pyasn1 RelativeDistinguishedName structure'''
    originalSubject = csr['certificationRequestInfo']['subject'][0]
    currentLength = len(originalSubject)
    originalSubject[currentLength] = rdn
    return csr


def EncodeToAsn1(pyasn1Obj):
    return encoder.encode(pyasn1Obj)


def ParsePkiMessage(raw):
    '''Takes a raw, ASN1 encoded PKIMessage structure and returns a
    pyasn1 parsed object'''
    pkiMessage, _ = decoder.decode(raw, asn1Spec=rfc9480.PKIMessage())
    # header = pkiMessage['header']
    # body = pkiMessage['body']
    return pkiMessage  # , header, body


def GetCmpStatusFromPkiMessage(pkiMessage):
    '''Takes pyasn1 PKIMessage object and returns its status
    NOT TESTED'''
    response = pkiMessage['body']['rp']['response'][0]  # only get first response from sequence
    status = response['status']['status']
    return str(status)


def CertAsn1ToPem(cert):
    '''Transform a parsed ASN1 certificate object into a binary certificate
    for use in other sub-systems'''
    encoded = encoder.encode(cert)

    # this is somewhat ugly, as my current encoder encapsulates it inside
    # another ASN1 structure, for now I just have to remove that wrapper
    # manually, it is in the first 4 bytes of the data TODO
    return encoded[4:]


def GetResponseType(pkiMessage):
    '''Returns the body type of a pyasn1 object representing a PKIMessage'''
    return pkiMessage['body'].getName()


def GetCertFromPkiMessage(pkiMessage):
    '''Takes a pyasn1-object representing a response to a CSR request,
    containing the PKIMessage structure with the issued certificate in it,
    and returns the actual certificate'''

    response = pkiMessage['body']['cp']['response'][0]  # only get first response from sequence
    status = response['status']['status']

    assert PKISTATUS_ACCEPTED == status
    cert = response['certifiedKeyPair']['certOrEncCert']['certificate']
    serialNumber = str(cert['tbsCertificate']['serialNumber'])
    return serialNumber, cert


def ParseCsr(rawCsr, headerIncluded=False):
    '''Builds a pyasn1-structured CSR out of a raw, base-64 request. If headerIncluded
    is true, it is assumed that the request is enclosed in markers, that will be removed
    -----BEGIN CERTIFICATE REQUEST-----', '-----END CERTIFICATE REQUEST-----'''
    if headerIncluded:
        rawCsr = pem.readPemFromFile(StringIO(rawCsr), '-----BEGIN CERTIFICATE REQUEST-----',
                                     '-----END CERTIFICATE REQUEST-----')

    csr, _ = decoder.decode(rawCsr, asn1Spec=CertificationRequest())
    return csr


def BuildCmpFromPkcs10(rawpkcs10):
    '''Creates an ASN1-encoded pkiMessage from a PKCS10'''
    parsedPkcs10 = ParseCsr(rawpkcs10, headerIncluded=True)

    # PKIHeader
    pvno = univ.Integer(2)  # cmp2000
    sender = GeneralName().setComponentByName('rfc822Name', 'test-cmp-cli@dekart.com')
    recipient = GeneralName().setComponentByName('rfc822Name', 'test-cmp-srv@dekart.com')

    pkiHeader = rfc9480.PKIHeader()
    pkiHeader['pvno'] = pvno
    pkiHeader['sender'] = sender
    pkiHeader['recipient'] = recipient

    # PKIBody
    pkiBody = rfc9480.PKIBody()

    # explained http://sourceforge.net/mailarchive/message.php?msg_id=31787332
    ctag4 = Tag(tagClassContext, tagFormatConstructed, 4)
    pkcs10tagged = parsedPkcs10.subtype(explicitTag=ctag4, cloneValueFlag=True)
    pkiBody['p10cr'] = pkcs10tagged

    # PKIMessage
    pkiMessage = rfc9480.PKIMessage()
    pkiMessage['body'] = pkiBody
    pkiMessage['header'] = pkiHeader

    cmpRequest = encoder.encode(pkiMessage)
    return cmpRequest


def ParseCmpResponse(raw):
    pkiMessage, _ = decoder.decode(raw, asn1Spec=rfc9480.PKIMessage())  # CertRepMessage())
    pkiMessageType = pkiMessage['body'].getName()
    certRepMessage = pkiMessage['body'][3]
    certResponse = pkiMessage['body'][3][1][0]
    certReqId = certResponse[0]
    pkiStatus = certResponse[1]
    certifiedKeyPair = certResponse[2]
    certOrEncCert = certResponse[2][0]
    tbsCertificate = certResponse[2][0][0][0]
    return pkiMessage


def BuildCmpReviveRequest(serialNumber, sender='test-cmp-cli@dekart.com', recipient='test-cmp-srv@dekart.com'):
    '''A convenient wrapper of BuildCmpRevokeRequest'''
    return BuildCmpRevokeRequest(serialNumber, sender='test-cmp-cli@dekart.com',
                                 recipient='test-cmp-srv@dekart.com',
                                 reason=REASON_REMOVE_FROM_CRL)


def BuildCmpRevokeRequest(serialNumber, sender='test-cmp-cli@dekart.com',
                          recipient='test-cmp-srv@dekart.com',
                          reason=REASON_UNSPECIFIED):
    '''Creates a certificate revocation request, based on the given
    serial#. It also holds and revives a certificate:
    reasons
        REASON_CERTIFICATE_HOLD - hold
        REASON_REMOVE_FROM_CRL - revive.
    `serialNumber` can also be a list of numbers, if so - all of them
    will be revoked in a single request, with the same reason'''

    # the function uses lists internally, to accomodate the possibility of
    # revoking multiple certificates at once. For backwards compatibility,
    # we check if the input is a single number, and "listify" it if necessary
    if not type(serialNumber) == list:
        serialNumber = [serialNumber]

    # PKIHeader
    pvno = univ.Integer(2)  # cmp2000
    sender = GeneralName().setComponentByName('rfc822Name', sender)
    recipient = GeneralName().setComponentByName('rfc822Name', recipient)

    pkiHeader = rfc9480.PKIHeader()
    pkiHeader['pvno'] = pvno
    pkiHeader['sender'] = sender
    pkiHeader['recipient'] = recipient

    # PKIBody
    pkiBody = rfc9480.PKIBody()

    # for `rr` revocation requests we need to build a structure of the form
    # RevReqContent/RevDetails/CertTemplate
    revReqContent = rfc9480.RevReqContent()

    for index, entry in enumerate(serialNumber):
        # here we build a RevDetails structure for each given serial number
        # and append it to revReqContent
        revDetails = rfc9480.RevDetails()
        certTemplate = CertTemplate()
        certTemplate['serialNumber'] = entry
        revDetails['certDetails'] = certTemplate

        # create an extension that explicitly specifies the reason for revoking the cert.
        # this is also how you specify whether you set it on HOLD or RESUME a held cert.
        crlEntryDetails = Extensions()
        crlReason = Extension()
        crlReason['extnID'] = univ.ObjectIdentifier((2, 5, 29, 21))  # 2.5.29.21 CRL reason
        crlReason['critical'] = univ.Boolean(True)

        # the extension value doesn't go in there as an integer, but as an ENUMERATED inside
        # an OCTET STRING, hence the 2 lines below do exactly that
        extnValue = encoder.encode(univ.Enumerated(reason))
        extnValue = encoder.encode(univ.OctetString(extnValue))
        crlReason['extnValue'] = extnValue

        crlEntryDetails.setComponentByPosition(0, crlReason)
        revDetails['crlEntryDetails'] = crlEntryDetails
        revReqContent.setComponentByPosition(index, revDetails)

    # this `magic` is required because `[11] RevReqContent` has the explicit 11 tag
    # thus we create an ad-hoc subtype, just like we did in BuildCmpFromPkcs10
    # explained http://sourceforge.net/mailarchive/message.php?msg_id=31787332
    ctag11 = Tag(tagClassContext, tagFormatConstructed, 11)
    revReqContentTagged = revReqContent.subtype(explicitTag=ctag11, cloneValueFlag=True)
    pkiBody['rr'] = revReqContentTagged

    pkiMessage = rfc9480.PKIMessage()
    pkiMessage['body'] = pkiBody
    pkiMessage['header'] = pkiHeader

    cmpRequest = encoder.encode(pkiMessage)
    return cmpRequest


def pkimessage_must_contain_fields(data, fields):
    """Ensure that all fields listed in `fields` are present in the header of `data`

    :param data: pyasn1 PKIMessage object
    :param fields: list of str, names of fields that must be present in the header"""
    present_fields = list(data['header'])
    absent_fields = []
    for entry in fields:
        if entry not in present_fields:
            absent_fields.append(entry)

    if len(absent_fields) > 0:
        raise ValueError(f"The following required fields were absent: {absent_fields}")



def get_field_value_from_pkimessage_as_bytes(data, field_name):
    """Extract the value of a field from a PKIMessage structure

    :param data: pyasn1 object representing a PKIMessage
    :param field_name: str, name of the field you want to extract, e.g., "protection"
    :return: bytes, raw value of that field"""
    return data[field_name].asOctets()


def get_field_value_from_pkimessage_as_bytes_via_path(data, path):
    """Extract the value of a field from a PKIMessage structure

    :param data: pyasn1 object representing a PKIMessage
    :param path: str, name of the field you want to extract, given as a dot-notation, e.g.,
                       "header.senderNonce" or "protection"
    :return: bytes, raw value of that field"""
    keys = path.strip().split('.')
    for key in keys:
        data = data[key]
    return data.asOctets()


def get_pyasn1_field_via_path(data, path):
    """Extract as PyASN1 object from a complex PyASN1 structure by specifying its path

    :param data: pyasn1 object
    :param path: str, path to the field you want to extract, given as a dot-notation, e.g.,
                       "header.senderNonce", "protection", "header.sender.directoryName", etc.
    :return: pyasn1 object, the value you were looking for"""
    keys = path.strip().split('.')
    for key in keys:
        data = data[key]
    return data


# This function provides a way to query an ASN1 object by passing a string that represents a path to the piece you are
# interested in, think of it asn ASN1Path, by analogy with XPath for XML or JSONPath for JSON. It is meant to be
# invoked from RobotFramework test cases, hence the notation is a compact, single string.
#
# To understand the notation, imagine you have this structure:
# PKIMessage:
#  header=PKIHeader:
#   pvno=cmp2000
#   sender=GeneralName:
#    directoryName=Name:
#     rdnSequence=RDNSequence:
#      RelativeDistinguishedName:
#       AttributeTypeAndValue:
#        type=2.5.4.10
#        value=0x13074e65746f506179
#      RelativeDistinguishedName:
#       AttributeTypeAndValue:
#        type=2.5.4.3
#        value=0x130755736572204341
#
# The query 'header.sender.directoryName.rdnSequence/0' will return the first (i.e. index 0) element inside rdnSequence
#      RelativeDistinguishedName:
#       AttributeTypeAndValue:
#        type=2.5.4.10
#        value=0x13074e65746f506179
#
# The query 'header.sender.directoryName.rdnSequence/0/0.value' will return the first element of rdnSequence, then dive
# in and extract the first element of that (which will be of type AttributeTypeAndValue), then it will return the
# attribute called `value`
# value=0x13074e65746f506179
#
# A few points to make it easier to navigate through PyASN1's own stringified notation.
# - if there's a `=` in the line (e.g., `header=PKIHeader`), then its children are accessed via the dot, e.g.:
#   `header.pvno` or `header.sender`.
# - if there's no equal sign, it is a sequence or a set, and elements are accessed by index (even if pyasn1 shows them
#   as a string!). For instance, in the following piece you don't write the query as
#   `RelativeDistinguishedName.AttributeTypeAndValue.type`, but as `/0/0.type`, which reads as "get inside the first
#   element of the first element, then retrieve the attribute called 'type'.
#     rdnSequence=RDNSequence:
#      RelativeDistinguishedName:
#       AttributeTypeAndValue:
#        type=2.5.4.10

def get_nested_value(asn1_obj, query):
    # first_rdn = get_nested_value(parsed_data, 'header.sender.directoryName.rdnSequence/0')
    # get_nested_value(result, 'header.sender.directoryName.rdnSequence/0/0.value')
    keys = query.split('.')
    for key in keys:
        if '/' in key:
            parts = key.split('/')
            for part in parts:
                if part.isdigit():
                    asn1_obj = asn1_obj[int(part)]
                else:
                    asn1_obj = asn1_obj[part]
        else:
            asn1_obj = asn1_obj[key]
    return asn1_obj


if __name__ == '__main__':
    from base64 import b64decode

    if True:
        # parse a pkimessage
        raw = b64decode('''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
Aa/Ap/XrL6CDeGT5HFvxbg==''')
        # import pdb

        # pdb.set_trace()
        result = ParsePkiMessage(raw)
        result.prettyPrint()

        # access the 0th element of a complex structure
        rdn_first = get_nested_value(result, 'header.sender.directoryName.rdnSequence/0')
        print(rdn_first)

        # access the key named `value` of the 0th element of `rdn`
        piece = get_nested_value(rdn_first[0], 'value')
        # piece = get_nested_value(rdn, '/0.value')
        print(piece)

        # access the key named `value` of the 0th element of `rdn`, but do so in a single query that starts from the
        # parent object. Here the syntax
        rdn_inner_value = get_nested_value(result, 'header.sender.directoryName.rdnSequence/0/0.value')
        print(rdn_inner_value)


    if False:  # test response to a revocation request
        # suspend raw = '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'.decode('base64')
        raw = 'MIIIJDBVAgECpCgwJjEQMA4GA1UEChMHTmV0b1BheTESMBAGA1UEAxMJZU1hcmsxIENBgRd0ZXN0LWNtcC1jbGlAZGVrYXJ0LmNvbaENMAsGCSqGSIb3DQEBBawJMAcwBTADAgEAoIICBQOCAgEAC+fG7MFaqeU4/L/gyaNQ41l8IC5aHsicE4HxNq5JHsMTCO/e2QjOviVRNwN1tdU3T+PTwgjUIDyihngfoKPhJRDaOy/L/Np+HKtRgftCGMA56fJi6AZhsauz7/IXa3OL0Xezhqz8UvV+WZylbAo9kL1aIt+xTOHh1uNb9fspgF4xQwpo5szIaMyc9/hTpXRSI/bEsWHUdNVZt68JwOin6d2tqISQGxb5Rv8OttJB+4bRq3YSwTnn/Kceznh2zD/6JYUo9HVwvW5phKj0jv7s1TNvH+WYtH3cDUwWkm1v1/vZOxWUGIWG7u07jk/ukDFll6xn8Tx78Xt50uFFEFKhBXFHWFdaSP9aFvei/btgQ7nOGvkdB+SAIl+JljmLFz+GaQFfNuT9jB4lEkVmfhCb8MFdJc4DIKLC4n/5j8h/Xv6U/+qggfX92BNJzODRY1BQEM4tNE4ADwXB6NHuUbOnmHkZ8QYJFZd3act4gbYPUii4jxYX9dx4Rzd2OSx2HVNz3Nh6TXiITqEFMBvq1SdnPZ47xL1taazrrGMdYxrZXl0T7T4MQ+Mxhbg+/YPsVssn7Km5b3mcangPjM9Ja17zH2uAJyTVx/m6i8+fpSENXX2tpnbmVhPExWl9MGBiEp9YlNKhsSALEdJ5UsgpQfEGYPikRxpQhQCs+wNT4SaS0NOhggW1MIIFsTCCBa0wggOVoAMCAQICCgi8Ac9BTqSxWW0wDQYJKoZIhvcNAQEFBQAwJjEQMA4GA1UEChMHTmV0b1BheTESMBAGA1UEAxMJZU1vbmV5IENBMB4XDTE0MDMxNjE5MzM0NFoXDTI0MDMxNjE5MzM0NFowJjEQMA4GA1UEChMHTmV0b1BheTESMBAGA1UEAxMJZU1hcmsxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqGihs2m+D6DN8LjOvqX25mMcV6ongrBQ9SHDDZfmGre1oqP+bSo5NKzGKyDJqTjelt/YHyu3Ja+qT38IcCFN5NbC045yxTz0bEtqpXFdYymBrRBBrXk4YPjul5BDL1BngqXy+Wv7nGqjAb5utdZgxDIwT0C0RQl5bDM4/qeMFeahMA265lYxErbDd8Bez+OA5CEHrl9V2wcHf3bh3d8+QiD038OYNkzuY9EDL1qGxpVBoKhEf3t6JFhyIaqJjoMBO7Z/GT5YU/1YbjvQzuLYm2uqNz62v0NvY4P+ujJWHuyo635x0afnHbciLsInITRJ6nK83GFS4ihpSfZsW9CaFUUhutcg8uRJD5W46rZLsF79EQjL1rf1o4cKmMGRh8gWBvq7/eCpmumZ2mLqwy2wFRTPqRwrcjGKiPcghYiBjxAlAC3UNmziRa1z90I8YASkJDxJO+NXdtctARpxMJfvU1xruXf90aZX3YATWwT3CofEwxRc8Hi94yRmU08NYw4AyLfELVipOglqwrE1n4cy1Yj0j3PmXAG0M8/FjjMVDfMVT6ncgRkgVItYGu5gqIa2nAwE93vAgHsRu4TSE3bfK6/6qVsRPBd9/RuusxkW1DjA47XiUH1M6yral4Hx+uUNu/RonBvZCI+bMW1XCihvrdSy5PXAXm8vqvmmz1RnWIcCAwEAAaOB3DCB2TA4BgNVHRIEMTAvhi1odHRwOi8vaW5zaWRlLmRla2FydC5jb20vbmV0b3BheS9lbW9uZXljYS5jZXIwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2luc2lkZS5kZWthcnQuY29tL25ldG9wYXkvZW1vbmV5Y2EuY2VyMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTc/+iImG8HF9JdNP2IIBXYTgFqsjAdBgorBgEEAcZ1AQEBAQH/BAwwCgICA9IeBEV1cm8wDQYJKoZIhvcNAQEFBQADggIBAEpUe7c2uRVjcqcrD7+eakVo7bP0ax8MXuFG/+BHVm+A29B+duHun76Je1H8HJsYpOiMUy4oRteUeDdSCaekvYT+WQm7KQJ0+qwDY4ptW90FD0Q9BZ2LU/rFVzDGUtixtBaNeMwtVaSaRmn2Gc1kdriKEQGTyGwkkHRzE6LMQFUSrbJx42crf/bX/e+QJ7r8Kfk0G/ALHKradJ144a9IihaYVVeQxLrBDNT7vNAWx55waDgc8lVoeP0Wc0iA+q1vLA2yNnHpLJtlHtcAb8cZ0G1/ex/Id8ih1vOqQxMqxPn7VDNODjbRZWoAGJ+vGXx5OlHk6sA+ia8rjKjhoR4lnkA9T32KlXcZD5Bx/Y4RPF8nMPRo+42/QFEj7kbNTkFHADPqmrOSd3es+v28kbM/DjVEcj2HAWE+sVa6pUTCWROZx+4N96VxGdL93JRUMZ3qwNnXZZ4GakR/1nSqQEVZy4qjiylkN+WpY3c9nBIXocKAE9o32vBq3PN1iyjCRsG1f3VS95L2LJOH7J9P8rDuTp3EWEI7HFF8QGSM4uXULf9KQhfxMHiriQL+xLCRo27YiKzStJpF2lTSnhq1Qx83ykcs+H5l+xfIzQig1vwztslFzs4U4FlfTsXLBIANvenb1lwhZePG2RCoDWTiVSOXErdgM8qet6jJCfiXswlNhQUw'.decode(
            'base64')
        result = GetCmpStatusFromPkiMessage(raw)

    '''
    data = BuildCmpRevokeRequest(12345)
    from pyasn1 import debug
    #debug.setLogger(debug.Debug('all'))
    structure, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    print structure.prettyPrint()
    '''

    if False:  # pkcs10 request test
        rawpkcs10 = '''-----BEGIN CERTIFICATE REQUEST-----
	MIIBnTCCAQYCAQAwXTELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIw
	EAYDVQQDEwlsb2NhbGhvc3QxJzAlBgkqhkiG9w0BCQEWGGFkbWluQHNlcnZlci5l
	eGFtcGxlLmRvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr1nYY1Qrll1r
	uB/FqlCRrr5nvupdIN+3wF7q915tvEQoc74bnu6b8IbbGRMhzdzmvQ4SzFfVEAuM
	MuTHeybPq5th7YDrTNizKKxOBnqE2KYuX9X22A1Kh49soJJFg6kPb9MUgiZBiMlv
	tb7K3CHfgw5WagWnLl8Lb+ccvKZZl+8CAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4GB
	AHpoRp5YS55CZpy+wdigQEwjL/wSluvo+WjtpvP0YoBMJu4VMKeZi405R7o8oEwi
	PdlrrliKNknFmHKIaCKTLRcU59ScA6ADEIWUzqmUzP5Cs6jrSRo3NKfg1bd09D1K
	9rsQkRc9Urv9mRBIsredGnYECNeRaK5R1yzpOowninXC
	-----END CERTIFICATE REQUEST-----'''

        csr = ParseCsr(rawpkcs10, headerIncluded=True)
        # print csr.prettyPrint()

        if True:  # test how it extends the subject with our own stuff, depends
            # on the csr
            rawRdn = 'MSwwKgYKKwYBBAHGdQEBAgQcMBoGCisGAQQBxnUBAQIBAf8ECTAHAgIAyAIBZA=='.decode('base64')
            rdn, _ = decoder.decode(rawRdn, asn1Spec=RelativeDistinguishedName())

            alteredCsr = CsrExtendSubject(csr, rdn)
            # print extendedCsr.prettyPrint()
            print
            '-----BEGIN CERTIFICATE REQUEST-----'
            print
            encoder.encode(alteredCsr).encode('base64'),
            print
            '-----END CERTIFICATE REQUEST-----'

        if False:  # test netopay extensions, depends on csr, make sure the test
            # above it is also enabled

            """extnID=1.3.6.1.4.1.9077.1.1.2
            critical='True'
            extnValue=0x04093007020200c8020164"""
            rawExtension1 = 'MBoGCisGAQQBxnUBAQIBAf8ECTAHAgIAyAIBZA=='.decode('base64')
            extension1, _ = decoder.decode(rawExtension1, asn1Spec=Extension())

            """extnID=1.3.6.1.4.1.9077.1.1.1
            critical='True'
            extnValue=0x040c300a020203d21e044575726f"""
            rawExtension2 = 'MB0GCisGAQQBxnUBAQEBAf8EDDAKAgID0h4ERXVybw=='.decode('base64')
            extension2, _ = decoder.decode(rawExtension2, asn1Spec=Extension())

            extensions = [extension1, extension2]

            rawStandardExtension = 'MBwGA1UdEQEB/wQSMBCCDnByaXZldC5qb3kuY29t'.decode('base64')
            standardExtension, _ = decoder.decode(rawStandardExtension, asn1Spec=Extension())

            extensions = [extension1, extension2, standardExtension]

            extendedCsr = CsrAddExtensions(csr, extensions)
            # print extendedCsr.prettyPrint()
            print
            '-----BEGIN CERTIFICATE REQUEST-----'
            print
            encoder.encode(extendedCsr).encode('base64'),
            print
            '-----END CERTIFICATE REQUEST-----'

    if False:  # pkcs10 request with extensions, without wrapping
        rawpkcs10 = '''MIIDNTCCAp4CAQAwgawxGTAXBgkqhkiG9w0BCQEWCnBraUBjdHMubWQxGzAZBgNVBAMMElLEg2ls
ZWFuIEFuYSBNYXJpYTEiMCAGA1UECwwZVGVobm9sb2dpaSBJbmZvcm1hdGlvbmFsZTEbMBkGA1UE
CgwSw45udHJlcHJpbmRlcmUgU1JMMRIwEAYDVQQHDAlDaGnFn2luYXUxEDAOBgNVBAgMB01vbGRv
dmExCzAJBgNVBAYTAk1EMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHlLKPEGRmgHoY+fSC
txm8UuOUm8H5AK7c1elJ6Bz5hKgHpD1wxiX3+lpLyHgGngD7397An3d0vT4spZWpHZzIRgmIiBIL
xhKy7AYLene8miYueujMgyBUlLnOoUrvg6JbEtXpr174c+zwWe8NzMdl0fSDHoigyJZUJHGAJJsD
FwIDAQABoIIBRjAaBgorBgEEAYI3DQIDMQwWCjYuMS43NjAxLjIwUAYJKwYBBAGCNxUUMUMwQQIB
BQwKQ1RTLVBhbnRhegwRQ1RTLVBhbnRhelxOZXN0YXAMHVJlcXVlc3RDZXJ0aWZpY2F0ZS52c2hv
c3QuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgECHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAHQAcgBv
AG4AZwAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIDAQAwbgYJ
KoZIhvcNAQkOMWEwXzAOBgNVHQ8BAf8EBAMCBPAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwGQYDVR0R
BBIwEIYOTW9iaWxlT3BlcmF0b3IwHQYDVR0OBBYEFH44AQAcN2uoaFVwzO9rfh2MJwneMA0GCSqG
SIb3DQEBBQUAA4GBADH5zSmn5UcffcwBn2aZ+gWlGP/rjNAjabVwEhlZBZRN9aL8sH42yKKrNOTk
hWudVkIQQgSmg9k3e4U1jaypHXmmQbUtZQRm9tJWrJq64k6ndEy/Sj8aquHPaFb/g8R6frDRMJO3
anQnb/uotBKGQKxq8wVz9dGAp2MpMMUNz8wi
'''
        csr = ParseCsr(rawpkcs10, headerIncluded=False)
        print
        'TODO - this one does not work'

    # test parsing cmp responses
    if False:
        raw = '''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'''
        # decoder.decode.defaultErrorState = decoder.stDumpRawValue
        data, _ = decoder.decode(b64decode(raw), asn1Spec=rfc9480.PKIMessage())
        # d = ParseCmpResponse(raw)
        print
        data



