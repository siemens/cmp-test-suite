from pyasn1 import debug
from pyasn1.type import univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed
from pyasn1_alt_modules.rfc2459 import GeneralName, Extension, Extensions
from pyasn1_alt_modules.rfc2511 import CertTemplate
from pyasn1_alt_modules import rfc4210
from pyasn1.codec.der import decoder, encoder




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

# revocation reasons http://www.alvestrand.no/objectid/2.5.29.21.html#
REASON_UNSPECIFIED = 0
REASON_KEY_COMPROMISE = 1
REASON_CA_COMPROMISE = 2
REASON_AFFILIATION_CHANGED = 3
REASON_SUPERSEDED = 4
REASON_CESSATION_OF_OPERATION = 5
REASON_CERTIFICATE_HOLD = 6
REASON_REMOVE_FROM_CRL = 8


def build_cmp_revive_request(serial_number, sender='test-cmp-cli@example.com', recipient='test-cmp-srv@example.com'):
	return build_cmp_revoke_request(serial_number, sender='test-cmp-cli@example.com',
									recipient='test-cmp-srv@example.com',
									reason=REASON_REMOVE_FROM_CRL)


def build_cmp_revoke_request(serial_number, sender='test-cmp-cli@example.com',
							 recipient='test-cmp-srv@example.com',
							 reason=REASON_UNSPECIFIED):
	"""Creates a certificate revocation request, based on the given serial#
	:param serial_number: str, serial number of certificate to revoke
	:param sender: optional str, sender to use in the request
	:param recipient: optional str, recipient of the request
	:param reason: optional int, one of the REASON_* constants
	:returns: bytes, DER-encoded PKIMessage """

	# PKIHeader
	pvno = univ.Integer(2) # cmp2000
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
	crl_reason.setComponentByName('extnID', univ.ObjectIdentifier((2, 5, 29, 21))) #2.5.29.21 CRL reason
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

	# print(pki_message.prettyPrint())
	cmp_request = encoder.encode(pki_message)
	return cmp_request



if __name__ == '__main__':
	data = build_cmp_revoke_request(12345)
	debug.setLogger(debug.Debug('all'))

	structure, _ = decoder.decode(data, asn1Spec=rfc4210.PKIMessage())
	print(structure)

	data = build_cmp_revoke_request(12345)
	open('cmp-revoke.bin', 'wb').write(data)

	data = build_cmp_revive_request(54321)
	open('cmp-revive.bin', 'wb').write(data)

	data = build_cmp_revoke_request(11111, reason=REASON_CERTIFICATE_HOLD)
	open('cmp-hold.bin', 'wb').write(data)
