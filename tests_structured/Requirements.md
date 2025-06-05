<!--
Add copywrite
-->

# Requirements 
This document provides detailed functional requirements for the test cases in the CMP test suite. It outlines specific prerequisites, message flows, and expected behaviors for each test case based on RFC 9483. The document serves as a blueprint for implementing and validating test cases.

## Functional test cases (implicit and explicit)
Functional test cases always follow the same format:
RFC {Number} Section {Number} "{Quote from which the test case arises}"
{as many blocks as needed to explain from which RFC sections the test cases arise}
- Test Name: {Name of the test case, which is the same as in the implemention in robot files}
    - Input: {What does the end entity send or what has occured}
    - Output: {How should the reaction of the PKI managemet operation be}

### Enrolling an End Entity to New PKI

#### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 

##### Prerequisites
RFC 9483 4.1.1 "The certificate of the EE MUST have been enrolled by an external PKI, e.g., 
a manufacturer-issued device certificate."
- Test Name: Reject Certificate From Non External Source
    - Input: EE sends certificate from not external source
    - Output: pki sends rejection

RFC 9483 4.1.1 "The PKI management entity MUST have the trust anchor of the external PKI."
- Test Name: Reject Certificate From Untrusted Source
    - Input: EE sends certificate from untrusted source
    - Output: pki sends rejection

RFC 9483 4.1.1 "When using the generalInfo field certProfile, the EE MUST know the identifier 
needed to indicate the requested certificate profile."
- Test Name: Reject Invalid CertProfil Identifier
    - Input: EE sends ir false identifier
    - Output: pki sends rejection


##### Message Flow
For each of these Test Cases requirements from Section 3 should be passed.

RFC 9483 4.1.1 "For this PKI management operation, the EE MUST include a sequence of one CertReqMsg in the ir. If more certificates are required, further requests MUST be sent using separate PKI management operations."
- Test Name: Reject Multiple CertReqMsg In IR
    - Input: EE sends more than one sequence of CertReqMsg in the ir 
    - Output: correct reaction of the PKI
- Test Name: Accept Single CertReqMsg In IR
    - Input: EE sends one sequence of CertReqMsg in the ir 
    - Output: valid ip message



RFC 9483 4.1.1 "In case the EE included the generalInfo field implicitConfirm in the request 
message and the PKI management entity does not need any explicit confirmation 
from the EE, the PKI management entity MUST include the generalInfo field 
implicitConfirm in the response message."
RFC 9483 4.1.1 "If the EE did not request implicit confirmation or implicit confirmation was not granted by the PKI management entity, certificate confirmation MUST be performed as follows."
RFC 9483 4.1.1 "If the EE successfully received the certificate, it MUST send a certConf message in due time. On receiving a valid certConf message, the PKI management entity MUST respond with a pkiConf message. If the PKI management entity does not receive the expected certConf message in time, it MUST handle this like a rejection by the EE."
- Test Name: Include ImplicitConfirm In Response When Requested
    - Input: EE includes the generalInfo field implicitConfirm 
    - Output: ip can include implicitConfirm
- Test Name: Not Include ImplicitConfirm In Response When Not Granted
    - Input: EE includes the generalInfo field implicitConfirm 
    - Output: ip can include no implcitConfirm granted 

- Test Name: Respond with PKIConf On Valid CertConf
    - Input: EE includes the generalInfo field implicitConfirm + ip can include no implcitConfirm granted + EE sends valid certConf
    - Output: pki responds with pkiConf message

Test Name: 
    - Input: EE includes the generalInfo field implicitConfirm + ip can include no implcitConfirm granted + EE sends not valid certConf
    - Output: pki responds correctly 

- Test Name: Response Without ImplicitConfirm When Not Granted
    - Input: EE does not request implcitConfirm 
    - Output: ip does not include implcitConfirm 

- Test Name: Responds With PKIConf On Valid CertConf
    - Input: EE does not request implcitConfirm + ip does not include ImplicitConfirm + EE valid correct certConf 
    - Output pki responds with pkiConf message


- Test Name: 
    - Input: EE does not request implcitConfirm + ip does not include implicit Confirm + EE sends not valid certConf
    - Output: correct reaction of pki
- Test Name: Handles Missing CertConf As Rejection
    - Input: EE does not request implcitConfirm + ip does not include implicit Confirm + EE sends certConf not in time
    - Output: pki handles this as rejection


RFC 9483 4.1.1 "If the certificate request was rejected by the CA, the PKI management entity 
MUST return an ip message containing the status code "rejection" as described in 
Section 3.6, and the certifiedKeyPair field SHALL be omitted. The EE MUST NOT 
react to such an ip message with a certConf message, and the PKI management 
operation MUST be terminated."
- Test Name: Reject CertConf For Rejected Certificate
    - Input: EE sends certConf message after certificate was rejected
    - Output: pki does not react

#### MAC-based protection
Needed sections of the RFC for testing:
- 4.1.1
- 4.1.5

#### Central key pair generation
Needed sections of the RFC for testing:
- 4.1.1
- 4.1.6

#### MAC-based protection + central key pair generation
Needed sections of the RFC for testing:
- 4.1.1 
- 4.1.5
- 4.1.6



### Enrolling an End Entity to a Known PKI

#### Signatured-based protection and decentral key generation
Needed sections of the RFC for testing:
- 4.1.1
- 4.1.2 

##### Prerequisites 
RFC 9483 4.1.2 "The certificate used by the EE have been enrolled by the PKI it requests another
certificate from."
- Test Name: 
    - Input: 
    - Output: 

RFC 9483 4.1.2 "When using the generalInfo field certProfile, the EE MUST know the identifier 
needed to indicate the requested certificate profile."
- Test Name: Reject Invalid CertProfil Identifier
    - Input: EE sends ir false identifier
    - Output: pki sends rejection

##### Message Flow
RFC 9483 4.1.2 "The message sequence for this PKI management operation is identical to that given in Section 4.1.1, with the following changes:"
- test cases above should be tested with cr as message body

RFC 9483 4.1.2 "The body of the first request and response be cr and cp. Otherwise, ir and ip
be used.
Note: Since the difference between ir/ip and cr/cp is syntactically not essential, an ir/ip may
be used in this PKI management operation."
- Test Name: 
    - Input: 
    - Output: 

RFC 9483 4.1.2 "The caPubs field in the certificate response message be absent."
- Test Name: 
    - Input: 
    - Output: 

#### MAC-based protection
Needed sections of the RFC for testing:
- 4.1.2 
- 4.1.5

#### Central key pair generation
Needed sections of the RFC for testing:
- 4.1.2
- 4.1.6

#### MAC-based protection + central key pair generation
Needed sections of the RFC for testing:
- 4.1.2
- 4.1.5
- 4.1.6


### Updating a Valid Certificate


#### Signatured-based protection and decentral key generation
Needed sections of the RFC for testing:
- 4.1.3 

##### Prerequisites 


#### Central key pair generation
Needed sections of the RFC for testing:
- 4.1.3
- 4.1.6

#### MAC-based protection + central key pair generation
Needed sections of the RFC for testing:
- 4.1.3
- 4.1.5
- 4.1.6 


### Enrolling an End Entitiy Using a PKCS#10 Request

#### Signatured-based protection and decentral key generation
Needed sections of the RFC for testing:
- 4.1.3

#### MAC-based protection
Needed sections of the RFC for testing:
- 4.1.3
- 4.1.5

#### Central key pair generation
Needed sections of the RFC for testing:
- 4.1.3
- 4.1.6

#### MAC-based protection + central key pair generation
Needed sections of the RFC for testing:
- 4.1.3
- 4.1.5
- 4.1.6



### Revoking a Certificate
Needed sections of the RFC:
- 4.2 - Revoking a Certificate
- 3.4 - for generic aspects of PKI Messages 
- 5.1.3 - for revocation specific PKI management operation 
- 5.3.2 - for revocation specific PKI management operation


RFC 9483 4.2 "The revocation request message MUST be signed using the certificate that is to be revoked to prove the authorization to revoke."
- Test Name: Reject Revocation request With 
    - Input: 
    - Output: 

RFC 9483 4.2 "The revocation request message is signature-protected using this 
certificate. This requires that the EE still possesses the private key. If 
this is not the case, the revocation has to be initiated by other means, e.g., 
revocation by the RA, as specified in Section 5.3.2."
RFC 9483 5.1.3 "It MUST make sure that the referenced certificate exists 
(failInfo bit: badCertId), has been issued by the addressed CA, and is not 
already expired or revoked (failInfo bit: certRevoked). On success, it respond 
with a positive rp message, as described in Section 4.2."
- Test Name: 
    - Input: 
    - Output: 


RFC 9483 4.2 "The revocation request message MUST be signed using the certificate that is to be revoked to prove the authorization to revoke."
- Test Name: 
    - Input: 
    - Output: 


## Tests for any message the EE recieves

### Section 3.4


### Section 5.1

RFC 9483 5.1 "The PKI management entity terminating the PKI management operation at CMP level
respond to all received requests by returning a related CMP response message or 
an error."
- pki has send cmp response message or error 

RFC 9483 5.1 "In addition to the checks described in Section 3.5, the responding PKI 
management entity check that a request that initiates a new PKI management 
operation does not use a transactionID that is currently in use."
- transactionID is already in use -> failInfo bit value is transactionIdInUse

RFC 9483 5.1 "The responding PKI management entity copy the sender field of the request to the 
recipient field of the response, copy the senderNonce of the request to the 
recipNonce of the response, and use the same transactionID for the response."
- pki sends response where recipient field of response = sender field of the request
- pki sends response where recipient field of response != sender field of the request
- pki sends response where recipNonce of response = senderNonce of the request
- pki sends response where recipNonce of response != senderNonce of the request
- pki sends response where transactionID of response = transactionID of the request
- pki sends response where transactionID of response != transactionID of the request
- same things as above with version 'senderfield, transactionID' 'senderfield, senderNonce' 'senderNonce, transactionID'

### Section 5.1.1
RFC 9483 5.1.1 "The PKI management entity check the message body according to the applicable
requirements from Section 4.1. Possible failInfo bit values used for error reporting in case a check failed include badCertId and badCertTemplate."
- TODO the many test cases also with the help of Section 3

RFC 9483 5.1.1 "It verify the presence and value of the proof-of-possession (failInfo bit: 
badPOP) unless central key generation is requested."
- TODO many test cases also with the help of Section 3

### Section 5.1.2


### Section 5.1.4


### Section 5.1.5




