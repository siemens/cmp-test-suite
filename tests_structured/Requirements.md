
# Functional test cases 

## Section 4.1.1

### Prerequisites
"The certificate of the EE MUST have been enrolled by an external PKI, e.g., a 
manufacturer-issued device certificate."
- Reject Certificate From Non External Source
    - Input: EE sends certificate from not external source
    - Output: pki sends rejection

"The PKI management entity MUST have the trust anchor of the external PKI."
- Reject Certificate From Untrusted Source
    - Input: EE sends certificate from untrusted source
    - Output: pki sends rejection

"When using the generalInfo field certProfile, the EE MUST know the identifier 
needed to indicate the requested certificate profile."
- Reject Invalid CertProfil Identifier
    - Input: EE sends ir false identifier
    - Output: pki sends rejection


### Message Flow
For each of these Test Cases requirements from Section 3 should be passed.

"For this PKI management operation, the EE MUST include a sequence of one CertReqMsg in the ir. If more certificates are required, further requests MUST be sent using separate PKI management operations."
- Reject Multiple CertReqMsg In IR
    - Input: EE sends more than one sequence of CertReqMsg in the ir 
    - Output: correct reaction of the PKI
- Accept Single CertReqMsg In IR
    - Input: EE sends one sequence of CertReqMsg in the ir 
    - Output: valid ip message



"In case the EE included the generalInfo field implicitConfirm in the request 
message and the PKI management entity does not need any explicit confirmation 
from the EE, the PKI management entity MUST include the generalInfo field 
implicitConfirm in the response message."
"If the EE did not request implicit confirmation or implicit confirmation was not granted by the PKI management entity, certificate confirmation MUST be performed as follows."
"If the EE successfully received the certificate, it MUST send a certConf message in due time. On receiving a valid certConf message, the PKI management entity MUST respond with a pkiConf message. If the PKI management entity does not receive the expected certConf message in time, it MUST handle this like a rejection by the EE."
- Include ImplicitConfirm In Response When Requested
    - Input: EE includes the generalInfo field implicitConfirm 
    - Output: ip can include implicitConfirm
- Not Include ImplicitConfirm In Response When Not Granted
    - Input: EE includes the generalInfo field implicitConfirm 
    - Output: ip can include no implcitConfirm granted 

- Respond with PKIConf On Valid CertConf
    - Input: EE includes the generalInfo field implicitConfirm + ip can include no implcitConfirm granted + EE sends valid certConf
    - Output: pki responds with pkiConf message


    - Input: EE includes the generalInfo field implicitConfirm + ip can include no implcitConfirm granted + EE sends not valid certConf
    - Output: pki responds correctly 

- Response Without ImplicitConfirm When Not Granted
    - Input: EE does not request implcitConfirm 
    - Output: ip does not include implcitConfirm 

- Responds With PKIConf On Valid CertConf
    - Input: EE does not request implcitConfirm + ip does not include ImplicitConfirm + EE valid correct certConf 
    - Output pki responds with pkiConf message


- EE does not request implcitConfirm + ip does not include implicit Confirm + EE sends not valid certConf -> correct reaction of pki
- Handles Missing CertConf As Rejection
    - Input: EE does not request implcitConfirm + ip does not include implicit Confirm + EE sends certConf not in time
    - Output: pki handles this as rejection


"If the certificate request was rejected by the CA, the PKI management entity 
MUST return an ip message containing the status code "rejection" as described in 
Section 3.6, and the certifiedKeyPair field SHALL be omitted. The EE MUST NOT 
react to such an ip message with a certConf message, and the PKI management 
operation MUST be terminated."
- Reject CertConf For Rejected Certificate
    - Input: EE sends certConf message after certificate was rejected
    - Output: pki does not react



## Section 4.1.2

### Prerequisites 





# Tests for any message the EE recieves

## Section 5.1

"The PKI management entity terminating the PKI management operation at CMP level
respond to all received requests by returning a related CMP response message or 
an error."
- pki has send cmp response message or error 

"In addition to the checks described in Section 3.5, the responding PKI 
management entity check that a request that initiates a new PKI management 
operation does not use a transactionID that is currently in use."
- transactionID is already in use -> failInfo bit value is transactionIdInUse

"The responding PKI management entity copy the sender field of the request to the 
recipient field of the response, copy the senderNonce of the request to the 
recipNonce of the response, and use the same transactionID for the response."
- pki sends response where recipient field of response = sender field of the request
- pki sends response where recipient field of response != sender field of the request
- pki sends response where recipNonce of response = senderNonce of the request
- pki sends response where recipNonce of response != senderNonce of the request
- pki sends response where transactionID of response = transactionID of the request
- pki sends response where transactionID of response != transactionID of the request
- same things as above with version 'senderfield, transactionID' 'senderfield, senderNonce' 'senderNonce, transactionID'

## Section 5.1.1
"The PKI management entity check the message body according to the applicable
requirements from Section 4.1. Possible failInfo bit values used for error reporting in case a check failed include badCertId and badCertTemplate."
- TODO the many test cases also with the help of Section 3

"It verify the presence and value of the proof-of-possession (failInfo bit: 
badPOP) unless central key generation is requested."
- TODO many test cases also with the help of Section 3




