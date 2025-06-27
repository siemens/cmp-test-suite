# Test Suite Structure
This document provides a high-level overview of the structure and organization of the test suite for the CMP (Certificate Management Protocol) implementation.
The document categorizes test cases based on authentication methods, key pair generation methods, and the forms of requests used during enrollment as described in the RFC.

For each form of request and variant, the document gives a brief description and lists the relevant sections of RFC 9483 that need to be referenced during testing.

Each topic corresponds directly to a test class and section in the file [Requirements](Requirements.md).


TODO
Still needs to be sorted here:
- 4.3 Support Messages
- 4.4 Handling Delay Delivery
- fullly include Section 5
- Section 6 CMP Message Transfer Mechanisms (shoudl be included at a later date)


## Enrolling End Entities
RFC 9483 Section 4.1: "These approaches differ in the way the EE authenticates itself to the PKI, in the form of the
request being used, and how the key pair to be certified is generated."

For each form of request, there will be tests for how the EE authenticates itself to the PKI and how the key pair is generated. Therefore, we categorize test cases based on authentication methods, key pair generation methods, and the forms of requests used during enrollment.

Ways in which the EE authenticates itself to the PKI:
- Signature-based protection 
- MAC-based protection (see Section 4.1.5)

Ways in which the key pair is generated:
- Decentral key generation
- Central key generation (see Section 4.1.6)


The forms of requests are:
- 4.1.1 Enrolling an End Entity to a New PKI
- 4.1.2 Enrolling an End Entity to a Known PKI
- 4.1.3 Updating a Valid Certificate
- 4.1.4 Enrolling an End Entitiy Using a PKCS#10 Request

Sections 4.1.1 to 4.1.4 explain the forms of requests from a signature-based protection and decentral key generation perspective.
Section 4.1.5 explains the variants of MAC-based protection. There are variants for PKI management operations for Sections 4.1.1, 4.1.2, and 4.1.4.
Section 4.1.6 explains the variants for adding central key pair generation to enrollment. There are variants for Sections 4.1.1 to 4.1.4 and for the variants described in Section 4.1.5.


### Enrolling an End Entity to a New PKI
RFC 9483 Section 4.1 "using a certificate from an external PKI, e.g., a manufacturer-issued device certificate, and the corresponding private key"

#### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 

#### MAC-based protection
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 5.2.3 - for replacing the protection 
- 4.1.1 - for the general description of request
- 4.1.5 - for MAC-based variant specific details

#### Central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for the general description of request
- 4.1.6 - for central key pair generation  variant specific details

#### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for the general description of request
- 4.1.5 - for MAC-based variant specific details
- 4.1.6 - for central key pair generation  variant specific details



### Enrolling an End Entity to a Known PKI
RFC 9483 Section 4.1: "using a private key and certificate issued from the same PKI that is addressed for requesting a certificate"

#### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2 

#### MAC-based protection
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 5.2.3 - for replacing the protection
- 4.1.1 - for general description and message sequence of request
- 4.1.2 
- 4.1.5 - for MAC-based variant specific details

#### Central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2
- 4.1.6 - for central key pair generation  variant specific details

#### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2
- 4.1.5 - for MAC-based variant specific details
- 4.1.6 - for central key pair generation  variant specific details


### Updating a Valid Certificate
RFC 9483 Section 4.1 "using the certificate to be updated and the corresponding private key"

#### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.3 


#### Central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.3
- 4.1.6 - for central key pair generation  variant specific details

#### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.3
- 4.1.5 - for MAC-based variant specific details
- 4.1.6 - for central key pair generation  variant specific details


### Enrolling an End Entity Using a PKCS#10 Request
RFC 9483 Section 4.1 "using shared secret information known to the EE and the PKI management entity"
RFC 9483 Section 4.1.4 "This offers a
variation of the PKI management operations specified in Sections 4.1.1 to 4.1.3."

#### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2 - for prerequisites
- 4.1.3 - for general description and message sequence of update
- 4.1.4 - 

#### MAC-based protection
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2 - for prerequisites
- 4.1.3 - for general description and message sequence of update
- 4.1.4 - 
- 4.1.5 - for MAC-based variant specific details

#### Central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2 - for prerequisites
- 4.1.3 - for general description and message sequence of update
- 4.1.4 - 
- 4.1.6 - for central key pair generation  variant specific details

#### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 3.4 - for generic aspects of PKI Messages 
- 5.1.1 - for PKI management operation responding to a certificate request
- 5.1.2 - for PKI management operation responding to a confirmation message 
- 5.1.4 - for PKI management operation responding to a support message (here I´m not sure)
- 5.1.5 - for PKI management operation initiating delayed delivery 
- 4.1.1 - for general description and message sequence of request
- 4.1.2 - for prerequisites
- 4.1.3 - for general description and message sequence of update
- 4.1.4 - 
- 4.1.5 - for MAC-based variant specific details
- 4.1.6 - for central key pair generation  variant specific details

## Revoking a Certificate
RFC 9483 Section 4.2 "should be used by an entity to request revocation of a
certificate. Here, the revocation request is used by an EE to revoke one of its own certificates."

Needed sections of the RFC:
- 4.2 - Revoking a Certificate
- 3.4 - for generic aspects of PKI Messages 
- 5.1.3 - for revocation specific PKI management operation 
- 5.3.2 - for revocation specific PKI management operation
