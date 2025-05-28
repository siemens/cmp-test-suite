
# Enrolling End Entities
RFC 9483 Section 4.1: "These approaches differ in the way the EE authenticates itself to the PKI, in the form of the
request being used, and how the key pair to be certified is generated."
For each form of request being used, there will be a tests for how the EE authenticates itself to the PKI and how the Key Pair is generated. 

Ways how the EE authenticates itself to the PKI:
- Signature-based protection
- MAC-based protection (see Section 4.1.5)

Ways how the key pair is generated:
- Decentral key generation
- Central key generation (see Section 4.1.6)


The forms of requests are:
- 4.1.1 Enrolling an End Entity to a New PKI
- 4.1.2 Enrolling an End Entity to a Known PKI
- 4.1.3 Updating a Valid Certificate
- 4.1.4 Enrolling an End Entitiy Using a PKCS#10 Request

Sections 4.1.1 to 4.1.4 explain the forms of requests from a signature-based protection and decentral key generation perspective.
Section 4.1.5 explaines the variants of MAC-based protection. There are variants for PKI management operations for Sections 4.1.1, 4.1.2 and 4.1.4.
Section 4.1.6 explains the variants for adding central key pair generation to enrollment. There are variants for Sections 4.1.1 to 4.1.4 and to the variants described in Section 4.1.5.


## Enrolling an End Entity to a New PKI
RFC 9483 Section 4.1 "using a certificate from an external PKI, e.g., a manufacturer-issued device certificate, and
the corresponding private key"

### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 4.1.1 

### MAC-based protection
Needed sections of the RFC:
- 4.1.1 
- 4.1.5

### Central key pair generation
Needed sections of the RFC:
- 4.1.1
- 4.1.6

### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 4.1.1 
- 4.1.5
- 4.1.6



## Enrolling an End Entity to a Known PKI
RFC 9483 Section 4.1 "using a private key and certificate issued from the same PKI that is addressed for requesting
a certificate"

### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 4.1.2 

### MAC-based protection
Needed sections of the RFC:
- 4.1.2 
- 4.1.5

### Central key pair generation
Needed sections of the RFC:
- 4.1.2
- 4.1.6

### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 4.1.2
- 4.1.5
- 4.1.6


## Updating a Valid Certificate
RFC 9483 Section 4.1 "using the certificate to be updated and the corresponding private key"

### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 4.1.3 


### Central key pair generation
Needed sections of the RFC:
- 4.1.3
- 4.1.6

### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 4.1.3
- 4.1.5
- 4.1.6 


## Enrolling an End Entitiy Using a PKCS#10 Request
RFC 9483 Section 4.1 "using shared secret information known to the EE and the PKI management entity"

### Signatured-based protection and decentral key generation
Needed sections of the RFC:
- 4.1.3

### MAC-based protection
Needed sections of the RFC:
- 4.1.3
- 4.1.5

### Central key pair generation
Needed sections of the RFC:
- 4.1.3
- 4.1.6

### MAC-based protection + central key pair generation
Needed sections of the RFC:
- 4.1.3
- 4.1.5
- 4.1.6