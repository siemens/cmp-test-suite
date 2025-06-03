# Guiliano Test Classes
## What are in the test clases:
This collection of references to the RFC means that this section has been mentioned in the documentation of a test case. It does not show how many times the reference has been used or what exactly has been tested in the test case that mentioned the reference.


### basic
- RFC 6712 "3.3. General Form"
- RFC 9483 Section 3
- RFC 9483 Section 4.1.4
- RFC 9483 Section 3 and 5
- RFC 9483 Section 4.1.2
- RFC 9483 Section 4.1.3
- RFC 9483 Section 4.1.4
- RFC 9483 Section 4
- RFC 9483 Section 5
- RFC 9483 Section 3.5

### Cert_conf_tests
- RFC 9483 Section 4.1.1
- RFC 9483 Section 4.1
- RFC 9483, Section 3 and 4.1
- RFC 9483, Section 3.1

### Cross_certification
- RFC4210bis-18 Appendix D.6
- RFC4210bis-15 Section Section 5.3.11

### deprecated
Tests which are deprecated and should be removed in the future.

### extra_issuing 
- RFC 4210-bis18 5.2.8.4
- RFC 4210bis-18 Section 5.2.8.3.3
- RFC 4210bis-18 Section 5.2.8.3.
- RFC 4211 section-6.1
- RFC 4211 section-6.2
- RFC 4211 section-6.3
- RFC 4211 section-6.4
- RFC 4211 section-7.1
- RFC 4211 section-7.2

### kga
- RFC 9483 Section 4.1.6.1
- RFC9483 Section 4.1.6
- RFC 9483 Section 4.1.6.2

### lwcmp
- RFC 9483 Section 3.1
- RFC 9483 Section 3.2
- RFC 9483 Section 3.3
- RFC 9483 Section 3.5
- RFC 9483 Section 3.6.4
- RFC 9483 Section 4
- RFC 9483 Section 4.1
- RFC 9483 Section 4.1.1
- RFC 9483 Section 4.1.2
- RFC 9483 Section 4.1.3
- RFC 9483 Section 4.1.4
- RFC 9483 Section 5
- RFC 9483 Section 5.1.1
- RFC 9483 Section 5.1.2
- RFC 9483 Section 5.1.4
- RFC 9483 Section 6.1

### pki_mgmt_entity_op
'pki_mgmt_entity_op' are test cases for Section 5 of the RFC
- RFC 9483 5. PKI Management Entity Operations
- RFC 9483 5.2. Forwarding Messages
- RFC 9483 5.2.2 Adding Protection and Batching of Messages
- RFC 9483 5.2.2.1 Adding Protection to a Request Message

### revocation_tests
- RFC 9483 Section 4.2
- RFC 9483 Sections 3
- RFC 9483 Section 5.3.2,
- RFC 9483, Section 4.1.1
- RFC 9483, Section 4.1.3

### support_messages
- RFC 9483 Section 4.3.1 Get CA Certificates
- RFC 9483 Section 4.3.2 Get Root CA Certificate Update
- RFC 9483 Section 4.3.3 Get Certificate Request Template
- RFC 9483 Section 4.3.4 currentCRL
- RFC 9483 Section 4.3.4. CRL Update Retrieval



### guiliano tests in new structure
Classes I have sorted in my "test_structured":
- basic
- lwcmp



# resources.keywords
Any possible todos are commeted with the sections or after the respective tests. 
The keywords are sorted by their functionality. Structural comments are indicated by the suffix "keywords". Overall structure is indicated by 4 hashtages infront of the comments and an explanation what the keywords for the upcoming sections are for. 
The structure is like this: 
- Set up keywords
    - Set Up Test Suite
    - Increase TestIndex
    - Get Next Common Name
    - Set Up EnvelopedData Certs For Tests

- Certificate and key initialization keywords
    - Certificate initialization keywords
        - Issue New Cert For Testing
        - Issue And Revoke A Fresh Cert
        - Generate CSR For Testing
        - Generate CertTemplate For Testing
    - Key generation keywords
        - Generate Unique Key
        - Generate Default Key
        - Generate Default PQ SIG Key
        - Generate Default PQ KEM Key
        - Generate Default KeyAgreement Key
        - Generate Default KeyEncipherment Key
        - Generate Default Composite Sig Key
    - Certificate validation and confirmation keywords
        - Certificate Must Be Valid
        - Validate Certificate Was Issued For Expected Alg
        - Confirm Certificate If Needed

- PKIMessage handling keywords
    - PKIMessage creation keywords
        - Build Composite Signature Request
        - Default Protect PKIMessage
        - Default Protect With MAC
        - Generate Default MAC Protected PKIMessage
        - Generate Default IR Sig Protected
    - Transportation keywords
        - Exchange Data With CA
        - Exchange PKIMessage
        - Exchange Migration PKIMessage
    - PKIMessage parsing and logging keywords
        - Try To Log PKIMessage As ASN1
        - Load And Refresh PKIMessage From File

- PKIMessage validation keywords
    - PKImessage body variables keywords
        - PKIMessage Body Type Must Be
        - PKIMessage Must Contain ImplicitConfirm Extension
    - Nonce validation keywords
        - Sender And Recipient Nonces Must Match
        - SenderNonce Must Be At Least 128 Bits Long
        - Collect Nonce From PKIMessage
    - Response time validation keywords
        - Response Time Must Be Fresh
    - PKIMessage Status validation keywords
        - PKIStatusInfo failinfo Bit Must Be
        - PKIStatus Must Be

- Certificate Signing Request keywords
    - Generate CSR With RSA2048 And A Predefined Common Name
    - Load And Parse Example CSR
    - Generate Key And CSR

- Hybrid algorithm keywords
    - Exchange Hybrid PKIMessage
    - Validate EncrCert For KEM

- EnvelopedData keywords
    - Issued NEG RSA KTRI CERT
    - ISSUE POS RSA KTRI Cert
    - Issue NEG ECC KARI Cert
    - Issue POS ECC KARI Cert
