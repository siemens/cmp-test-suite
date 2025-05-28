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

# Test Classes
## support_messages
- Section 4.3.1 Get CA Certificates
- Section 4.3.2 Get Root CA Certificate Update
- Section 4.3.3 Get Certificate Request Template
- Section 4.3.4 currentCRL
- Section 4.3.4. CRL Update Retrieval

## pki_mgmt_entity_op
'pki_mgmt_entity_op' are test cases for Section 5 of the RFC
- 5. PKI Management Entity Operations
- 5.2. Forwarding Messages
- 5.2.2 Adding Protection and Batching of Messages
- 5.2.2.1 Adding Protection to a Request Message

