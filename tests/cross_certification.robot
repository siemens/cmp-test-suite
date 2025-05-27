# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Contains Test cases which are more or less only relevant for CMP and not LwCMP.

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/keyutils.py
Library             ../resources/cmputils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/envdatautils.py
Library             ../resources/cryptoutils.py
Library             ../resources/certbuildutils.py

Suite Setup    Set Up CRR Test Cases
Test Tags           cmp   advanced   crr


*** Keywords ***
Set Up CRR Test Cases
    [Documentation]    Set up the test cases for the CMP test cases.
    Set Up Test Suite
    ${cert}=   May Load Cert   ${TRUSTED_CA_CERT}
    ${key}=    Load Private Key From File    ${TRUSTED_CA_KEY}   password=${TRUSTED_CA_KEY_PASSWORD}
    VAR   ${TRUSTED_CA_CERT}    ${cert}  scope=Global
    VAR   ${TRUSTED_CA_KEY}     ${key}  scope=Global

Default Protect PKIMessage With Trusted Cert
    [Documentation]    Protects the PKIMessage with the trusted CA certificate.
    [Arguments]    ${pki_message}
    ${response}=  Protect PKIMessage    ${pki_message}    signature
    ...           private_key=${TRUSTED_CA_KEY}    cert=${TRUSTED_CA_CERT}   certs_dir=${TRUSTED_CA_DIR}
    RETURN    ${response}


*** Test Cases ***
# TODO fix citation if RFC defined!!!

CA MUST Accept Valid Cross Certification Request
    [Documentation]   According to RFC4210bis-15 Section 5.3.11 and appendix D.6 We send a valid
    [Tags]      positive   robot:skip-on-failure
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${key}=   Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    # -1 day
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${SENDER}   issuer=${RECIPIENT}
    ...       sign_alg=${sig_alg}    version=v3  include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${ccr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert   ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    ccp
    PKIStatus Must Be    ${response}   accepted
    Validate Cross Certification Response  ${response}

CA MUST Return A Correct Cross Certificate
    [Documentation]   According to RFC4210bis-15 Section 5.3.11 and appendix D.6 We send a valid
    ...               cross certification request and the CA returns a cross certificate.
    ...               When the CA accepts the request, it MUST return the correct cross certificate.
    [Tags]      positive
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${cert_template}   ${key}=   Generate CCR CertTemplate For Testing
    ${ccr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert   ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    ccp
    PKIStatus Must Be    ${response}   accepted
    ${cert_chain}=  Build CMP Chain From PKIMessage    ${response}   for_issued_cert=True
    Validate Certificate Pkilint    ${cert_chain}[0]
    Validate CA Cross-Signed Certificate    ${cert_chain}[0]   ${cert_template}   ${cert_chain}[1]

CA MUST Reject Cross Certification Request With EE Certificate
    [Documentation]    According to RFC4210bis-15 Section 5.3.11 the ccr request can only be sent by a CA.
    ...                We send a valid cross certification request signed with an end-entity certificate.
    ...                The CA MUST reject this request and may respond with the optional failInfo `notAuthorized`.
    [Tags]         negative   trust  ee
    ${cert_template}   ${key}=   Generate CCR CertTemplate For Testing
    ${ccr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage    ${ccr}  signature=protection
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}  notAuthorized

CA MUST Reject Cross Certification Request with private key
    [Documentation]    According to RFC4210bis-15 Section Section 5.3.11 the private key **MUST** not be
    ...             disclosed to the other CA. We send a PKIMessage with a encrypted private key. The CA
    ...             **MUST** reject this request and may respond with the optional failInfo `badRequest`,
    ...            `badPOP`.
    [Tags]         negative  bad-behaviour
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${cert_template}    ${key}=  Generate CertTemplate For Testing
    # ${data}=   Prepare Private Key For POP
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}   sender=${SENDER}   use_string=False
    ${rid}=   Prepare Recipient Identifier    ${TRUSTED_CA_CERT}
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${rid}   ${TRUSTED_CA_CERT}   for_agreement=False
    ...        private_key=${TRUSTED_CA_KEY}
    # It is not relevant if the private key is correct, because this behaviour is not allowed.
    ${ccr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    popo=${popo}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    ccp
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest,badPOP

CA MUST Reject Cross Certification Request without POP
   [Documentation]    According to RFC4210bis-15 Section Section 5.3.11 the private key **MUST** not be
   ...                disclosed to the other CA. We send a Crr message without a key, basically asking the
   ...                CA to create a key for us. The CA MUST reject this request and may respond with the
   ...                optional failInfo `badRequest` , `badPOP`.
   [Tags]   negative
   ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
   Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
   ${cm}=   Get Next Common Name
   ${ccr}=     Build CCR From Key
   ...    ${None}
   ...    common_name=${cm}
   ...    for_kga=True
   ...    recipient=${RECIPIENT}
   ...    implicit_confirm=${True}
   ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
   ${response}=    Exchange PKIMessage    ${protected_crr}
   PKIMessage Body Type Must Be    ${response}    error
   PKIStatus Must Be    ${response}   rejection
   PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badRequest

CA MUST Reject Cross Certification Request With V2
    [Documentation]   According to RFC4210bis-18 Appendix D.6 the version field of the `CertTemplate` must be v3
    ...                v1. We send a valid cross certification with the version field set to v2. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]     negative   badCertTemplate
    ${key}=   Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${SENDER}   issuer=${RECIPIENT}
    ...     version=v2     sign_alg=${sig_alg}
    ...     include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${ccr}=     Build CCR From Key   ${key}   cert_template=${cert_template}   recipient=${RECIPIENT}
    ...     exclude_fields=popo_structure
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

#### Missing fields in CertTemplate

CA MUST Reject Cross Certification Request Missing Version Field
    [Documentation]    According to RFC4210bis-18 Appendix D.6, the version field of CertTemplate must be present.
    ...                We send a valid cross certification request without the version field. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}
    ...    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,publicKey,signingAlg
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Signing Algorithm
    [Documentation]    Signing algorithm in the CertTemplate must be present.
    ...                We send a valid cross certification request without signingAlg. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]      negative    badCertTemplate
    ${key}=    Generate Default Key
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}
    ...    subject=${SENDER}    issuer=${RECIPIENT}
    ...    version=v3    include_fields=subject,issuer,validity,publicKey,version
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Validity
    [Documentation]    Validity field must be completely specified.
    ...                We send a valid cross certification request without validity. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${cert_template}=    Prepare CertTemplate    ${key}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3
    ...    include_fields=subject,issuer,publicKey,version,signingAlg    exclude_fields=validity
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Issuer
    [Documentation]    Issuer field must be present in CertTemplate.
    ...                We send a valid cross certification request without issuer. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,validity,publicKey,version,signingAlg
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing PublicKey
    [Documentation]    PublicKey field must be present in CertTemplate.
    ...                We send a valid cross certification request without publicKey. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}
    ...    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,version,signingAlg
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing POPOSigningKey
    [Documentation]    POPOSigningKey must be present as proof-of-possession.
    ...                We send a valid cross certification request without POPOSigningKey. The CA MUST reject
    ...                the request and may return a `badPOP` failInfo.
    [Tags]    negative    badPOP
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}
    ...    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${cert_req_msg}=   Prepare CertReqMsg    ${key}    cert_template=${cert_template}     exclude_popo=True
    ${ccr}=    Build CCR From Key    ${key}    cert_req_msg=${cert_req_msg}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Reject Cross Certification Request Non-Signing Key
    [Documentation]    The key used in the CertTemplate must be a signing key.
    ...                We send a valid cross certification request with a non-signing key. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    negative    badCertTemplate   badAlg
    ${key}=    Generate Default Key
    ${key2}=    Generate Key  x25519
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key2}    validity=${validity}
    ...    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3
    ...    include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${ccr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted CA Cert    ${ccr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badAlg
