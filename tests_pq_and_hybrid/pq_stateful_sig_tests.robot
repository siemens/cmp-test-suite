# SPDX-FileCopyrightText: Copyright 2025 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
#
# robocop: off=LEN28
#
*** Settings ***
Documentation    Test cases for XMSS, XMSSMT, and HSS stateful hash-based signature algorithms,
...              based on RFC 8391, RFC 8554, and RFC 9802. Tests cover certificate issuance,
...              key usage validation for EE and CA certificates, public key format validation,
...              algorithm identifier parameter handling, exhausted key detection,
...              HSS multi-level hierarchies, and LMS/LMOTS index management.
Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/pq_verify_logic.py

Suite Setup         Set Up PQ Stateful Sig Suite
Test Tags           pq-stateful-sig   pqc  pq-sig   rfc9802


*** Variables ***
# Should not be modified, unless sha is replaced with shake.
# Uses a fast algorithm for testing purposes.
${HSS_DEFAULT_ALG}    hss_lms_sha256_m32_h5_lmots_sha256_n32_w8


*** Keywords ***
Set Up PQ Stateful Sig Suite
    [Documentation]    Initializes the test suite for PQ stateful signature tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ stateful issuing endpoint for certificate requests using XMSS, XMSSMT, or HSS algorithms.
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ stateful-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Stateful Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE

*** Test Cases ***
CA MUST Issue A Valid XMSS Certificate
    [Documentation]    According to RFC 8391 and RFC 9802 a XMSS-SHA2_10_256 private key
    ...                is a valid stateful signature algorithm. We send a valid `ir` PKIMessage to the CA
    ...                and expect it to issue a valid certificate.
    [Tags]             positive    xmss
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid XMSS EE Certificate With KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a End-Entity XMSS private key is allowed to
    ...                have key usages: digitalSignature, nonRepudiation, cRLSign. We send a valid `ir` PKIMessage to
    ...                the CA and expect it to issue a valid certificate with these key usages.
    [Tags]             positive    xmss  extensions  key_usage
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${extensions}=    Prepare Extensions    digitalSignature, nonRepudiation, cRLSign
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA MUST Reject Invalid XMSS Public Key Size
    [Documentation]    According to RFC 8391 and RFC 9802 a XMSS-SHA2_10_256 public key
    ...                must have a key size of 4 bytes + 2*n bytes, where n is the number of bytes in the hash output.
    ...                For SHA-256, this means the key size must be 68 bytes. We send a valid `ir` PKIMessage to the
    ...                CA with an invalid key size and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    xmss   invalid_key_size
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    invalid_key_size=${True}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Invalid XMSS Request With Parameters set
    [Documentation]    According to RFC 9802 Section 7, the XMSS AlgorithmIdentifier `parameters`
    ...                field must not be set. We send a valid `ir` PKIMessage to the CA with the `parameters` field
    ...                set to random bytes and expect the CA to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    xmss   alg_id_parameters
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    add_params_rand_bytes=${True}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept CA Certificate Request With XMSS KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a CA XMSS private key is allowed to have
    ...                key usages: keyCertSign, digitalSignature, nonRepudiation, cRLSign. We send a valid `ir`
    ...                PKIMessage to the CA with these key usages and expect it to issue a valid certificate.
    [Tags]             positive    xmss  extensions  key_usage
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    True    critical=True
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign, digitalSignature, nonRepudiation, cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA Reject A Valid XMSS EE Request With keyCertSign KeyUsage
    [Documentation]    According to RFC 9802 Section 6 a End-Entity XMSS private key is not
    ...                allowed to have key usages: keyCertSign. We send a valid `ir` PKIMessage to the CA with
    ...                this key usage and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    xmss  extensions  key_usage
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    False    critical=False
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign, digitalSignature, nonRepudiation, cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Rejected    ${response}    ip    badCertTemplate

CA MUST Reject A Exhausted XMSS Private Key
    [Documentation]    According to RFC 8391 and RFC 9802 a XMSS-SHA2_10_256 private key
    ...                must track its state and reject requests when the key is exhausted, the easiest way
    ...                to track this, is by using the key by index. We send `ir` PKIMessage with an exhausted
    ...                key. The CA MUST reject the reject the request and may respond with a `failInfo`
    ...                `badPOP` and/or `badCertTemplate`.
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${key}=    Modify PQ Stateful Sig Private Key    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badCertTemplate   False

CA MUST Reject A XMSS-SHA2_10_512 Key
    [Documentation]    According to the NIST SP 800-208 Section 5.1 footnote 5: SHAKE128, SHAKE256, and SHA-512 are
    ...                not approved for use by this Special Publication. We send a valid `ir` PKIMessage to the CA
    ...                with a XMSS-SHA2_10_512 key and expect it to reject the request.
    ${key}=     Generate Unique Key    xmss-sha2_10_512
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Issue A Valid XMSSMT Certificate
    [Documentation]    According to RFC 8391 and RFC 9802 a XMSSMT-SHA2_20/2_256 private key
    ...                is a valid stateful signature algorithm. We send a valid `ir` PKIMessage to the CA
    ...                and expect it to issue a valid certificate.
    [Tags]    positive    xmssmt
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}    ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid XMSSMT EE Certificate With KeyUsages
    [Documentation]    According to RFC 8391 and RFC 9802 the CA MUST correctly process
    ...                extensions for XMSSMT certificates. We request an end-entity certificate with KeyUsage
    ...                bits set and expect successful issuance.
    [Tags]    positive    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extensions}=    Prepare Extensions    digitalSignature,nonRepudiation,cRLSign
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA MUST Reject Invalid XMSSMT Public Key Size
    [Documentation]    According to RFC 8391 an invalid XMSSMT public key MUST lead to rejection.
    ...                The XMSSMT-SHA2_20/2_256 public key must have a key size of 4 bytes + 2*n bytes,
    ...                where n is the number of bytes in the hash output. For SHA-256, this means the key size
    ...                must be 68 bytes. We send a valid `ir` PKIMessage to the CA with an invalid key size
    ...                and expect it to reject the request.
    [Tags]    negative    xmssmt    invalid_key_size
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    invalid_key_size=${True}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Invalid XMSSMT Request With Parameters Set
    [Documentation]   According to RFC 9802 Section 7, the XMSSMT AlgorithmIdentifier `parameters`
    ...                field must not be set. We send a valid `ir` PKIMessage to the CA with the `parameters` field
    ...                set to random bytes and expect the CA to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]    negative    xmssmt    alg_id_parameters
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    add_params_rand_bytes=${True}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept CA Certificate Request With XMSSMT KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a CA XMSSMT private key is allowed to have
    ...                key usages: keyCertSign, digitalSignature, nonRepudiation, cRLSign. We send a valid `ir`
    ...                PKIMessage to the CA with these key usages and expect it to issue a valid certificate.
    [Tags]    positive    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    True    critical=True
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign,digitalSignature,nonRepudiation,cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA MUST Reject A Valid XMSSMT EE Request With keyCertSign KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a End-Entity XMSSMT private key is not
    ...                allowed to have key usages: keyCertSign. We send a valid `ir` PKIMessage to the CA
    ...                with this key usage and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]    negative    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    False    critical=False
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign,digitalSignature,nonRepudiation,cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Rejected    ${response}    ip    badCertTemplate

CA MUST Reject A Exhausted XMSSMT Private Key
    [Documentation]    According to RFC 8391 and RFC 9802 a XMSSMT-SHA2_20/2_256 private key
    ...                must track its state and reject requests when the key is exhausted, the easiest way
    ...                to track this, is by using the key by index. We send `ir` PKIMessage with an exhausted
    ...                key. The CA MUST reject the reject the request and may respond with a `failInfo`
    ...                `badPOP` and/or `badCertTemplate`.
    [Tags]    negative    xmssmt    exhausted_key
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=   Get Next Common Name
    ${key}=   Modify PQ Stateful Sig Private Key    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badCertTemplate   False

CA MUST Issue A Valid HSS Certificate
    [Documentation]    According to RFC 8554 and RFC 9802 an HSS private key with LMS/LMOTS parameters
    ...                is a valid stateful signature algorithm. We send a valid `ir` PKIMessage to the CA
    ...                and expect it to issue a valid certificate using the default HSS algorithm.
    [Tags]             positive    hss
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid HSS EE Certificate With KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a End-Entity HSS private key is allowed to
    ...                have key usages: digitalSignature, nonRepudiation, cRLSign. We send a valid `ir` PKIMessage to
    ...                the CA and expect it to issue a valid certificate with these key usages.
    [Tags]             positive    hss  extensions  key_usage
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${extensions}=    Prepare Extensions    digitalSignature, nonRepudiation, cRLSign
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA MUST Reject Invalid HSS Public Key Size
    [Documentation]    According to RFC 8554 and RFC 9802 an HSS public key must have a specific
    ...                size based on the LMS parameters. We send a valid `ir` PKIMessage to the CA with an
    ...                invalid key size and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    hss   invalid_key_size
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    invalid_key_size=${True}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Invalid HSS Request With Parameters Set
    [Documentation]    According to RFC 9802 Section 7, the HSS AlgorithmIdentifier `parameters`
    ...                field must not be set. We send a valid `ir` PKIMessage to the CA with the `parameters` field
    ...                set to random bytes and expect the CA to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    hss   alg_id_parameters
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    add_params_rand_bytes=${True}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept CA Certificate Request With HSS KeyUsages
    [Documentation]    According to RFC 9802 Section 6 a CA HSS private key is allowed to have
    ...                key usages: keyCertSign, digitalSignature, nonRepudiation, cRLSign. We send a valid `ir`
    ...                PKIMessage to the CA with these key usages and expect it to issue a valid certificate.
    [Tags]             positive    hss  extensions  key_usage
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    True    critical=True
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign, digitalSignature, nonRepudiation, cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Accepted    ${response}

CA MUST Reject A Valid HSS EE Request With keyCertSign KeyUsage
    [Documentation]    According to RFC 9802 Section 6 a End-Entity HSS private key is not
    ...                allowed to have key usages: keyCertSign. We send a valid `ir` PKIMessage to the CA with
    ...                this key usage and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    hss  extensions  key_usage
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    False    critical=False
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign, digitalSignature, nonRepudiation, cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    VAR  &{params}    spki=${spki}    extensions=${extensions}
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key}    ${cm}    ${params}
    Check PKIMessage Rejected    ${response}    ip    badCertTemplate

CA MUST Reject A Exhausted HSS Private Key
    [Documentation]    According to RFC 8554 and RFC 9802 an HSS private key must track its state
    ...                and reject requests when the key is exhausted. We send `ir` PKIMessage with an exhausted
    ...                key. The CA MUST reject the request and may respond with a `failInfo`
    ...                `badPOP`.
    [Tags]             negative    hss   exhausted_key
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${cm}=   Get Next Common Name
    ${cert_request}=    Prepare CertRequest    key=${key}   common_name=${cm}
    ${der_data}=   Encode To DER   ${cert_request}
    ${signature}=     Sign Data   ${der_data}    ${key}
    ${mod_sig}=    Manipulate PQ Stateful Signature Bytes   ${signature}    ${key}   manipulate_sig=${False}
    ${popo}=     Prepare Signature POPO   ${key}    signature=${mod_sig}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID    popo=${popo}    cert_request=${cert_request}
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    Check PKIMessage Rejected   ${response}    ip    badPOP

CA MUST Issue HSS Certificate With Multiple Hierarchy Levels
    [Documentation]    According to RFC 8554 HSS supports multi-level hierarchies. We send a valid
    ...                `ir` PKIMessage to the CA with an HSS key configured for multiple levels and expect
    ...                it to issue a valid certificate.
    [Tags]             positive    hss   multi_level
    ${key}=     Generate Unique Key    ${HSS_DEFAULT_ALG}   levels=3
    ${cm}=   Get Next Common Name
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    ${cert}=   Check PKIMessage Accepted   ${response}    ip
    ${pub_key}=    Load Public Key From Cert    ${cert}
    Should Be Equal As Integers   ${pub_key.levels}    3

CA MUST Accept Request with HSS Key used same LMS index But diff key index
    [Documentation]    According to RFC 8554 the LMS index and HSS key index are independent.
    ...                We send a valid `ir` PKIMessage protect with a HSS key with level 2 to the CA using the
    ...                same LMS index but different key indices and expect both requests to be accepted.
    [Tags]             positive    hss   lms_key_index    leaf_index
    ${key_sign}=     Generate Unique Key    hss_lms_sha256_m32_h5_lmots_sha256_n32_w8   levels=2
    ${cm}=   Get Next Common Name
    ${response}=    Build And Send PKIMessage PQ Stateful    ${key_sign}    ${cm}
    ${cert_chain}=    Build CMP Chain From PKIMessage    ${response}   for_issued_cert=True
    # One index is already used to establish the certificate, so only the other 31 keys are
    # are used up.
    FOR   ${_}    IN RANGE   31
        ${_}=     Sign Data   b"DATA"    ${key_sign}
    END
    ${cm2}=    Get Next Common Name
    ${key_new}=     Generate Unique Key    ${HSS_DEFAULT_ALG}
    ${ir}=      Build Ir From Key    ${key_new}   ${cm2}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Protect PKIMessage   ${ir}    signature    private_key=${key_sign}    cert_chain=${cert_chain}
    ${sig}=    Get Asn1 Value As Bytes    ${prot_ir}    protection
    ${index}=   Get PQ Stateful Sig Index From Sig   ${sig}    ${key_sign}   True
    # After 31 comes 0 again, the same as the index which is used to establish the certificate.
    Should Be Equal As Integers    ${index}    0
    ${response2}=    Exchange PKIMessage   ${prot_ir}
    Check PKIMessage Accepted    ${response2}


*** Keywords ***
Protect And Send PKIMessage PQ Stateful
    [Documentation]    Protects and send a PKIMessage which is protected for a PQ Stateful signature algorithm test.
    ...
    ...                A default protection mechanism is applied to the provided PKIMessage.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `pki_message`: The PKIMessage object to protect and send.
    ...
    ...                Returns:
    ...                -------
    ...                - The PKIMessage response from the CMP server.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response}= | Protect And Send PKIMessage PQ Stateful | ${pki_message} |
    ...
    [Tags]    exchange
    [Arguments]    ${pki_message}
    ${prot_pki_message}=    Default Protect PKIMessage    ${pki_message}
    ${response}=    Exchange PKIMessage    ${prot_pki_message}
    RETURN    ${response}

Build And Send PKIMessage PQ Stateful
    [Documentation]    Build and send a protected PKIMessage for PQ Stateful signature tests.
    ...                This keyword constructs a PKIMessage using the provided key and subject (common name),
    ...                applies optional parameters from the options dictionary, protects the message,
    ...                and sends it to the CMP server for processing.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `key`: The private key object used for certificate issuance.
    ...                - `cm`: The subject's common name or identifier.
    ...
    ...                `params`: Dictionary of optional parameters:
    ...                --------
    ...                - `spki`: SubjectPublicKeyInfo. Defaults to `None` (will be generated from the key).
    ...                - `exclude_fields`: Fields to exclude from the PKIMessage. Defaults to `sender,senderKID`.
    ...                - `extensions`: Certificate extensions. Defaults to `None`.
    ...
    ...                Returns:
    ...                -------
    ...                - The PKIMessage response from the CMP server.
    ...
    ...                Examples:
    ...                --------
    ...                | ${response}= | Build And Send PKIMessage PQ Stateful | ${key} | ${cm} | ${params} |
    ...
    [Tags]    ir
    [Arguments]    ${key}    ${cm}    ${params}=${None}
    # Set default values if params is not provided
    IF   $params is None
        VAR    &{params}   # robocop: off=VAR01
    END
    ${spki}=    Get From Dictionary    ${params}    spki    default=${None}
    ${exclude_fields}=    Get From Dictionary    ${params}    exclude_fields    default=sender,senderKID
    ${extensions}=    Get From Dictionary    ${params}    extensions    default=${None}
    ${implicit_confirm}=    Get From Dictionary    ${params}    implicit_confirm    default=${True}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...    sender=${SENDER}    recipient=${RECIPIENT}    exclude_fields=${exclude_fields}
    ...    extensions=${extensions}    implicit_confirm=${implicit_confirm}
    ${response}=    Protect And Send PKIMessage PQ Stateful   ${ir}
    RETURN    ${response}

Check PKIMessage Accepted
    [Documentation]    Verifies that a PKIMessage response is accepted and contains a valid certificate.
    ...
    ...                Checks that the response has a PKIStatus of 'accepted',
    ...                contains the expected PKIBody type, and that the included certificate is valid.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The PKIMessage response object to check.
    ...                - `expected_pkibody`: The expected PKIBody type. Defaults to 'ip' (initialization response).
    ...
    ...                Returns:
    ...                ------------
    ...                - The valid certificate extracted from the PKIMessage.
    ...
    ...                Examples:
    ...                --------
    ...                | Check PKIMessage Accepted | ${response} |
    ...                | Check PKIMessage Accepted | ${response} | cp |
    ...
    [Arguments]    ${response}    ${expected_pkibody}=ip
    PKIMessage Body Type Must Be    ${response}    ${expected_pkibody}
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}
    RETURN    ${cert}

Check PKIMessage Rejected
    [Documentation]    Verifies that a PKIMessage response is correctly rejected.
    ...
    ...                Checks that the response has a PKIStatus of 'rejection',
    ...                contains the expected PKIBody type, and the expected failinfo.
    ...
    ...                Arguments:
    ...                ---------
    ...                - `response`: The PKIMessage response object to check.
    ...                - `expected_pkibody`: The expected PKIBody type (e.g., 'ip', 'error').
    ...                - `failinfo`: The expected failinfo value (e.g., badCertTemplate).
    ...
    ...                Examples:
    ...                --------
    ...                | Check PKIMessage Rejected | ${response} | ip | badCertTemplate |
    ...
    [Arguments]    ${response}    ${expected_pkibody}    ${failinfo}
    PKIMessage Body Type Must Be    ${response}    ${expected_pkibody}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    ${failinfo}
