# SPDX-FileCopyrightText: Copyright 2025 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation    Test cases for XMSS and XMSSMT stateful hash-based signature algorithms,
...              based on RFC 8391 and the draft-ietf-lamps-x509-shbs document.
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

Suite Setup         Set Up Test Suite
Test Tags           pq-stateful-sig   pqc  pq-sig


*** Test Cases ***
# TODO fix reference if the draft is published (currently in the RFC Editor queue)
CA MUST Issue A Valid XMSS Certificate
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs a XMSS-SHA2_10_256 private key
    ...                is a valid stateful signature algorithm. We send a valid `ir` PKIMessage to the CA
    ...                and expect it to issue a valid certificate.
    [Tags]             positive    xmss
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid XMSS EE Certificate With KeyUsages
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 6 a End-Entity XMSS private key is allowed to
    ...                have key usages: digitalSignature, nonRepudiation, cRLSign. We send a valid `ir` PKIMessage to
    ...                the CA and expect it to issue a valid certificate with these key usages.
    [Tags]             positive    xmss  extensions  key_usage
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${extensions}=    Prepare Extensions    digitalSignature, nonRepudiation, cRLSign
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}   spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject Invalid XMSS Public Key Size
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs a XMSS-SHA2_10_256 public key
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
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Invalid XMSS Request With Parameters set
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 7, the XMSS AlgorithmIdentifier `parameters`
    ...                field must not be set. We send a valid `ir` PKIMessage to the CA with the `parameters` field
    ...                set to random bytes and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]             negative    xmss   alg_id_parameters
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    add_params_rand_bytes=${True}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept CA Certificate Request With XMSS KeyUsages
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 6 a CA XMSS private key is allowed to have
    ...                key usages: keyCertSign, digitalSignature, nonRepudiation, cRLSign. We send a valid `ir`
    ...                PKIMessage to the CA with these key usages and expect it to issue a valid certificate.
    [Tags]             positive    xmss  extensions  key_usage
    ${key}=     Generate Unique Key    xmss-sha2_10_256
    ${cm}=   Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    True    critical=True
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign, digitalSignature, nonRepudiation, cRLSign
    VAR  @{extensions}    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}   spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ...         extensions=${extensions}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA Reject A Valid XMSS EE Request With keyCertSign KeyUsage
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 6 a End-Entity XMSS private key is not
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
    ${ir}=      Build Ir From Key    ${key}   ${cm}   spki=${spki}
    ...         sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ...         extensions=${extensions}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject A Exhausted XMSS Private Key
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs a XMSS-SHA2_10_256 private key
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
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
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
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Issue A Valid XMSSMT Certificate
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs a XMSSMT-SHA2_20/2_256 private key
    ...                is a valid stateful signature algorithm. We send a valid `ir` PKIMessage to the CA
    ...                and expect it to issue a valid certificate.
    [Tags]    positive    xmssmt
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}    ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Issue A Valid XMSSMT EE Certificate With KeyUsages
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs the CA MUST correctly process
    ...                extensions for XMSSMT certificates. We request an end-entity certificate with KeyUsage
    ...                bits set and expect successful issuance.
    [Tags]    positive    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extensions}=    Prepare Extensions    digitalSignature,nonRepudiation,cRLSign
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ...       extensions=${extensions}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

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
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Invalid XMSSMT Request With Parameters Set
    [Documentation]   According to draft-ietf-lamps-x509-shbs Section 7, the XMSSMT AlgorithmIdentifier `parameters`
    ...                field must not be set. We send a valid `ir` PKIMessage to the CA with the `parameters` field
    ...                set to random bytes and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]    negative    xmssmt    alg_id_parameters
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}    add_params_rand_bytes=${True}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Accept CA Certificate Request With XMSSMT KeyUsages
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 6 a CA XMSSMT private key is allowed to have
    ...                key usages: keyCertSign, digitalSignature, nonRepudiation, cRLSign. We send a valid `ir`
    ...                PKIMessage to the CA with these key usages and expect it to issue a valid certificate.
    [Tags]    positive    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    True    critical=True
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign,digitalSignature,nonRepudiation,cRLSign
    @{extensions}=    Create List    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ...       extensions=${extensions}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Certificate Must Be Valid    ${cert}

CA MUST Reject A Valid XMSSMT EE Request With keyCertSign KeyUsages
    [Documentation]    According to draft-ietf-lamps-x509-shbs Section 6 a End-Entity XMSSMT private key is not
    ...                allowed to have key usages: keyCertSign. We send a valid `ir` PKIMessage to the CA
    ...                with this key usage and expect it to reject the request. The CA may respond with the
    ...                `failInfo` `badCertTemplate`.
    [Tags]    negative    xmssmt    extensions    key_usage
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=    Get Next Common Name
    ${extension}=    Prepare BasicConstraints Extension    False    critical=False
    ${extension2}=    Prepare KeyUsage Extension    keyCertSign,digitalSignature,nonRepudiation,cRLSign
    @{extensions}=    Create List    ${extension}    ${extension2}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${ir}=    Build Ir From Key    ${key}    ${cm}    spki=${spki}
    ...       sender=${SENDER}    recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ...       extensions=${extensions}
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject A Exhausted XMSSMT Private Key
    [Documentation]    According to RFC 8391 and draft-ietf-lamps-x509-shbs a XMSSMT-SHA2_20/2_256 private key
    ...                must track its state and reject requests when the key is exhausted, the easiest way
    ...                to track this, is by using the key by index. We send `ir` PKIMessage with an exhausted
    ...                key. The CA MUST reject the reject the request and may respond with a `failInfo`
    ...                `badPOP` and/or `badCertTemplate`.
    ${key}=    Generate Unique Key    xmssmt-sha2_20/2_256
    ${cm}=   Get Next Common Name
    ${key}=   Modify PQ Stateful Sig Private Key    ${key}
    ${ir}=      Build Ir From Key    ${key}   ${cm}    sender=${SENDER}    recipient=${RECIPIENT}
    ...         exclude_fields=sender,senderKID
    ${prot_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage PQ Stateful    ${prot_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badCertTemplate   False
