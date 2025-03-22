# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/keyutils.py
Library             ../resources/cmputils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/general_msg_utils.py
Library             ../resources/ca_kga_logic.py


*** Variables ***
# normally this would be provided from the command line
${environment}      cloudpki


*** Test Cases ***
###### 5. PKI Management Entity Operations

#### 5.2. Forwarding Messages

### 5.2.2 Adding Protection and Batching of Messages

## 5.2.2.1 Adding Protection to a Request Message

CA MUST Reject Added Protection PKIMessage Without Copied senderNonce
    [Documentation]    According to RFC 9483 Section 5.2.2.1, when a PKI management entity wraps its protection around
    ...    a request in a nested message, it MUST copy the `senderNonce` and `transactionID` from the
    ...    original message into the header of the nested message. We send a nested PKIMessage where the
    ...    `senderNonce` is not copied but the `transactionID` is. The CA MUST detect the invalid
    ...    `senderNonce` and reject the request, possibly responding with the failinfo `badSenderNonce`.
    [Tags]    adding-protection    header    negative    nested
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If   not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${protected_ir}=    Generate Default IR Sig Protected
    ${transaction_id}=    Get Asn1 Value As Bytes    ${protected_ir}    header.transactionID
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${protected_ir}    header.senderNonce
    ${sender_nonce}=    Manipulate First Byte    ${sender_nonce}
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    # Response must be a single message.
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce    exclusive=True

CA MUST Reject Added Protection PKIMessage Without Copied transactionID
    [Documentation]    According to RFC 9483 Section 5.2.2.1, when a PKI management entity wraps its protection around
    ...    a request in a nested message, it MUST copy the `senderNonce` and `transactionID` from the
    ...    original message into the header of the nested message. We send a nested PKIMessage where the
    ...    `transactionID` is not copied but the `senderNonce` is. The CA MUST detect the invalid
    ...    `transactionID` and reject the request, possibly responding with the failinfo `badSenderNonce`.
    [Tags]    adding-protection    header    negative    nested
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${protected_ir}=    Generate Default IR Sig Protected
    ${transaction_id}=    Get Asn1 Value As Bytes    ${protected_ir}    header.transactionID
    ${transaction_id}=    Manipulate First Byte    ${transaction_id}
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${protected_ir}    header.senderNonce
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True    

CA MUST Reject Nested PKIMessage With Mismatched Protection
    [Documentation]    According to RFC 9483 Section 5.2.2.1, when a PKI management entity wraps its protection around
    ...    a request in a nested message, it MUST copy the `senderNonce` and `transactionID` into the
    ...    header and use signature-based protection. We send a nested PKIMessage that correctly copies
    ...    both values but applies MAC-based protection instead. The CA MUST detect this and reject the
    ...    request, possibly responding with the failinfo `wrongIntegrity` or `badRequest`.
    [Tags]    adding-protection    header    mac    negative    nested
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped because MAC Protected Messages are not allowed.
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${protected_ir}=    Generate Default IR Sig Protected
    ${transaction_id}=    Get Asn1 Value As Bytes    ${protected_ir}    header.transactionID
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${protected_ir}    header.senderNonce
    ${nested}=    Build Nested PKIMessage
    ...    exclude_fields=${None}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=wrongIntegrity,badRequest    exclusive=True    

CA MUST Accept Valid Added Protection To PKIMessage
    [Documentation]    According to RFC 9483 Section 5.2.2.1, when a PKI management entity wraps its protection around
    ...    a request in a nested message, it MUST copy the `senderNonce` and `transactionID` into the
    ...    header and use signature-based protection. We send a nested PKIMessage that correctly copies
    ...    both `senderNonce` and `transactionID` and applies signature-based protection. The CA MUST
    ...    process the request and issue a certificate.
    [Tags]    adding-protection    nested    positive
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${protected_ir}=    Generate Default IR Sig Protected
    ${transaction_id}=    Get Asn1 Value As Bytes    ${protected_ir}    header.transactionID
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${protected_ir}    header.senderNonce
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    # Response must be a single message.
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Answer To Valid MAC Based Protected Added Protection with MAC Based Protection
    [Documentation]    According to RFC 9483 Section 5.2.2.1, when a PKI management entity wraps its protection around
    ...    a request in a nested message, it MUST copy the `senderNonce` and `transactionID` into the
    ...    header and use signature-based protection. If the wrapped message is MAC-protected, then the
    ...    CA MUST also respond with MAC-based protection. We send a nested PKIMessage that correctly
    ...    copies both `senderNonce` and `transactionID` and applies MAC-based protection. The CA MUST
    ...    process the request and issue a certificate.
    [Tags]    adding-protection    mac    nested    positive
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${pki_message}=    Generate Default MAC Protected PKIMessage
    ${transaction_id}=    Get Asn1 Value As Bytes    ${pki_message}    header.transactionID
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${pki_message}    header.senderNonce
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    sender_nonce=${sender_nonce}
    ...    transaction_id=${transaction_id}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIStatus Must Be   ${response}    status=accepted
    ${protection_type}=    Get Protection Type From PKIMessage    ${response}    lwcmp=${LWCMP}
    IF    '${protection_type}' != 'mac'
        Fail    The response to the wrapped protected message was not MAC-based protected.
    END

## Section 5.2.2.2. Batching Messages

# TODO move to basic

CA MUST Accept Valid Nested Batch Message
    [Documentation]    According to RFC 9483 Section 5.2.2.2, a PKI management entity generating a nested message must
    ...    include fresh `transactionID` and `senderNonce` in the header. We send a nested batch message
    ...    with unique `senderNonce`s and `transactionID`s for each request. If batch processing is allowed,
    ...    the CA MUST process the batch and respond appropriately. Otherwise, the CA MUST reject the
    ...    request, possibly responding with `badSenderNonce` or `badRequest`.
    [Tags]    batching    nested    positive
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    ${nonces}=    Generate Unique Byte Values    length=4
    ${ids}=    Generate Unique Byte Values    length=4
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${protected_ir1}=    Generate Default IR Sig Protected    transaction_id=${nonces[0]}    sender_nonce=${nonces[0]}
    ${protected_ir2}=    Generate Default IR Sig Protected    transaction_id=${nonces[1]}    sender_nonce=${nonces[1]}
    ${protected_ir3}=    Generate Default IR Sig Protected    transaction_id=${nonces[2]}    sender_nonce=${nonces[2]}
    VAR    @{msg_list}    ${protected_ir1}    ${protected_ir2}    ${protected_ir3}
    ${nested}=    Build Nested PKIMessage
    ...    other_messages=${msg_list}
    ...    recipient=${RECIPIENT}
    ...    sender_nonce=${nonces[3]}
    ...    transaction_id=${ids[3]}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    nested
    Validate Ids And Nonces For Nested Response    response=${response}    request=${prot_nested}

CA MUST Check If The Nested Batch Message Has A Unique transactionID
    [Documentation]    According to RFC 9483 Section 5.2.2.2, a PKI management entity generating a nested message must
    ...    use a fresh`transactionID` and `senderNonce` in the header. We send a nested batch message
    ...    where the `transactionID` of the third request is duplicated. The CA MUST reject the request,
    ...    potentially responding with the `failinfo` `transactionIdInUse` or `badRequest`.
    [Tags]    batching    header    negative    nested
    
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${nonces}=    Generate Unique Byte Values    length=4
    ${ids}=    Generate Unique Byte Values    length=3
    ${protected_ir1}=    Generate Default IR Sig Protected    transaction_id=${nonces[0]}    sender_nonce=${nonces[0]}
    ${protected_ir2}=    Generate Default IR Sig Protected    transaction_id=${nonces[1]}    sender_nonce=${nonces[1]}
    ${protected_ir3}=    Generate Default IR Sig Protected    transaction_id=${nonces[2]}    sender_nonce=${nonces[2]}
    VAR    @{msg_list}    ${protected_ir1}    ${protected_ir2}    ${protected_ir3}
    ${nested}=    Build Nested PKIMessage
    ...    other_messages=${msg_list}
    ...    recipient=${RECIPIENT}
    ...    sender_nonce=${nonces[3]}
    ...    transaction_id=${ids[2]}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=transactionIdInUse,badRequest    exclusive=True


CA MUST Check If The Nested Batch Message Has A Unique senderNonce
    [Documentation]    According to RFC 9483 Section 5.2.2.2, a PKI management entity generating a nested message must
    ...    use fresh a `transactionID` and `senderNonce` in the header. We send a nested batch message
    ...    where the `senderNonce` of the third request is duplicated. The CA MUST reject the request,
    ...    potentially responding with the `failinfo` `badSenderNonce` or `badRequest`.
    [Tags]    batching    header    negative    nested
    
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${nonces}=    Generate Unique Byte Values    length=3
    ${ids}=    Generate Unique Byte Values    length=4
    ${protected_ir1}=    Generate Default IR Sig Protected    transaction_id=${nonces[0]}    sender_nonce=${nonces[0]}
    ${protected_ir2}=    Generate Default IR Sig Protected    transaction_id=${nonces[1]}    sender_nonce=${nonces[1]}
    ${protected_ir3}=    Generate Default IR Sig Protected    transaction_id=${nonces[2]}    sender_nonce=${nonces[2]}
    VAR    @{msg_list}    ${protected_ir1}    ${protected_ir2}    ${protected_ir3}
    ${nested}=    Build Nested PKIMessage
    ...    other_messages=${msg_list}
    ...    recipient=${RECIPIENT}
    ...    sender_nonce=${nonces[2]}
    ...    transaction_id=${ids[3]}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce,badRequest    exclusive=True

CA MUST Check The Protection Of All Inner Messages
    [Documentation]    According to RFC 9483 Section 5.2.2.2, the protection of nested messages MUST NOT indicate
    ...    verification or approval of the bundled PKI requests. We send a nested message with three
    ...    requests, where the third request has an incorrect protection value. The CA MUST reject
    ...    the request, potentially responding with the `failinfo` `badMessageCheck`.
    [Tags]    batching    negative    nested    protection
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${nonces}=    Generate Unique Byte Values    length=4
    ${ids}=    Generate Unique Byte Values    length=4
    ${protected_ir1}=    Generate Default IR Sig Protected    transaction_id=${nonces[0]}    sender_nonce=${nonces[0]}
    ${protected_ir2}=    Generate Default IR Sig Protected    transaction_id=${nonces[1]}    sender_nonce=${nonces[1]}
    ${protected_ir3}=    Generate Default IR Sig Protected    transaction_id=${nonces[2]}    sender_nonce=${nonces[2]}
    ${protected_ir3}=    Modify PKIMessage Protection    ${protected_ir3}
    VAR    @{msg_list}    ${protected_ir1}    ${protected_ir2}    ${protected_ir3}
    ${nested}=    Build Nested PKIMessage
    ...    other_messages=${msg_list}
    ...    recipient=${RECIPIENT}
    ...    sender_nonce=${nonces[3]}
    ...    transaction_id=${ids[3]}
    ${prot_nested}=    Protect PKIMessage
    ...    ${nested}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${prot_nested}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

### Section 5.2.3 Replacing Protection

# According to Section 5.2.3, when an intermediate PKI management entity modifies a message,
# it MUST NOT change the transactionID, the senderNonce, or the recipNonce,
# except for the exception related to the recipNonce specified in Section 5.1.5.
# However, this restriction is not relevant for the CA (Certification Authority) or RA (Registration Authority).
# Instead, it is the responsibility of the Intermediate PKI Entity and the End Entity to ensure compliance.

## Section 5.2.3.2 Using raVerified

# TODO implement.
# CA MUST Reject Local Key Gen with badPOP From Trusted PKI with raVerified
#    [Documentation]    As of Section 5.2.3, message adaptations MUST NOT be applied
#    ...    to certificate request messages for central key generation.
#    ...    The original protection must be preserved for KGA, which will use it
#    ...    to encrypt the new private key for the EE.
#    Skip    This test depends on specific infrastructure setup and must be configured manually by the user.

# TODO implement.
# CA MUST Accept Local Key Gen From Trusted PKI with nested Protection

## Section 5.2.3.1 Not Changing Proof-of-Possession
# Omitted because it does not add logic to the CA or RA components, and it
# only ensures that Other PKI Entity and EE are correctly handling the senderNonce,
# transactionID, and recipNonce fields. For CA and RA components, they are handled the same way.

## Section 5.2.3.2 Using raVerified

CA MUST Accept IR From Trusted PKI With raVerified
    [Documentation]    According to RFC 9483 Section 5.2.3.2, if a PKI management entity modifies the certificate
    ...    template inside the initialization request (e.g., by adding, modifying, or removing fields),
    ...    it MUST verify the proof-of-possession (pop) using the original public key. If successful, it
    ...    sets the pop to `raVerified`. We send a valid initialization request message without
    ...    a proof-of-possession value, but with `raVerified` set. The CA MUST trust the PKI entity and
    ...    issue a valid certificate.
    [Tags]    ir    positive    raVerified    trust
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key
    ...    cert_template=${cert_template}
    ...    signing_key=${key}
    ...    ra_verified=True
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Reject KUR With badPOP From Trusted PKI With raVerified
    [Documentation]    According to RFC 9483 Section 5.2.3, `raVerified` is not allowed to be used in a key update
    ...    request because the original protection using the key and certificate to be updated must
    ...    be preserved. We send a key update request with `raVerified` set. The CA MUST reject the
    ...    request and may respond with the optional failinfo `badPOP` or `badRequest`.
    [Tags]    kur    negative    raVerified    trust
    ${is_set}=    Is Certificate And Key Set    ${OTHER_TRUSTED_PKI_CERT}    ${OTHER_TRUSTED_PKI_KEY}
    Skip If    not ${is_set}    Skipped because `OTHER_TRUSTED_PKI_KEY` and/or `OTHER_TRUSTED_PKI_CERT` are not set.
    ${kur}=    Build Key Update Request
    ...    cert=${REPLACE_}
    ...    signing_key=${key}
    ...    ra_verified=True
    ...    recipient=${RECIPIENT}
    ${protected_kur}=    Protect PKIMessage
    ...    ${kur}
    ...    protection=signature
    ...    private_key=${OTHER_TRUSTED_PKI_KEY}
    ...    cert=${OTHER_TRUSTED_PKI_CERT}
    ${response}=    Exchange PKIMessage    ${protected_kur}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP,badRequest   exclusive=True

### Section 5.3. Acting on Behalf of Other PKI Entities

## Section 5.3.1 Requesting a Certificate
# Out of scope for this test suite. However, a user may add checks for the local EE
# subject name against the PKI policy or other policy checks.
