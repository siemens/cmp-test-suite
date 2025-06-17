# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Tests specifically for the lightweight CMP profile

Resource            ../config/${environment}.robot
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
Library             ../resources/certextractutils.py

Suite Setup    Set Up LWCMP
Test Tags    rfc9483-validation  rfc9483-header  verbose-tests  verbose-pkiheader


*** Variables ***
${RE_USE_RR}    False
${RE_USE_KUR}    False
${RE_USE_P10cr}   False
${RE_USE_CCR}    False
${RE_USE_IR}    False
${RE_USE_CR}    False


*** Keywords ***
Set Up LWCMP
    [Documentation]    Set up the test environment for LwCMP tests
    Set Up Test Suite
    ${is_file}=    Run Keyword And Return Status    OperatingSystem.File Should Exist    ${OTHER_TRUSTED_PKI_KEY}
    IF  ${is_file}
        ${der_cert}=    Load And Decode PEM File    ${OTHER_TRUSTED_PKI_CERT}
        ${cert}=   Parse Certificate    ${der_cert}
        ${key}=    Load Private Key From File   ${OTHER_TRUSTED_PKI_KEY}
        VAR    ${OTHER_TRUSTED_PKI_CERT}    ${cert}    scope=Global
        VAR    ${OTHER_TRUSTED_PKI_KEY}    ${key}    scope=Global
    END
    Set Up Test Suite
    VAR   ${INNER_CERT}    ${ISSUED_CERT}    scope=Global
    VAR   ${INNER_KEY}    ${ISSUED_KEY}    scope=Global
    IF  '${RA_CERT_CHAIN_PATH}' == '${None}'
        ${cert_chain}=   Build Cert Chain From Dir    ${OTHER_TRUSTED_PKI_CERT}   ${RA_CERT_CHAIN_DIR}
    ELSE
        ${cert_chain}=   Load Certificate Chain     ${RA_CERT_CHAIN_PATH}
    END
    VAR   ${RA_CERT_CHAIN}    ${cert_chain}    scope=Global
    TRY
        Set Up CRR Test Cases
    EXCEPT
        Log    Failed to setup the CCR required certificate and signing key.
    END

Default Build Inner IR Message
    [Documentation]    Build an inner IR message with the default signature protection
    [Arguments]    &{params}
    ${cert_template}   ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key  ${key}  cert_template=${cert_template}
    ...       recipient=${RECIPIENT}   &{params}
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    IF  ${use_mac}
        ${prot_body}=    Protect With MAC    ${ir}   &{params}
        RETURN    ${protected_ir}
    END

    ${ir}=    May Patch Message For Bad SIG Sender or SenderKID  ${ir}   ${INNER_CERT}   &{params}
    ${protected_ir}=    Protect PKIMessage    ${ir}    signature
    ...                 private_key=${INNER_KEY}    cert=${INNER_CERT}   &{params}
    RETURN    ${protected_ir}

Protect With Trusted PKI
    [Documentation]    Protect a PKIMessage with a trusted PKI
    [Arguments]    ${pki_message}   &{params}
    ${pki_message}=  May Patch Message For Bad SIG Sender or SenderKID  ${pki_message}   ${RA_CERT_CHAIN}[0]   &{params}
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    IF  ${use_mac}
        ${prot_msg}=    Protect PKIMessage    ${pki_message}    ${DEFAULT_MAC_ALGORITHM}
        ...                 password=${PRESHARED_SECRET}   bad_message_check=True
        RETURN    ${prot_msg}
    END
    ${prot_msg}=    Protect PKIMessage    ${pki_message}    signature
    ...                 private_key=${OTHER_TRUSTED_PKI_KEY}    cert_chain=${RA_CERT_CHAIN}
    ...                 &{params}
    RETURN    ${prot_msg}

Protect With Trusted CA
    [Documentation]    Protect a PKIMessage with a trusted CA.
    [Arguments]    ${pki_message}   &{params}
    ${pki_message}=  May Patch Message For Bad SIG Sender or SenderKID  ${pki_message}   ${RA_CERT_CHAIN}[0]   &{params}
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    IF  ${use_mac}
        ${prot_msg}=    Protect PKIMessage    ${pki_message}    ${DEFAULT_MAC_ALGORITHM}
        ...                 password=${PRESHARED_SECRET}   bad_message_check=True
        RETURN    ${prot_msg}
    END
    ${prot_msg}=    Protect PKIMessage    ${pki_message}    signature
    ...                 private_key=${TRUSTED_CA_KEY_OBJ}    cert_chain=${TRUSTED_CA_CERT_CHAIN}
    ...                 &{params}
    RETURN    ${prot_msg}

Build Fresh Inner Body
    [Documentation]    Build a fresh inner body with the default signature protection
    [Arguments]    ${inner_name}   &{params}
    IF  '${inner_name}' == 'ir'
        ${cert_template}   ${key}=    Generate CertTemplate For Testing
        ${ir}=   Build Cr From Key    ${key}   cert_template=${cert_template}
        ...             recipient=${RECIPIENT}   &{params}
        ${protected}=    Default Protect For Build Body    ${ir}   &{params}
    ELSE IF   '${inner_name}' == 'cr'
        ${cert_template}   ${key}=    Generate CertTemplate For Testing
        ${ir}=   Build Cr From Key    ${key}   cert_template=${cert_template}
        ...             recipient=${RECIPIENT}   &{params}
        ${protected}=    Default Protect For Build Body    ${ir}   &{params}
    ELSE IF   '${inner_name}' == 'kur'
        ${cert}   ${key}=    Issue New Cert For Testing
        ${cert_template}   ${new_key}=    Generate CertTemplate For Testing
        ${ir}=    Build Key Update Request   ${new_key}  cert_template=${cert_template}
        ...       recipient=${RECIPIENT}   &{params}
        ${protected}=    Default Protect For Build Body RR OR KUR   ${ir}   ${cert}   ${key}   &{params}
    ELSE IF   '${inner_name}' == 'p10cr'
        ${cm}=  Get Next Common Name
        ${key}=  Generate Default Key
        ${ir}=   Build P10cr From Key   ${key}   recipient=${RECIPIENT}   common_name=${cm}
        ...             &{params}
        ${protected}=    Default Protect For Build Body    ${ir}   &{params}
    ELSE IF   '${inner_name}' == 'ccr'
        ${cert_template}   ${key}=    Generate CCR CertTemplate For Testing
        ${ir}=   Build Ccr From Key     ${key}   cert_template=${cert_template}
        ...             recipient=${RECIPIENT}   &{params}
        ${protected}=    Protect With Trusted CA     ${ir}   &{params}
    ELSE
        Fail    Unknown inner name: ${inner_name}
    END
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    IF  ${use_mac}
        ${protected}=    Protect With MAC    ${protected}   &{params}
    END
    ${set_mac_alg}=   Get From Dictionary    ${params}   set_mac_algorithm  ${False}
    IF  ${set_mac_alg}
        ${protected}=  Patch ProtectionAlg    ${protected}    protection=${DEFAULT_MAC_ALGORITHM}
    END
    RETURN    ${protected}

Build Added Protection Body Inner
    [Documentation]    Build a PKIMessage with added protection
    [Arguments]    ${name}   ${exclude_fields}   &{params}
    VAR    ${empty_data}
    ${inner_name}=   Replace String    ${name}    added-protection-inner-   ${empty_data}
    ${protected_ir}=    Build Fresh Inner Body  ${inner_name}   exclude_fields=${exclude_fields}   &{params}
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    for_added_protection=True
    ${prot_body}=    Protect With Trusted PKI   ${nested}
    RETURN    ${prot_body}

Build Added Protection Body
    [Documentation]    Build a PKIMessage with added protection
    [Arguments]    ${exclude_fields}   &{params}
    ${protected_ir}=    Default Build Inner IR Message
    ${nested}=    Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_ir}
    ...    for_added_protection=True
    ...    exclude_fields=${exclude_fields}
    ...    &{params}
    ${prot_body}=    Protect With Trusted PKI   ${nested}   &{params}
    ${without_cert_chain}=   Get From Dictionary    ${params}   without_cert_chain  ${False}
    IF   ${without_cert_chain}
        ${prot_body}=  Patch For Without CertChain    ${prot_body}  ${OTHER_TRUSTED_PKI_CERT}
    END
    RETURN    ${prot_body}

Build Batch Body Inner
    [Documentation]    Generate a unprotected nested PKIMessage with the given sender nonces and ids.
    ...
    ...            Returns:
    ...             - a nested PKIMessage with the IR messages (unprotected or protected).
    [Tags]    loop    nested
    [Arguments]    ${name}   ${exclude_fields}   &{params}
    ${nonces}=    Generate Unique Byte Values    length=4
    ${ids}=    Generate Unique Byte Values    length=4
    VAR   @{protected_irs}
    FOR    ${i}    IN RANGE    2
        ${protected_ir}=    Default Build Inner IR Message    transaction_id=${ids}[${i}]
        ...                 sender_nonce=${nonces}[${i}]
        Append To List    ${protected_irs}    ${protected_ir}
    END
    # To ensure that this test always works, we need to set the sender nonce
    # and transaction id, which are now unique for each message.
    ${tx_id}=   Get From Dictionary    ${params}   transaction_id   ${ids}[2]
    ${sender_nonce}=   Get From Dictionary    ${params}   sender_nonce   ${nonces}[2]
    Set To Dictionary    ${params}   transaction_id=${tx_id}
    Set To Dictionary    ${params}   sender_nonce=${sender_nonce}
    VAR    ${empty_data}
    ${inner_name}=   Replace String    ${name}    batch_inner_   ${empty_data}
    ${prot_ir3}=    Build Fresh Inner Body  ${inner_name}   exclude_fields=${exclude_fields}   &{params}
    Append To List    ${protected_irs}   ${prot_ir3}
    ${nested}=  Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_irs}
    ...    sender_nonce=${nonces}[3]
    ...    transaction_id=${ids}[3]
    ...    exclude_fields=sender,senderKID
    ${prot_body}=    Protect With Trusted PKI   ${nested}
    RETURN   ${prot_body}

Build Batch Body
    [Documentation]    Generate a unprotected nested PKIMessage with the given sender nonces and ids.
    ...
    ...            Returns:
    ...             - a nested PKIMessage with the IR messages (unprotected or protected).
    [Tags]    loop    nested
    [Arguments]    ${exclude_fields}   &{params}
    ${nonces}=    Generate Unique Byte Values    length=4
    ${ids}=    Generate Unique Byte Values    length=4
    VAR   @{protected_irs}
    FOR    ${i}    IN RANGE    3
        ${protected_ir}=    Default Build Inner IR Message    transaction_id=${ids}[${i}]
        ...                 sender_nonce=${nonces}[${i}]
        Append To List    ${protected_irs}    ${protected_ir}
    END
    # To ensure that this test always works, we need to set the sender nonce
    # and transaction id, which are now unique for each message.
    ${tx_id}=   Get From Dictionary    ${params}   transaction_id   ${ids}[3]
    ${sender_nonce}=   Get From Dictionary    ${params}   sender_nonce   ${nonces}[3]
    Set To Dictionary    ${params}   transaction_id=${tx_id}
    Set To Dictionary    ${params}   sender_nonce=${sender_nonce}
    ${nested}=  Build Nested PKIMessage
    ...    recipient=${RECIPIENT}
    ...    other_messages=${protected_irs}
    ...    exclude_fields=${exclude_fields}
    ...    &{params}
    ${prot_body}=    Protect With Trusted PKI   ${nested}   &{params}
    ${without_cert_chain}=   Get From Dictionary    ${params}   without_cert_chain  ${False}
    IF   ${without_cert_chain}
        ${prot_body}=  Patch For Without CertChain    ${prot_body}  ${OTHER_TRUSTED_PKI_CERT}
    END
    RETURN   ${prot_body}

Patch For without CertChain
    [Documentation]    Patch the PKIMessage with the without cert chain
    [Arguments]    ${body}   ${cert}
    VAR   @{certs}   ${cert}
    ${body}=   Patch ExtraCerts    ${body}   ${certs}
    RETURN   ${body}

May Patch Message For Bad SIG Sender or SenderKID
    [Documentation]    Patch the PKIMessage for a bad sender or senderKID
    [Arguments]    ${body}   ${cert}   &{params}
    ${bad_ski}=   Get From Dictionary    ${params}   bad_ski  ${False}
    ${bad_sender}=   Get From Dictionary    ${params}   bad_sender  ${False}
    ${use_issuer}=   Get From Dictionary    ${params}   use_issuer  ${False}
    IF  ${bad_ski}
        ${body}=  Patch SenderKID    ${body}    ${cert}   negative=True
        ${body}=  Patch sender    ${body}    ${cert}   subject=True
    ELSE IF   ${use_issuer}
        ${body}=  Patch sender    ${body}    ${cert}   subject=False
        ${body}=  Patch SenderKID    ${body}    ${cert}
    ELSE IF   ${bad_sender}
        ${sender}=  Modify Common Name Cert    ${cert}  False
        ${body}=  Patch Sender    ${body}   sender_name=${sender}
        ${body}=  Patch SenderKID    ${body}    ${cert}
    END
    RETURN   ${body}

Protect With MAC
    [Documentation]    Protect a PKIMessage with a MAC algorithm.
    [Arguments]    ${pki_message}   &{params}
    ${bad_sender_kid}=  Get From Dictionary    ${params}   bad_sender_kid  ${False}
    ${bad_message_check}=  Get From Dictionary    ${params}   bad_message_check  ${False}
    IF  ${bad_sender_kid}
        ${sender}=   Get From Dictionary    ${params}   sender
        ${pki_message}=  Patch SenderKID    ${pki_message}    ${sender}   negative=True
    ELSE
        ${sender}=   Get From Dictionary    ${params}   sender
        ${pki_message}=  Patch SenderKID    ${pki_message}    ${ISSUED_CERT}
    END
    ${prot_body}=    Protect PKIMessage    ${pki_message}    ${DEFAULT_MAC_ALGORITHM}
    ...              password=${PRESHARED_SECRET}   bad_message_check=${bad_message_check}
    RETURN    ${prot_body}

Default Protect For Build Body
    [Documentation]    Default protection for a PKIMessage body.
    [Arguments]    ${body}   &{params}
    ${exclude_protection}=   Get From Dictionary    ${params}   exclude_protection  ${False}
    ${without_cert_chain}=   Get From Dictionary    ${params}   without_cert_chain  ${False}
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    ${set_mac_alg}=   Get From Dictionary    ${params}   set_mac_algorithm  ${False}
    IF  ${set_mac_alg}
        ${body}=  Patch ProtectionAlg    ${body}    protection=${DEFAULT_MAC_ALGORITHM}
        RETURN   ${body}
    END
    IF  ${exclude_protection}
        RETURN   ${body}
    END
    IF  ${use_mac}
        ${prot_body}=   Protect With MAC    ${body}   &{params}
        RETURN   ${prot_body}
    END
    ${body}=  May Patch Message For Bad SIG Sender or SenderKID  ${body}   ${ISSUED_CERT}   &{params}
    ${prot_body}=   Default Protect PKIMessage    ${body}   &{params}
    IF   ${without_cert_chain}
        ${prot_body}=  Patch For Without CertChain    ${prot_body}  ${ISSUED_CERT}
    END
    RETURN   ${prot_body}

Default Protect For Build Body RR OR KUR
    [Documentation]    Default protection for a PKIMessage body.
    [Arguments]    ${body}   ${cert}   ${sign_key}   &{params}
    ${exclude_protection}=   Get From Dictionary    ${params}   exclude_protection  ${False}
    ${without_cert_chain}=   Get From Dictionary    ${params}   without_cert_chain  ${False}
    IF  ${exclude_protection}
        RETURN   ${body}
    END
    ${use_mac}=   Get From Dictionary    ${params}   use_mac  ${False}
    IF  ${use_mac}
        ${prot_body}=   Protect With MAC    ${body}   &{params}
        RETURN   ${prot_body}
    END
    ${mod_body}=   May Patch Message For Bad SIG Sender or SenderKID  ${body}   ${cert}   &{params}
    ${do_patch}=   Get From Dictionary    ${params}   do_patch  ${True}
    ${prot_body}=   Protect PKIMessage  ${mod_body}   signature
    ...                 private_key=${sign_key}  cert=${cert}   &{params}
    IF   ${without_cert_chain}
        ${prot_body}=  Patch For Without CertChain    ${prot_body}  ${cert}
    END
    RETURN   ${prot_body}

Build Body By Name
    [Documentation]    Build a body by name
    [Arguments]    ${body_name}  ${exclude_fields}   &{params}
    ${without_cert_chain}=   Get From Dictionary    ${params}   without_cert_chain  ${False}
    ${exclude_protection}=   Get From Dictionary    ${params}   exclude_protection  ${False}
    IF   '${body_name}' == "cr"
        IF   '${RE_USE_CR}' == '${False}'
            ${cert_template}   ${key}=   Generate CertTemplate For Testing
            VAR   ${CR_TEMPLATE}    ${cert_template}    scope=Suite
            VAR   ${CR_KEY}    ${key}    scope=Suite
            VAR   ${RE_USE_CR}    False    scope=Suite
        END
        ${body}=   Build Cr From Key    ${CR_KEY}   cert_template=${CR_TEMPLATE}
        ...             exclude_fields=${exclude_fields}   recipient=${RECIPIENT}
        ...             &{params}
        ${prot_body}=    Default Protect For Build Body    ${body}   &{params}
    ELSE IF    '${body_name}' == "ir"
        IF   '${RE_USE_IR}' == '${False}'
            ${cert_template}   ${key}=   Generate CertTemplate For Testing
            VAR   ${IR_TEMPLATE}    ${cert_template}    scope=Suite
            VAR   ${IR_KEY}    ${key}    scope=Suite
            VAR   ${RE_USE_IR}    False    scope=Suite
        END
        ${body}=   Build Ir From Key    ${IR_KEY}   cert_template=${IR_TEMPLATE}
        ...             exclude_fields=${exclude_fields}   recipient=${RECIPIENT}
        ...             &{params}
        ${prot_body}=    Default Protect For Build Body    ${body}   &{params}
    ELSE IF    '${body_name}' == "ccr"
        IF   '${RE_USE_CCR}' == '${False}'
            ${cert_template}   ${key}=   Generate CCR CertTemplate For Testing
            VAR   ${CCR_TEMPLATE}    ${cert_template}    scope=Suite
            VAR   ${CCR_KEY}    ${key}    scope=Suite
            VAR   ${RE_USE_CCR}    False    scope=Suite
        END
        ${body}=   Build Ccr From Key    ${CCR_KEY}   cert_template=${CCR_TEMPLATE}
        ...             exclude_fields=${exclude_fields}   recipient=${RECIPIENT}
        ...             &{params}
        IF   ${exclude_protection}
            RETURN    ${body}
        END
        ${prot_body}=    Protect With Trusted CA    ${body}  &{params}
        IF   ${without_cert_chain}
            ${body}=  Patch For Without CertChain    ${body}  ${TRUSTED_CA_CERT_CHAIN}[0]
        END
    ELSE IF    '${body_name}' == "kur"
         IF   '${RE_USE_KUR}' == '${False}'
            ${cert}   ${key}=   Issue New Cert For Testing
            VAR   ${KUR_CERT}    ${cert}    scope=Suite
            VAR   ${KUR_KEY}    ${key}    scope=Suite
            ${cert_template}   ${new_key}=   Generate CertTemplate For Testing
            VAR   ${KUR_TEMPLATE}    ${cert_template}    scope=Suite
            VAR   ${KUR_NEW_KEY}    ${new_key}    scope=Suite
            VAR   ${RE_USE_KUR}    False    scope=Suite
        END
        ${body}=   Build Key Update Request   ${KUR_NEW_KEY}   cert_template=${KUR_TEMPLATE}
        ...        exclude_fields=${exclude_fields}   recipient=${RECIPIENT}
        ...        &{params}
        ${prot_body}=   Default Protect For Build Body RR OR KUR    ${body}   ${KUR_CERT}   ${KUR_KEY}   &{params}
    ELSE IF    '${body_name}' == 'p10cr'
        IF  '${RE_USE_P10CR}' == '${False}'
            ${csr}   ${_}=   Generate CSR For Testing
            VAR   ${P10CR_CSR}    ${csr}    scope=Suite
            VAR   ${RE_USE_P10cr}    False    scope=Suite
        END
        ${bad_pop}=   Get From Dictionary    ${params}   bad_pop  ${False}
        IF  ${bad_pop}
            ${key}=  Generate Default Key
            ${cm}=  Get Next Common Name
            ${body}=   Build P10Cr From Key   ${key}   recipient=${RECIPIENT}  common_name=${cm}
            ...        exclude_fields=${exclude_fields}   &{params}
        ELSE
            ${body}=   Build P10Cr From CSR   ${P10CR_CSR}   recipient=${RECIPIENT}
             ...        exclude_fields=${exclude_fields}   &{params}
        END
        ${prot_body}=    Default Protect For Build Body    ${body}   &{params}
    ELSE IF    '${body_name}' == 'genm'
        ${body}    Build CMP General Message   current_crl    recipient=${RECIPIENT}
        ...        exclude_fields=${exclude_fields}   &{params}
        ${prot_body}=    Default Protect For Build Body    ${body}   &{params}
    ELSE IF    '${body_name}' == 'rr'
        # Used to save resources by reusing the RR cert and key,
        # if possible.
        IF   '${RE_USE_RR}' == '${False}'
            ${cert}   ${key}=   Issue New Cert For Testing
            VAR   ${RR_CERT}    ${cert}    scope=Suite
            VAR   ${RR_KEY}    ${key}    scope=Suite
            VAR   ${RE_USE_RR}    False    scope=Suite
        END
        ${body}=    Build CMP Revoke Request   ${RR_CERT}   recipient=${RECIPIENT}
        ...        exclude_fields=${exclude_fields}   &{params}
        ${prot_body}=   Default Protect For Build Body RR OR KUR    ${body}   ${RR_CERT}   ${RR_KEY}   &{params}
    ELSE IF    '${body_name}' == 'added-protection'
        ${prot_body}=   Build Added Protection Body   ${exclude_fields}   &{params}
    ELSE IF    'added-protection-inner' in '${body_name}'
        ${prot_body}=   Build Added Protection Body Inner   ${body_name}    ${exclude_fields}   &{params}
    ELSE IF    '${body_name}' == 'batch'
        ${prot_body}=   Build Batch Body     ${exclude_fields}   &{params}
    ELSE IF    'batch_inner' in '${body_name}'
        ${prot_body}=   Build Batch Body Inner    ${body_name}    ${exclude_fields}   &{params}
    ELSE
        Fail    Unknown body name: ${body_name}
    END
    RETURN    ${prot_body}


Check For Resource Minimizing
    [Documentation]    Check if created structures can be reused, for the next test.
    [Arguments]    ${body_name}
    IF  '${body_name}' == 'rr'
        VAR    ${RE_USE_RR}   ${True}    scope=Suite
    ELSE IF   '${body_name}' == 'kur'
        VAR    ${RE_USE_KUR}   ${True}    scope=Suite
    ELSE IF   '${body_name}' == 'p10cr'
        VAR    ${RE_USE_P10cr}   ${True}    scope=Suite
    ELSE IF   '${body_name}' == 'ir'
        VAR    ${RE_USE_IR}   ${True}    scope=Suite
    ELSE IF   '${body_name}' == 'cr'
        VAR    ${RE_USE_CR}   ${True}    scope=Suite
    ELSE IF   '${body_name}' == 'ccr'
        VAR    ${RE_USE_CCR}   ${True}    scope=Suite
    END

Set Resource Minimizing To False
    [Documentation]    Set the resource minimizing to False.
    [Arguments]    ${body_name}
    IF  '${body_name}' == 'rr'
        VAR    ${RE_USE_RR}   ${False}    scope=Suite
    ELSE IF   '${body_name}' == 'kur'
        VAR    ${RE_USE_KUR}   ${False}    scope=Suite
    ELSE IF   '${body_name}' == 'p10cr'
        VAR    ${RE_USE_P10cr}   ${False}    scope=Suite
    ELSE IF   '${body_name}' == 'ir'
        VAR    ${RE_USE_IR}   ${False}    scope=Suite
    ELSE IF   '${body_name}' == 'cr'
        VAR    ${RE_USE_CR}   ${False}    scope=Suite
    ELSE IF   '${body_name}' == 'ccr'
        VAR    ${RE_USE_CCR}   ${False}    scope=Suite
    END

Validate Negative Response
    [Documentation]    Validate negative test cases
    [Arguments]    ${response}   ${body_name}    ${failinfo}   ${exclusive}=True
    PKIStatus Must Be    ${response}   rejection
    VAR    ${data}   nested, inner_batch, added-protection, genm
    IF  '${body_name}' in '${data}'
        PKIMessage Body Type Must Be    ${response}   error
    END
    Check For Resource Minimizing    ${body_name}
    PKIStatusInfo Failinfo Bit Must Be    ${response}   ${failinfo}   ${exclusive}

Build Without senderNonce
    [Documentation]    Build requests with bad sender nonce
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   senderNonce,sender,senderKID
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badSenderNonce   True

Build With Too Short senderNonce
    [Documentation]    Build requests with bad sender nonce
    [Arguments]    ${body_name}
    ${nonces}=   Generate Unique Byte Values    1    8
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   sender_nonce=${nonces[0]}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badSenderNonce   True

Build With Too Long senderNonce
    [Documentation]    Build requests with bad sender nonce
    [Arguments]    ${body_name}
    ${nonces}=   Generate Unique Byte Values    1    100
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   sender_nonce=${nonces[0]}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badSenderNonce   True

Build Without TransactionID
    [Documentation]    Build requests with bad transaction ID
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   transactionID,sender,senderKID
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badDataFormat   True

Build With Too Short TransactionID
    [Documentation]    Build requests with bad transaction ID
    [Arguments]    ${body_name}
    ${nonces}=   Generate Unique Byte Values    1    8
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   transaction_id=${nonces[0]}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badRequest   True

Build With Too Long TransactionID
    [Documentation]    Build requests with bad transaction ID
    [Arguments]    ${body_name}
    ${nonces}=   Generate Unique Byte Values    1    100
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   transaction_id=${nonces[0]}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badRequest   True

Build Without messageTime
    [Documentation]    Build requests without a message time set.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   messageTime,sender,senderKID
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badTime   True

Build With MessageTime In Future
    [Documentation]    Build requests with a message time in the future.
    [Arguments]    ${body_name}
    ${message_time}=   Get Current Date   UTC   increment=5 hours
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID  message_time=${message_time}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badTime   True

Build With MessageTime In Past
    [Documentation]    Build requests with a message time in the past.
    [Arguments]    ${body_name}
    ${message_time}=   Get Current Date   UTC   increment=-5 hours
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   message_time=${message_time}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badTime   True

Build With Sig Alg without Protection
    [Documentation]   Build requests with a protection algorithm without a protection value.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   sender=${SENDER}  exclude_protection=True
    ${body}=  Patch ProtectionAlg    ${body}    protection=signature   private_key=${INNER_KEY}
    ${response}=  Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With MAC Alg without Protection
    [Documentation]   Build requests with a protection algorithm without a protection value.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   sender=${SENDER}   exclude_protection=True
    ...       set_mac_algorithm=True
    ${response}=  Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Protection Without Alg
    [Documentation]    Build requests with a protection without an algorithm.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   exclude_protection=True
    ${body}=  Modify PKIMessage Protection    ${body}
    ${response}=  Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Bad Sig Protection
    [Documentation]    Build requests with a protection algorithm without a protection value.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   bad_message_check=True
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build Without extraCerts
    [Documentation]    Build requests without an extraCerts field
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   exclude_certs=True
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck,addInfoNotAvailable   False

Build Without Cert Chain
    [Documentation]    Build requests without a cert chain
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   exclude_certs=True
    ...       without_cert_chain=True
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck,signerNotTrusted  False

Build With recipNonce
    [Documentation]    Build requests with a recipNonce set, which is not allowed.
    [Arguments]    ${body_name}
    ${nonces}=   Generate Unique Byte Values    1    16
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID   recip_nonce=${nonces[0]}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badRecipientNonce   True

Build With Bad Sig Sender
    [Documentation]    Build requests with a bad sender for a signature protected PKIMessage.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   bad_sender=True  do_patch=${False}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Bad Issuer As Sender
    [Documentation]    Build requests with a bad issuer as sender.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   use_issuer=True  do_patch=${False}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Bad Sig SenderKID
    [Documentation]    Build requests with a bad senderKID for a signature protected PKIMessage.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   bad_ski=True  do_patch=${False}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Bad MAC Sender Choice
    [Documentation]    Build requests with a bad sender choice for a MAC protected PKIMessage.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   bad_mac_sender=True
    ...       do_patch=${False}   use_mac=True   sender=${SENDER}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build With Bad MAC SenderKID
    [Documentation]    Build requests with a bad senderKID for a MAC protected PKIMessage.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   bad_sender_kid=True
    ...       do_patch=${False}   use_mac=True   sender=${SENDER}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build Bad MAC Protected Message
    [Documentation]    Build requests with a MAC protected PKIMessage, which is not allowed.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   bad_message_check=True
    ...       do_patch=${False}   use_mac=True   sender=${SENDER}   sender_kid=${SENDER}
    ${response}=   Exchange PKIMessage    ${body}
    Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True

Build Not Allowed MAC-Protected Message
    [Documentation]    Build requests with a MAC protected PKIMessage, which is not allowed.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   ${None}   sender=${SENDER}
    ...       do_patch=${False}    for_mac=True
    ${protected}=    Default Protect With MAC    ${body}
    ${response}=   Exchange PKIMessage    ${protected}
    Validate Negative Response   ${response}   ${body_name}   wrongIntegrity   True

Build Message For Positive Header Validation
    [Documentation]    Build a message for header validation.
    [Arguments]    ${body_name}
    ${body}=  Build Body By Name    ${body_name}   sender,senderKID
    ${response}=   Exchange PKIMessage    ${body}
    Validate PKIMessage Header    ${response}   ${body}   allow_failure_sender=${STRICT}
    Validate Cmp Body Types    ${response}   ${body}   error=False
    IF  'batch_inner' in '${body_name}'
        ${inner_response}=   Get Inner PKIMessage    ${response}   2
        ${inner_body}=   Get Inner PKIMessage    ${body}   2
        Validate PKIMessage Header    ${inner_response}   ${inner_body}   allow_failure_sender=${STRICT}
    END
    IF  'added-protection' in '${body_name}'
        ${inner_body}=   Get Inner PKIMessage    ${body}
        Validate PKIMessage Header    ${response}   ${inner_body}   allow_failure_sender=${STRICT}
    END
    # Set the resource minimizing to False, so that the next
    # structures does use a new fresh structure.
    # So that not a similar CertRequest is used.
    # Might cause the `badCertTemplate` error.
    Set Resource Minimizing To False   ${body_name}

Build Message For Negative Header Validation
    [Documentation]    Build a message for negative header validation.
    [Arguments]    ${body_name}
    VAR   ${names}   genm, rr, batch, added-protection
    IF  '${body_name}' in '${names}'
        ${body}=  Build Body By Name    ${body_name}   sender,senderKID   bad_message_check=True
    ELSE
        ${body}=  Build Body By Name    ${body_name}   sender,senderKID   bad_pop=True
    END
    ${response}=   Exchange PKIMessage    ${body}
    Validate PKIMessage Header    ${response}   ${body}   allow_failure_sender=${STRICT}
    Validate Cmp Body Types    ${response}   ${body}
    IF  '${body_name}' in '${names}'
        Validate Negative Response   ${response}   ${body_name}   badMessageCheck   True
    ELSE IF    'added-protection-inner' in '${body_name}'
        VAR   ${empty_data}
        ${inner_name}=   Replace String    ${body_name}    'added-protection-inner'   ${empty_data}
        Validate Negative Response   ${response}   ${inner_name}   badPOP   True
    ELSE IF   'batch_inner' in '${body_name}'
        VAR   ${empty_data}
        ${inner_name}=   Replace String    ${body_name}    batch_inner_   ${empty_data}
        ${inner_body}=   Get Inner PKIMessage    ${body}    2
        ${inner_response}=   Get Inner PKIMessage    ${response}    2
        Validate Negative Response   ${inner_response}   ${inner_name}   badPOP   True
        Validate PKIMessage Header    ${inner_response}   ${inner_body}   allow_failure_sender=${STRICT}
    ELSE
        Validate Negative Response   ${response}   ${body_name}   badPOP   True
    END

*** Test Cases ***
CA MUST Reject IR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ir
     Build Without senderNonce    ir

CA MUST Reject P10CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    p10cr
     Build Without senderNonce    p10cr

CA MUST Reject CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    cr
     Build Without senderNonce    cr

CA MUST Reject KUR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    kur
     Build Without senderNonce    kur

CA MUST Reject GENM Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    genm
     Build Without senderNonce    genm

CA MUST Reject CCR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ccr
     Build Without senderNonce    ccr

CA MUST Reject RR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    rr
     Build Without senderNonce    rr

CA MUST Reject ADDED-PROTECTION Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection
     Build Without senderNonce    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ir
     Build Without senderNonce    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -cr
     Build Without senderNonce    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -kur
     Build Without senderNonce    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -p10cr
     Build Without senderNonce    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ccr
     Build Without senderNonce    added-protection-inner-ccr

CA MUST Reject BATCH Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch
     Build Without senderNonce    batch

CA MUST Reject BATCH_INNER_IR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ir
     Build Without senderNonce    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    cr
     Build Without senderNonce    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    kur
     Build Without senderNonce    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    p10cr
     Build Without senderNonce    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR Without SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ccr
     Build Without senderNonce    batch_inner_ccr

CA MUST Reject IR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ir
     Build With Too Short senderNonce    ir

CA MUST Reject P10CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    p10cr
     Build With Too Short senderNonce    p10cr

CA MUST Reject CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    cr
     Build With Too Short senderNonce    cr

CA MUST Reject KUR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    kur
     Build With Too Short senderNonce    kur

CA MUST Reject GENM With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    genm
     Build With Too Short senderNonce    genm

CA MUST Reject CCR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ccr
     Build With Too Short senderNonce    ccr

CA MUST Reject RR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    rr
     Build With Too Short senderNonce    rr

CA MUST Reject ADDED-PROTECTION With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection
     Build With Too Short senderNonce    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ir
     Build With Too Short senderNonce    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -cr
     Build With Too Short senderNonce    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -kur
     Build With Too Short senderNonce    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -p10cr
     Build With Too Short senderNonce    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ccr
     Build With Too Short senderNonce    added-protection-inner-ccr

CA MUST Reject BATCH With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch
     Build With Too Short senderNonce    batch

CA MUST Reject BATCH_INNER_IR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ir
     Build With Too Short senderNonce    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    cr
     Build With Too Short senderNonce    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    kur
     Build With Too Short senderNonce    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    p10cr
     Build With Too Short senderNonce    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Too Short SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ccr
     Build With Too Short senderNonce    batch_inner_ccr

CA MUST Reject IR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ir
     Build With Too Long senderNonce    ir

CA MUST Reject P10CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    p10cr
     Build With Too Long senderNonce    p10cr

CA MUST Reject CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    cr
     Build With Too Long senderNonce    cr

CA MUST Reject KUR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    kur
     Build With Too Long senderNonce    kur

CA MUST Reject GENM With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    genm
     Build With Too Long senderNonce    genm

CA MUST Reject CCR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    ccr
     Build With Too Long senderNonce    ccr

CA MUST Reject RR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    rr
     Build With Too Long senderNonce    rr

CA MUST Reject ADDED-PROTECTION With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection
     Build With Too Long senderNonce    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ir
     Build With Too Long senderNonce    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -cr
     Build With Too Long senderNonce    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -kur
     Build With Too Long senderNonce    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -p10cr
     Build With Too Long senderNonce    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    added-protection    -ccr
     Build With Too Long senderNonce    added-protection-inner-ccr

CA MUST Reject BATCH With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch
     Build With Too Long senderNonce    batch

CA MUST Reject BATCH_INNER_IR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ir
     Build With Too Long senderNonce    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    cr
     Build With Too Long senderNonce    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    kur
     Build With Too Long senderNonce    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    p10cr
     Build With Too Long senderNonce    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Too Long SenderNonce
     [Documentation]    A PKIMessage **MUST** have a `senderNonce` set which is 16-Bytes long. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    senderNonce    nested    batch    ccr
     Build With Too Long senderNonce    batch_inner_ccr

CA MUST Reject IR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    ir
     Build With recipNonce    ir

CA MUST Reject P10CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    p10cr
     Build With recipNonce    p10cr

CA MUST Reject CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    cr
     Build With recipNonce    cr

CA MUST Reject KUR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    kur
     Build With recipNonce    kur

CA MUST Reject GENM With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    genm
     Build With recipNonce    genm

CA MUST Reject CCR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    ccr
     Build With recipNonce    ccr

CA MUST Reject RR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    rr
     Build With recipNonce    rr

CA MUST Reject ADDED-PROTECTION With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection
     Build With recipNonce    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection    -ir
     Build With recipNonce    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection    -cr
     Build With recipNonce    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection    -kur
     Build With recipNonce    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection    -p10cr
     Build With recipNonce    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    added-protection    -ccr
     Build With recipNonce    added-protection-inner-ccr

CA MUST Reject BATCH With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    strict    robot:skip-on-failure
     Build With recipNonce    batch

CA MUST Reject BATCH_INNER_IR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    ir
     Build With recipNonce    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    cr
     Build With recipNonce    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    kur
     Build With recipNonce    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    p10cr
     Build With recipNonce    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With RecipNonce
     [Documentation]    A PKIMessage **MUST** not have a `recipNonce`. Ref: RFC 9483, Section 3.1.
     [Tags]    negative    recipNonce    nested    batch    ccr
     Build With recipNonce    batch_inner_ccr

CA MUST Reject IR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ir
     Build Without transactionID    ir

CA MUST Reject P10CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    p10cr
     Build Without transactionID    p10cr

CA MUST Reject CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    cr
     Build Without transactionID    cr

CA MUST Reject KUR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    kur
     Build Without transactionID    kur

CA MUST Reject GENM Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    genm
     Build Without transactionID    genm

CA MUST Reject CCR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ccr
     Build Without transactionID    ccr

CA MUST Reject RR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    rr
     Build Without transactionID    rr

CA MUST Reject ADDED-PROTECTION Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection
     Build Without transactionID    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ir
     Build Without transactionID    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -cr
     Build Without transactionID    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -kur
     Build Without transactionID    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -p10cr
     Build Without transactionID    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ccr
     Build Without transactionID    added-protection-inner-ccr

CA MUST Reject BATCH Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch
     Build Without transactionID    batch

CA MUST Reject BATCH_INNER_IR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ir
     Build Without transactionID    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    cr
     Build Without transactionID    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    kur
     Build Without transactionID    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    p10cr
     Build Without transactionID    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR Without TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ccr
     Build Without transactionID    batch_inner_ccr

CA MUST Reject IR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ir
     Build With Too Short transactionID    ir

CA MUST Reject P10CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    p10cr
     Build With Too Short transactionID    p10cr

CA MUST Reject CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    cr
     Build With Too Short transactionID    cr

CA MUST Reject KUR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    kur
     Build With Too Short transactionID    kur

CA MUST Reject GENM With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    genm
     Build With Too Short transactionID    genm

CA MUST Reject CCR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ccr
     Build With Too Short transactionID    ccr

CA MUST Reject RR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    rr
     Build With Too Short transactionID    rr

CA MUST Reject ADDED-PROTECTION With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection
     Build With Too Short transactionID    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ir
     Build With Too Short transactionID    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -cr
     Build With Too Short transactionID    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -kur
     Build With Too Short transactionID    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -p10cr
     Build With Too Short transactionID    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ccr
     Build With Too Short transactionID    added-protection-inner-ccr

CA MUST Reject BATCH With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch
     Build With Too Short transactionID    batch

CA MUST Reject BATCH_INNER_IR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ir
     Build With Too Short transactionID    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    cr
     Build With Too Short transactionID    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    kur
     Build With Too Short transactionID    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    p10cr
     Build With Too Short transactionID    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Too Short TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ccr
     Build With Too Short transactionID    batch_inner_ccr

CA MUST Reject IR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ir
     Build With Too Long transactionID    ir

CA MUST Reject P10CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    p10cr
     Build With Too Long transactionID    p10cr

CA MUST Reject CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    cr
     Build With Too Long transactionID    cr

CA MUST Reject KUR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    kur
     Build With Too Long transactionID    kur

CA MUST Reject GENM With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    genm
     Build With Too Long transactionID    genm

CA MUST Reject CCR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    ccr
     Build With Too Long transactionID    ccr

CA MUST Reject RR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    rr
     Build With Too Long transactionID    rr

CA MUST Reject ADDED-PROTECTION With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection
     Build With Too Long transactionID    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ir
     Build With Too Long transactionID    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -cr
     Build With Too Long transactionID    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -kur
     Build With Too Long transactionID    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -p10cr
     Build With Too Long transactionID    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    added-protection    -ccr
     Build With Too Long transactionID    added-protection-inner-ccr

CA MUST Reject BATCH With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch
     Build With Too Long transactionID    batch

CA MUST Reject BATCH_INNER_IR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ir
     Build With Too Long transactionID    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    cr
     Build With Too Long transactionID    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    kur
     Build With Too Long transactionID    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    p10cr
     Build With Too Long transactionID    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Too Long TransactionID
     [Documentation]    A PKIMessage **MUST** have a `transactionID` set which is 16-Bytes long.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    transactionID    nested    batch    ccr
     Build With Too Long transactionID    batch_inner_ccr

CA MUST Reject IR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ir
     Build Without messageTime    ir

CA MUST Reject P10CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    p10cr
     Build Without messageTime    p10cr

CA MUST Reject CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    cr
     Build Without messageTime    cr

CA MUST Reject KUR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    kur
     Build Without messageTime    kur

CA MUST Reject GENM Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    genm
     Build Without messageTime    genm

CA MUST Reject CCR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ccr
     Build Without messageTime    ccr

CA MUST Reject RR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    rr
     Build Without messageTime    rr

CA MUST Reject ADDED-PROTECTION Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection
     Build Without messageTime    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ir
     Build Without messageTime    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -cr
     Build Without messageTime    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -kur
     Build Without messageTime    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -p10cr
     Build Without messageTime    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ccr
     Build Without messageTime    added-protection-inner-ccr

CA MUST Reject BATCH Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch
     Build Without messageTime    batch

CA MUST Reject BATCH_INNER_IR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ir
     Build Without messageTime    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    cr
     Build Without messageTime    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    kur
     Build Without messageTime    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    p10cr
     Build Without messageTime    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR Without MessageTime
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ccr
     Build Without messageTime    batch_inner_ccr

CA MUST Reject IR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ir
     Build With MessageTime In Future    ir

CA MUST Reject P10CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    p10cr
     Build With MessageTime In Future    p10cr

CA MUST Reject CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    cr
     Build With MessageTime In Future    cr

CA MUST Reject KUR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    kur
     Build With MessageTime In Future    kur

CA MUST Reject GENM With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    genm
     Build With MessageTime In Future    genm

CA MUST Reject CCR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ccr
     Build With MessageTime In Future    ccr

CA MUST Reject RR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    rr
     Build With MessageTime In Future    rr

CA MUST Reject ADDED-PROTECTION With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection
     Build With MessageTime In Future    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ir
     Build With MessageTime In Future    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -cr
     Build With MessageTime In Future    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -kur
     Build With MessageTime In Future    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -p10cr
     Build With MessageTime In Future    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ccr
     Build With MessageTime In Future    added-protection-inner-ccr

CA MUST Reject BATCH With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch
     Build With MessageTime In Future    batch

CA MUST Reject BATCH_INNER_IR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ir
     Build With MessageTime In Future    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    cr
     Build With MessageTime In Future    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    kur
     Build With MessageTime In Future    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    p10cr
     Build With MessageTime In Future    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With MessageTime In Future
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ccr
     Build With MessageTime In Future    batch_inner_ccr

CA MUST Reject IR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ir
     Build With MessageTime In Past    ir

CA MUST Reject P10CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    p10cr
     Build With MessageTime In Past    p10cr

CA MUST Reject CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    cr
     Build With MessageTime In Past    cr

CA MUST Reject KUR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    kur
     Build With MessageTime In Past    kur

CA MUST Reject GENM With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    genm
     Build With MessageTime In Past    genm

CA MUST Reject CCR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    ccr
     Build With MessageTime In Past    ccr

CA MUST Reject RR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    rr
     Build With MessageTime In Past    rr

CA MUST Reject ADDED-PROTECTION With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection
     Build With MessageTime In Past    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ir
     Build With MessageTime In Past    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -cr
     Build With MessageTime In Past    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -kur
     Build With MessageTime In Past    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -p10cr
     Build With MessageTime In Past    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    added-protection    -ccr
     Build With MessageTime In Past    added-protection-inner-ccr

CA MUST Reject BATCH With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch
     Build With MessageTime In Past    batch

CA MUST Reject BATCH_INNER_IR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ir
     Build With MessageTime In Past    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    cr
     Build With MessageTime In Past    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    kur
     Build With MessageTime In Past    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    p10cr
     Build With MessageTime In Past    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With MessageTime In Past
     [Documentation]    A PKIMessage **MUST** have a `messageTime` which is sufficiently fresh.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    messageTime    nested    batch    ccr
     Build With MessageTime In Past    batch_inner_ccr

CA MUST Reject IR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ir
     Build With Bad Sig Protection    ir

CA MUST Reject P10CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    p10cr
     Build With Bad Sig Protection    p10cr

CA MUST Reject CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    cr
     Build With Bad Sig Protection    cr

CA MUST Reject KUR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    kur
     Build With Bad Sig Protection    kur

CA MUST Reject GENM With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    genm
     Build With Bad Sig Protection    genm

CA MUST Reject CCR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ccr
     Build With Bad Sig Protection    ccr

CA MUST Reject RR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    rr
     Build With Bad Sig Protection    rr

CA MUST Reject ADDED-PROTECTION With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection
     Build With Bad Sig Protection    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ir
     Build With Bad Sig Protection    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -cr
     Build With Bad Sig Protection    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -kur
     Build With Bad Sig Protection    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -p10cr
     Build With Bad Sig Protection    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ccr
     Build With Bad Sig Protection    added-protection-inner-ccr

CA MUST Reject BATCH With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch
     Build With Bad Sig Protection    batch

CA MUST Reject BATCH_INNER_IR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ir
     Build With Bad Sig Protection    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    cr
     Build With Bad Sig Protection    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    kur
     Build With Bad Sig Protection    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    p10cr
     Build With Bad Sig Protection    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Invalid Sig Protection
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ccr
     Build With Bad Sig Protection    batch_inner_ccr

CA MUST Reject IR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ir    extraCerts
     Build Without extraCerts    ir

CA MUST Reject P10CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    p10cr    extraCerts
     Build Without extraCerts    p10cr

CA MUST Reject CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    cr    extraCerts
     Build Without extraCerts    cr

CA MUST Reject KUR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    kur    extraCerts
     Build Without extraCerts    kur

CA MUST Reject GENM Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    genm    extraCerts
     Build Without extraCerts    genm

CA MUST Reject CCR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ccr    extraCerts
     Build Without extraCerts    ccr

CA MUST Reject RR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    rr    extraCerts
     Build Without extraCerts    rr

CA MUST Reject ADDED-PROTECTION Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    extraCerts
     Build Without extraCerts    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ir    extraCerts
     Build Without extraCerts    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -cr    extraCerts
     Build Without extraCerts    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -kur    extraCerts
     Build Without extraCerts    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -p10cr    extraCerts
     Build Without extraCerts    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ccr    extraCerts
     Build Without extraCerts    added-protection-inner-ccr

CA MUST Reject BATCH Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    extraCerts
     Build Without extraCerts    batch

CA MUST Reject BATCH_INNER_IR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ir    extraCerts
     Build Without extraCerts    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    cr    extraCerts
     Build Without extraCerts    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    kur    extraCerts
     Build Without extraCerts    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    p10cr    extraCerts
     Build Without extraCerts    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR Without extraCerts
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ccr    extraCerts
     Build Without extraCerts    batch_inner_ccr

CA MUST Reject IR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ir    extraCerts
     Build Without Cert Chain    ir

CA MUST Reject P10CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    p10cr    extraCerts
     Build Without Cert Chain    p10cr

CA MUST Reject CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    cr    extraCerts
     Build Without Cert Chain    cr

CA MUST Reject KUR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    kur    extraCerts
     Build Without Cert Chain    kur

CA MUST Reject GENM Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    genm    extraCerts
     Build Without Cert Chain    genm

CA MUST Reject CCR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    ccr    extraCerts
     Build Without Cert Chain    ccr

CA MUST Reject RR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    rr    extraCerts
     Build Without Cert Chain    rr

CA MUST Reject ADDED-PROTECTION Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    extraCerts
     Build Without Cert Chain    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ir    extraCerts
     Build Without Cert Chain    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -cr    extraCerts
     Build Without Cert Chain    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -kur    extraCerts
     Build Without Cert Chain    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -p10cr    extraCerts
     Build Without Cert Chain    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    added-protection    -ccr    extraCerts
     Build Without Cert Chain    added-protection-inner-ccr

CA MUST Reject BATCH Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    extraCerts
     Build Without Cert Chain    batch

CA MUST Reject BATCH_INNER_IR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ir    extraCerts
     Build Without Cert Chain    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    cr    extraCerts
     Build Without Cert Chain    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    kur    extraCerts
     Build Without Cert Chain    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    p10cr    extraCerts
     Build Without Cert Chain    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR Without Cert Chain
     [Documentation]    A PKIMessage **MUST** contain the complete cert chain and be valid protected.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    protection    nested    batch    ccr    extraCerts
     Build Without Cert Chain    batch_inner_ccr

CA MUST Reject IR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    ir
     Build With Protection Without Alg    ir

CA MUST Reject P10CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    p10cr
     Build With Protection Without Alg    p10cr

CA MUST Reject CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    cr
     Build With Protection Without Alg    cr

CA MUST Reject KUR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    kur
     Build With Protection Without Alg    kur

CA MUST Reject GENM With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    genm
     Build With Protection Without Alg    genm

CA MUST Reject CCR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    ccr
     Build With Protection Without Alg    ccr

CA MUST Reject RR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    rr
     Build With Protection Without Alg    rr

CA MUST Reject ADDED-PROTECTION With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection
     Build With Protection Without Alg    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection    -ir
     Build With Protection Without Alg    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection    -cr
     Build With Protection Without Alg    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection    -kur
     Build With Protection Without Alg    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection    -p10cr
     Build With Protection Without Alg    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    added-protection    -ccr
     Build With Protection Without Alg    added-protection-inner-ccr

CA MUST Reject BATCH With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch
     Build With Protection Without Alg    batch

CA MUST Reject BATCH_INNER_IR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch    ir
     Build With Protection Without Alg    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch    cr
     Build With Protection Without Alg    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch    kur
     Build With Protection Without Alg    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch    p10cr
     Build With Protection Without Alg    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Protection without Algorithm
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    nested    batch    ccr
     Build With Protection Without Alg    batch_inner_ccr

CA MUST Reject IR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    ir
     Build With Sig Alg Without Protection    ir

CA MUST Reject P10CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    p10cr
     Build With Sig Alg Without Protection    p10cr

CA MUST Reject CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    cr
     Build With Sig Alg Without Protection    cr

CA MUST Reject KUR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    kur
     Build With Sig Alg Without Protection    kur

CA MUST Reject GENM With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    genm
     Build With Sig Alg Without Protection    genm

CA MUST Reject CCR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    ccr
     Build With Sig Alg Without Protection    ccr

CA MUST Reject RR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    rr
     Build With Sig Alg Without Protection    rr

CA MUST Reject ADDED-PROTECTION With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection
     Build With Sig Alg Without Protection    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection    -ir
     Build With Sig Alg Without Protection    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection    -cr
     Build With Sig Alg Without Protection    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection    -kur
     Build With Sig Alg Without Protection    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection    -p10cr
     Build With Sig Alg Without Protection    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    added-protection    -ccr
     Build With Sig Alg Without Protection    added-protection-inner-ccr

CA MUST Reject BATCH With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch
     Build With Sig Alg Without Protection    batch

CA MUST Reject BATCH_INNER_IR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch    ir
     Build With Sig Alg Without Protection    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch    cr
     Build With Sig Alg Without Protection    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch    kur
     Build With Sig Alg Without Protection    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch    p10cr
     Build With Sig Alg Without Protection    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Sig Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    sig    nested    batch    ccr
     Build With Sig Alg Without Protection    batch_inner_ccr

CA MUST Reject IR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    ir
     Build With MAC Alg Without Protection    ir

CA MUST Reject P10CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    p10cr
     Build With MAC Alg Without Protection    p10cr

CA MUST Reject CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    cr
     Build With MAC Alg Without Protection    cr

CA MUST Reject GENM With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    genm
     Build With MAC Alg Without Protection    genm

CA MUST Reject ADDED-PROTECTION-INNER-IR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    added-protection    -ir
     Build With MAC Alg Without Protection    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    added-protection    -cr
     Build With MAC Alg Without Protection    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    added-protection    -p10cr
     Build With MAC Alg Without Protection    added-protection-inner-p10cr

CA MUST Reject BATCH_INNER_IR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    batch    ir
     Build With MAC Alg Without Protection    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    batch    cr
     Build With MAC Alg Without Protection    batch_inner_cr

CA MUST Reject BATCH_INNER_P10CR With MAC Algorithm without Protection
     [Documentation]    A PKIMessage **MUST** either be correctly protected with a signature or a MAC, or not at all.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    inconsistent    protection    mac    nested    batch    p10cr
     Build With MAC Alg Without Protection    batch_inner_p10cr

CA MUST Reject IR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    ir
     Build With Bad Sig Sender    ir

CA MUST Reject P10CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    p10cr
     Build With Bad Sig Sender    p10cr

CA MUST Reject CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    cr
     Build With Bad Sig Sender    cr

CA MUST Reject KUR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    kur
     Build With Bad Sig Sender    kur

CA MUST Reject GENM With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    genm
     Build With Bad Sig Sender    genm

CA MUST Reject CCR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    ccr
     Build With Bad Sig Sender    ccr

CA MUST Reject RR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    rr
     Build With Bad Sig Sender    rr

CA MUST Reject ADDED-PROTECTION With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection
     Build With Bad Sig Sender    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -ir
     Build With Bad Sig Sender    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -cr
     Build With Bad Sig Sender    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -kur
     Build With Bad Sig Sender    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -p10cr
     Build With Bad Sig Sender    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -ccr
     Build With Bad Sig Sender    added-protection-inner-ccr

CA MUST Reject BATCH With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch
     Build With Bad Sig Sender    batch

CA MUST Reject BATCH_INNER_IR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    ir
     Build With Bad Sig Sender    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    cr
     Build With Bad Sig Sender    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    kur
     Build With Bad Sig Sender    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    p10cr
     Build With Bad Sig Sender    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Invalid Sig Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    ccr
     Build With Bad Sig Sender    batch_inner_ccr

CA MUST Reject IR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    ir
     Build With Bad Issuer As Sender    ir

CA MUST Reject P10CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    p10cr
     Build With Bad Issuer As Sender    p10cr

CA MUST Reject CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    cr
     Build With Bad Issuer As Sender    cr

CA MUST Reject KUR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    kur
     Build With Bad Issuer As Sender    kur

CA MUST Reject GENM With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    genm
     Build With Bad Issuer As Sender    genm

CA MUST Reject CCR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    ccr
     Build With Bad Issuer As Sender    ccr

CA MUST Reject RR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    rr
     Build With Bad Issuer As Sender    rr

CA MUST Reject ADDED-PROTECTION With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection
     Build With Bad Issuer As Sender    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -ir
     Build With Bad Issuer As Sender    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -cr
     Build With Bad Issuer As Sender    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -kur
     Build With Bad Issuer As Sender    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -p10cr
     Build With Bad Issuer As Sender    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    added-protection    -ccr
     Build With Bad Issuer As Sender    added-protection-inner-ccr

CA MUST Reject BATCH With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch
     Build With Bad Issuer As Sender    batch

CA MUST Reject BATCH_INNER_IR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    ir
     Build With Bad Issuer As Sender    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    cr
     Build With Bad Issuer As Sender    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    kur
     Build With Bad Issuer As Sender    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    p10cr
     Build With Bad Issuer As Sender    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Issuer As Sender
     [Documentation]    A signature protected PKIMessage **MUST** have the `sender` field set to the `subject`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    sender    nested    batch    ccr
     Build With Bad Issuer As Sender    batch_inner_ccr

CA MUST Reject IR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    ir
     Build With Bad Sig SenderKID    ir

CA MUST Reject P10CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    p10cr
     Build With Bad Sig SenderKID    p10cr

CA MUST Reject CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    cr
     Build With Bad Sig SenderKID    cr

CA MUST Reject KUR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    kur
     Build With Bad Sig SenderKID    kur

CA MUST Reject GENM With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    genm
     Build With Bad Sig SenderKID    genm

CA MUST Reject CCR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    ccr
     Build With Bad Sig SenderKID    ccr

CA MUST Reject RR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    rr
     Build With Bad Sig SenderKID    rr

CA MUST Reject ADDED-PROTECTION With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection
     Build With Bad Sig SenderKID    added-protection

CA MUST Reject ADDED-PROTECTION-INNER-IR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection    -ir
     Build With Bad Sig SenderKID    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection    -cr
     Build With Bad Sig SenderKID    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-KUR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection    -kur
     Build With Bad Sig SenderKID    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection    -p10cr
     Build With Bad Sig SenderKID    added-protection-inner-p10cr

CA MUST Reject ADDED-PROTECTION-INNER-CCR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    added-protection    -ccr
     Build With Bad Sig SenderKID    added-protection-inner-ccr

CA MUST Reject BATCH With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch
     Build With Bad Sig SenderKID    batch

CA MUST Reject BATCH_INNER_IR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch    ir
     Build With Bad Sig SenderKID    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch    cr
     Build With Bad Sig SenderKID    batch_inner_cr

CA MUST Reject BATCH_INNER_KUR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch    kur
     Build With Bad Sig SenderKID    batch_inner_kur

CA MUST Reject BATCH_INNER_P10CR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch    p10cr
     Build With Bad Sig SenderKID    batch_inner_p10cr

CA MUST Reject BATCH_INNER_CCR With Invalid SKI SenderKID
     [Documentation]    A signature protected PKIMessage **MUST** have the senderKID set the SKI of the protection cert, if present.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    sig    senderKID    nested    batch    ccr
     Build With Bad Sig SenderKID    batch_inner_ccr

CA MUST Reject IR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    ir
     Build With Bad MAC Sender Choice    ir

CA MUST Reject P10CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    p10cr
     Build With Bad MAC Sender Choice    p10cr

CA MUST Reject CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    cr
     Build With Bad MAC Sender Choice    cr

CA MUST Reject GENM With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    genm
     Build With Bad MAC Sender Choice    genm

CA MUST Reject ADDED-PROTECTION-INNER-IR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -ir
     Build With Bad MAC Sender Choice    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -cr
     Build With Bad MAC Sender Choice    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -p10cr
     Build With Bad MAC Sender Choice    added-protection-inner-p10cr

CA MUST Reject BATCH_INNER_IR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    ir
     Build With Bad MAC Sender Choice    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    cr
     Build With Bad MAC Sender Choice    batch_inner_cr

CA MUST Reject BATCH_INNER_P10CR With Invalid MAC Sender
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    p10cr
     Build With Bad MAC Sender Choice    batch_inner_p10cr

CA MUST Reject IR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    ir
     Build Bad MAC Protected Message    ir

CA MUST Reject P10CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    p10cr
     Build Bad MAC Protected Message    p10cr

CA MUST Reject CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    cr
     Build Bad MAC Protected Message    cr

CA MUST Reject GENM Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    genm
     Build Bad MAC Protected Message    genm

CA MUST Reject ADDED-PROTECTION-INNER-IR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -ir
     Build Bad MAC Protected Message    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -cr
     Build Bad MAC Protected Message    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-P10CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    added-protection    -p10cr
     Build Bad MAC Protected Message    added-protection-inner-p10cr

CA MUST Reject BATCH_INNER_IR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    ir
     Build Bad MAC Protected Message    batch_inner_ir

CA MUST Reject BATCH_INNER_CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    cr
     Build Bad MAC Protected Message    batch_inner_cr

CA MUST Reject BATCH_INNER_P10CR Which is Invalid Protected
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    sender    nested    batch    p10cr
     Build Bad MAC Protected Message    batch_inner_p10cr

CA MUST Reject IR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    ir
     Build With Bad MAC SenderKID    ir

CA MUST Reject P10CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    p10cr
     Build With Bad MAC SenderKID    p10cr

CA MUST Reject CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    cr
     Build With Bad MAC SenderKID    cr

CA MUST Reject GENM With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    genm
     Build With Bad MAC SenderKID    genm

CA MUST Reject ADDED-PROTECTION-INNER-IR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    added-protection    -ir
     Build With Bad MAC SenderKID    added-protection-inner-ir

CA MUST Reject ADDED-PROTECTION-INNER-CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    added-protection    -cr
     Build With Bad MAC SenderKID    added-protection-inner-cr

CA MUST Reject ADDED-PROTECTION-INNER-P10CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    added-protection    -p10cr
     Build With Bad MAC SenderKID    added-protection-inner-p10cr

CA MUST Reject BATCH_INNER_IR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    batch    ir
     Build With Bad MAC SenderKID    batch_inner_ir

CA MUST Reject BATCH_INNER_CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    batch    cr
     Build With Bad MAC SenderKID    batch_inner_cr

CA MUST Reject BATCH_INNER_P10CR With Bad MAC SenderKID
     [Documentation]    A MAC protected PKIMessage **MUST** have the `sender` field set to the `directoryName` choice.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    senderKID    nested    batch    p10cr
     Build With Bad MAC SenderKID    batch_inner_p10cr

CA MUST Reject ADDED-PROTECTION Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    added-protection
     Build Not Allowed MAC-Protected Message    added-protection

CA MUST Reject BATCH Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    batch
     Build Not Allowed MAC-Protected Message    batch

CA MUST Reject BATCH_INNER_CCR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    batch    ccr
     Build Not Allowed MAC-Protected Message    batch_inner_ccr

CA MUST Reject BATCH_INNER_KUR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    batch    kur
     Build Not Allowed MAC-Protected Message    batch_inner_kur

CA MUST Reject ADDED-PROTECTION-INNER-KUR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    added-protection    -kur
     Build Not Allowed MAC-Protected Message    added-protection-inner-kur

CA MUST Reject ADDED-PROTECTION-INNER-CCR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    nested    added-protection    -ccr
     Build Not Allowed MAC-Protected Message    added-protection-inner-ccr

CA MUST Reject CCR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    ccr
     Build Not Allowed MAC-Protected Message    ccr

CA MUST Reject KUR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    kur
     Build Not Allowed MAC-Protected Message    kur

CA MUST Reject RR Which Is MAC Protected
     [Documentation]    A MAC protected PKIMessage is not allowed for a `rr` or `kur`,`ccr` and `nested` messages.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    mac    rr
     Build Not Allowed MAC-Protected Message    rr

CA MUST Return For NEG IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    ir
     Build Message For Negative Header Validation    ir

CA MUST Return For NEG P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    p10cr
     Build Message For Negative Header Validation    p10cr

CA MUST Return For NEG CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    cr
     Build Message For Negative Header Validation    cr

CA MUST Return For NEG KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    kur
     Build Message For Negative Header Validation    kur

CA MUST Return For NEG GENM A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    genm
     Build Message For Negative Header Validation    genm

CA MUST Return For NEG CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    ccr
     Build Message For Negative Header Validation    ccr

CA MUST Return For NEG RR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    rr
     Build Message For Negative Header Validation    rr

CA MUST Return For NEG ADDED-PROTECTION A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection
     Build Message For Negative Header Validation    added-protection

CA MUST Return For NEG ADDED-PROTECTION-INNER-IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection    -ir
     Build Message For Negative Header Validation    added-protection-inner-ir

CA MUST Return For NEG ADDED-PROTECTION-INNER-CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection    -cr
     Build Message For Negative Header Validation    added-protection-inner-cr

CA MUST Return For NEG ADDED-PROTECTION-INNER-KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection    -kur
     Build Message For Negative Header Validation    added-protection-inner-kur

CA MUST Return For NEG ADDED-PROTECTION-INNER-P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection    -p10cr
     Build Message For Negative Header Validation    added-protection-inner-p10cr

CA MUST Return For NEG ADDED-PROTECTION-INNER-CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    added-protection    -ccr
     Build Message For Negative Header Validation    added-protection-inner-ccr

CA MUST Return For NEG BATCH A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch
     Build Message For Negative Header Validation    batch

CA MUST Return For NEG BATCH_INNER_IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch    ir
     Build Message For Negative Header Validation    batch_inner_ir

CA MUST Return For NEG BATCH_INNER_CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch    cr
     Build Message For Negative Header Validation    batch_inner_cr

CA MUST Return For NEG BATCH_INNER_KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch    kur
     Build Message For Negative Header Validation    batch_inner_kur

CA MUST Return For NEG BATCH_INNER_P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch    p10cr
     Build Message For Negative Header Validation    batch_inner_p10cr

CA MUST Return For NEG BATCH_INNER_CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    negative    PKIHeader    nested    batch    ccr
     Build Message For Negative Header Validation    batch_inner_ccr

CA MUST Return For POS IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    ir
     Build Message For Positive Header Validation    ir

CA MUST Return For POS P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    p10cr
     Build Message For Positive Header Validation    p10cr

CA MUST Return For POS CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    cr
     Build Message For Positive Header Validation    cr

CA MUST Return For POS KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    kur
     Build Message For Positive Header Validation    kur

CA MUST Return For POS GENM A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    genm
     Build Message For Positive Header Validation    genm

CA MUST Return For POS CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    ccr
     Build Message For Positive Header Validation    ccr

CA MUST Return For POS RR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    rr
     Build Message For Positive Header Validation    rr

CA MUST Return For POS ADDED-PROTECTION A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection
     Build Message For Positive Header Validation    added-protection

CA MUST Return For POS ADDED-PROTECTION-INNER-IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection    -ir
     Build Message For Positive Header Validation    added-protection-inner-ir

CA MUST Return For POS ADDED-PROTECTION-INNER-CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection    -cr
     Build Message For Positive Header Validation    added-protection-inner-cr

CA MUST Return For POS ADDED-PROTECTION-INNER-KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection    -kur
     Build Message For Positive Header Validation    added-protection-inner-kur

CA MUST Return For POS ADDED-PROTECTION-INNER-P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection    -p10cr
     Build Message For Positive Header Validation    added-protection-inner-p10cr

CA MUST Return For POS ADDED-PROTECTION-INNER-CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    added-protection    -ccr
     Build Message For Positive Header Validation    added-protection-inner-ccr

CA MUST Return For POS BATCH A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch
     Build Message For Positive Header Validation    batch

CA MUST Return For POS BATCH_INNER_IR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch    ir
     Build Message For Positive Header Validation    batch_inner_ir

CA MUST Return For POS BATCH_INNER_CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch    cr
     Build Message For Positive Header Validation    batch_inner_cr

CA MUST Return For POS BATCH_INNER_KUR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch    kur
     Build Message For Positive Header Validation    batch_inner_kur

CA MUST Return For POS BATCH_INNER_P10CR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch    p10cr
     Build Message For Positive Header Validation    batch_inner_p10cr

CA MUST Return For POS BATCH_INNER_CCR A Valid PKIHeader
     [Documentation]    A PKIMessage **MUST** have a valid `PKIHeader`.
     ...    Ref: RFC 9483, Section 3.1.
     [Tags]    positive    PKIHeader    nested    batch    ccr
     Build Message For Positive Header Validation    batch_inner_ccr
