# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP Certificate Confirmation (`certConf`) requests and responses logic, covering
...                 scenarios for verifying proper handling of certificate confirmation by the CA. Includes tests to
...                 ensure compliance with configuration-dependent PKI policies, such as mandatory confirmation of
...                 issued certificates or responses to invalid or duplicate `certConf` requests.

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/keyutils.py
Library             ../resources/cmputils.py
Library             ../resources/protectionutils.py

Test Tags           certConf

Suite Setup    Set Up Test Suite


*** Test Cases ***
#### Accept and reject test.

CA MUST Accept Valid MAC Protected Issuing Process
    [Documentation]    According to RFC 9483 Section 4.1.1, when a valid request is received with MAC-based protection,
    ...    the CA MUST process the request and respond with a valid certificate response. The response must
    ...    not include the `implicitConfirm` extension. We send a request protected with MAC-based
    ...    protection and verify that the CA responds as required.
    [Tags]    mac    positive
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped test because MAC protection is disabled.
    ${protected_msg}=    Generate Default MAC Protected PKIMessage   ${DEFAULT_MAC_ALGORITHM}   ${False}
    ${response}=    Exchange PKIMessage    ${protected_msg}
    PKIStatus Must Be    ${response}    status=accepted
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    for_mac=True
    ${protected_cert_conf}=    Default Protect With MAC    ${cert_conf}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    pkiconf

CA MUST Accept EE Rejection Of The Issued Certificate
    [Documentation]    According to RFC 9483 Section 4.1, an End-Entity may reject a newly issued certificate by
    ...    sending a certConf message with a `rejection` status. We send a certConf message indicating
    ...    `rejection` with a failInfo of `badCertTemplate` and optional explanatory text. The CA MUST
    ...    acknowledge this rejection by responding with a PKI confirmation message, completing the
    ...    transaction.
    [Tags]    positive    rejection   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${status_info}=    Prepare PKIStatusInfo
    ...    status=rejection
    ...    failinfo=badCertTemplate
    ...    texts=I did not get what I wanted.
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    recipient=${RECIPIENT}
    ...    status_info=${status_info}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    pkiconf

#### Basic tests

CA MUST Reject More Than One CertStatus Inside The certConf
    [Documentation]    According to RFC 9483 Section 4.1, when implicit confirmation is not allowed, the
    ...    End-Entity MUST respond to all issued certificates. We send a valid Initialization
    ...    Request without the implicit confirmation set and expect the CA to issue a certificate.
    ...    Then we build a certificate confirmation message with two CertStatus entries. The CA
    ...    MUST detect the invalid message and may respond with the optional failInfo `badRequest`.
    [Tags]    invalid-size    negative
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert}=    Get Cert From PKIMessage    ${response}
    ${cert_hash}=    Calculate Cert Hash    ${cert}   hash_alg=sha256
    ${cert_status}=    Prepare CertStatus    ${cert_hash}    cert=${cert}   hash_alg=sha256
    VAR    @{My_List}    ${cert_status}    ${cert_status}
    Append To List    ${My_List}    ${cert_status}
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    pvno=3
    ...    recipient=${RECIPIENT}
    ...    cert_status=${My_List}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIStatus Must Be    ${response}    rejection
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

CA MUST Reject Invalid certReqId Inside The certConf
    [Documentation]    According to RFC 9483, the `certReqId` in the certConf message for the first issued
    ...    certificate must be set to 0. We send a certConf message with an invalid `certReqId`
    ...    value of -1. The CA MUST reject this message and may respond with the optional failInfo
    ...    `badRequest`.
    [Tags]    field    negative
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    recipient=${RECIPIENT}
    ...    cert_req_id=-1
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIStatus Must Be    ${response}    rejection
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

CA MUST Reject failInfo With Status Accepted Inside The certConf
    [Documentation]    According to RFC 9483 Section 4.1, the certConf message must have a consistent `status`
    ...    and failInfo. A `status` "accepted" indicates no error, making the inclusion of a failInfo
    ...    like `badRequest` invalid. We send a certConf message with this inconsistency, and the CA
    ...    MUST detect it and respond with an error, optionally including the failInfo `badRequest`.
    [Tags]    inconsistency    negative    status   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${status_info}=    Prepare PKIStatusInfo    status=accepted    failinfo=badRequest
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    status_info=${status_info}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIStatus Must Be    ${response}    rejection
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

### certificate hash

CA MUST Accept certConf With A Different HashAlg And Version 3
    [Documentation]    According to RFC 9483 Section 4.1, if the `pvno` field in the PKIHeader is set to
    ...    version 3, the certConf message may use a different hash algorithm than the one used by
    ...    the CA to sign the certificate. We send a certConf message with a different hash
    ...    algorithm and `pvno` set to 3. The CA MUST accept the message and respond with a valid PKI
    ...    confirmation message.
    [Tags]    popo    positive
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key
    ...    ${key}
    ...    pvno=3
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=    Get Cert From PKIMessage    ${response}
    ${cert_status}=    Prepare CertStatus   cert=${cert}   different_hash=True
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    pvno=3
    ...    cert_status=${cert_status}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    pkiconf

CA MUST Reject certConf With A Different HashAlg But Version 2
    [Documentation]    According to RFC 9483 Section 4.1, the certificate hash in the CertStatus must use the same
    ...    hash algorithm as the one used by the CA to sign the certificate. If the hash algorithm
    ...    differs and the `pvno` in the PKIHeader is set to 2, the CA MUST detect the mismatch and
    ...    respond with an error, optionally including the failInfo `badCertId`.
    [Tags]    negative    popo
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert}=    Get Cert From PKIMessage    ${response}
    ${cert_hash}=    Calculate Cert Hash    ${cert}    different_hash=True
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    pvno=2
    ...    cert_hash=${cert_hash}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertId    exclusive=True

### protection

CA MUST Reject certConf Signed With The Newly Issued Certificate
    [Documentation]    According to RFC 9483 Section 4.1, the certConf message must be signed using the same
    ...    credentials as the initial request to ensure consistent identity verification. We send a
    ...    certConf message signed with the newly issued certificate instead of the original
    ...    credentials. The CA MUST detect this integrity error and respond with an error,
    ...    optionally including the failInfo `badMessageCheck` or `badRequest`.
    [Tags]    bad-behaviour    negative    protection   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${cert}=    Get Cert From PKIMessage    ${response}
    ${cert_chain}=   Build CMP Chain From PKIMessage    ${response}   ee_cert=${cert}
    Write Certs To Dir    ${cert_chain}
    ${private_key}=  Get From List    ${burned_keys}    -1
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${private_key}
    ...    cert=${cert}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=wrongAuthority,badRequest

CA MUST Reject certConf With First PKIMessage PBM Protected Then PBMAC1
    [Documentation]    According to RFC 9483, all PKI messages within a transaction must use consistent
    ...    credentials and protection algorithms to ensure message integrity and security. We send
    ...    a valid certificate request protected with a password-based MAC and then send a
    ...    certificate confirmation message protected with a different algorithm (PBMAC1). The CA
    ...    MUST detect this inconsistency in protection algorithms and reject the certificate
    ...    confirmation message. The CA may optionally include the failInfo `badMessageCheck`.
    [Tags]    inconsistency    mac    negative    protection
    Skip If    not ${STRICT_MAC_VALIDATION}    Skipped because the `STRICT_MAC_VALIDATION` variable is set to False.
    ${pki_message}=    Generate Default MAC Protected PKIMessage    password_based_mac    ${False}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert_conf}=    Build Cert Conf From Resp    ${response}
    ${protected_cert_conf}=    Protect PKIMessage    ${cert_conf}    protection=pbmac1    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject certConf without Protection
    [Documentation]    According to RFC 9483, certificate confirmation messages must include a valid protection
    ...    mechanism to ensure message integrity and authenticity. We send a certificate
    ...    confirmation message without any protection. The CA MUST detect the missing protection
    ...    and reject the certConf message. The CA may optionally include the failInfo
    ...    `badMessageCheck`.
    [Tags]    negative    protection   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp    ${response}
    ${response}=    Exchange PKIMessage    ${cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject IR with Signature and Then certConf MAC Protection
    [Documentation]    According to RFC 9483, all PKI messages within a transaction must be protected using the
    ...    same credentials and protection algorithm to maintain integrity and consistency. We send
    ...    an initialization request protected with a signature and then a certificate confirmation
    ...    message using MAC-based-protection. The CA MUST detect this inconsistency and reject the
    ...    certConf message. The CA may optionally include the failInfo `wrongIntegrity`.
    [Tags]    inconsistency    mac    negative    protection
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp    ${response}   for_mac=True
    ...              sender=${SENDER}   recipient=${RECIPIENT}
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=wrongIntegrity    exclusive=True

### General Message

CA MUST Reject CertConf With No senderNonce
    [Documentation]    According to RFC 9483, Section 3 and 4.1, the `senderNonce` field in each message must match the
    ...    `senderNonce` from the initial message for consistency and replay protection. The `certConf`
    ...    message must include the same `senderNonce` used throughout the transaction. We send a
    ...    certificate confirmation message without the `senderNonce` field. The CA MUST detect this
    ...    omission and reject the message, optionally including the failInfo `badSenderNonce`.
    [Tags]    negative    rfc9483-header   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender,senderNonce
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce    exclusive=True

CA MUST Reject CertConf With Different senderNonce
    [Documentation]    According to RFC 9483, Section 3 and 4.1, the `senderNonce` field in each message must match the
    ...    `senderNonce` from the initial message for consistency and replay protection. The `certConf`
    ...    message must include the same `senderNonce` used throughout the transaction. We send a
    ...    `certConf` message with a modified `senderNonce`, expecting the CA to detect this mismatch.
    ...    The CA MUST reject the message and may respond with the optional failInfo `badSenderNonce`.
    [Tags]    negative    rfc9483-header   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender,senderNonce,recipNonce
    ${sender_nonce}=    Get Asn1 Value As Bytes    ${response}    header.recipNonce
    ${sender_nonce}=    Manipulate First Byte    ${sender_nonce}
    ${recip_nonce}=    Get Asn1 Value As Bytes    ${response}    header.senderNonce
    ${cert_conf}=    Patch SenderNonce    ${cert_conf}    sender_nonce=${sender_nonce}
    ${cert_conf}=    Patch RecipNonce    ${cert_conf}    recip_nonce=${recip_nonce}
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce    exclusive=True

CA MUST Reject certConf With No recipNonce
    [Documentation]    According to RFC 9483, Section 3.1, every message in a transaction, except the initial one,
    ...    must include the `recipNonce` field containing the `senderNonce` from the previous message.
    ...    This ensures message integrity and guards against replay attacks. We send a certConf message
    ...    without the `recipNonce` field. The CA MUST detect this omission and reject the message,
    ...    optionally including the failInfo `badRecipientNonce`.
    [Tags]    negative    rfc9483-header  minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender,recipNonce
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRecipientNonce    exclusive=True

CA MUST Reject CertConf With Different recipNonce
    [Documentation]    According to RFC 9483, each message in a transaction, except the initial one, must include the
    ...    `recipNonce` field matching the `senderNonce` from the previous message to ensure transaction
    ...    integrity. We send a certificate confirmation message with a modified `recipNonce` value. The
    ...    CA MUST detect this nonce mismatch and reject the message, optionally including the failInfo
    ...    `badRecipientNonce`.
    [Tags]    negative    rfc9483-header   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender,recipNonce
    ${recip_nonce}=    Get Asn1 Value As Bytes    ${response}    header.senderNonce
    ${recip_nonce}=    Manipulate First Byte    ${recip_nonce}
    ${cert_conf}=    Patch RecipNonce    ${cert_conf}    recip_nonce=${recip_nonce}
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRecipientNonce    exclusive=True

CA MUST Reject CertConf with omitted transactionID
    [Documentation]    According to RFC 9483 Section 3.1, the `transactionID` in the certConf message must match the
    ...    `transactionID` from the initial certificate issuance request. We send a certConf message
    ...    without the `transactionID` field. The CA MUST detect this omission and reject the message,
    ...    optionally including the failInfo `badRequest`.
    [Tags]    negative    rfc9483-header   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID,transactionID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

CA MUST Reject CertConf with Different transactionID
    [Documentation]    According to RFC 9483 Section 3.1, the `transactionID` in the certConf message must match the
    ...    `transactionID` from the initial certificate issuance request. We send a certConf message with
    ...    a modified `transactionID`. The CA MUST detect the mismatch and reject the message, optionally
    ...    responding with the failInfo `transactionIdInUse` or `badRequest`.
    [Tags]    negative    rfc9483-header  minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${tx_id}=    Get Asn1 Value As Bytes    ${response}    header.transactionID
    ${tx_id}=    Manipulate First Byte    ${tx_id}
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID,transactionID
    ${patched_cert_conf}=    Patch TransactionID    ${cert_conf}    ${tx_id}
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${patched_cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=transactionIdInUse,badRequest    exclusive=True

CA MAY Reject CertConf With implicitConfirm
    [Documentation]    According to RFC 9483 Sections 3 and 4.1, the use of `implicitConfirm` is recommended in `ir`,
    ...    `cr`, `kur`, and `p10cr` messages, optional in `ip`, `cp`, and `kup` response messages, and
    ...    prohibited in other message types. We send a `certConf` message with `implicitConfirm=True`.
    ...    The CA MAY reject this message due to the presence of `implicitConfirm`, potentially returning
    ...    a failInfo of `badRequest`. This test evaluates policy-dependent behavior and may fail based
    ...    on the policy.
    [Tags]    negative    policy-dependent    rfc9483-header    robot:skip-on-failure    strict
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ...    implicit_confirm=True
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be   ${response}    failinfo=badRequest   exclusive=True

CA SHOULD Send certConfirmed When Valid certConf Is Sent Again
    [Documentation]    According to RFC 9483 Sections 3 and 4.1, if a valid `certConf` message is sent more than once,
    ...    the CA SHOULD return a `certConfirmed` response to acknowledge the repeated confirmation.
    ...    We send a valid `certConf` message followed by a duplicate `certConf` message. The CA should
    ...    return a failInfo of `certConfirmed` in response to the repeated `certConf` message.
    [Tags]    negative    rfc9483-header    robot:skip-on-failure    strict   minimal
    ${response}=    Generate Default IR And Exchange For Cert Conf
    ${cert_conf}=    Build Cert Conf From Resp
    ...    ${response}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_cert_conf}=    Protect PKIMessage
    ...    ${cert_conf}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${pki_conf}=   Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    ${pki_conf2}=    Exchange PKIMessage    ${protected_cert_conf}
    PKIMessage Body Type Must Be    ${pki_conf2}    error
    PKIStatusInfo Failinfo Bit Must Be   ${pki_conf2}    failinfo=certConfirmed   exclusive=True


*** Keywords ***
Generate Default IR And Exchange For Cert Conf
    [Documentation]    Generates a default initialization request for a certificate confirmation message.
    ...
    ...                Returns:
    ...                -------
    ...                - the response from the CA after sending the ir.
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key
    ...       ${key}
    ...       cert_template=${cert_template}
    ...       recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...                 ${ir}
    ...                 protection=signature
    ...                 private_key=${ISSUED_KEY}
    ...                 cert=${ISSUED_CERT}
    ${response}=   Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be     ${response}      status=accepted
    PKIMessage Body Type Must Be    ${response}    ip
    RETURN    ${response}
