# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
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


*** Variables ***
# normally this would be provided from the command line
${environment}      cloudpki


*** Test Cases ***
# BIG TODO fix all the calls to Build P10cr... to Generate Default MAC Protected PKIMessage.
# or just ir MAC based.

# TODO move.

CA Must Issue Certificate Via P10cr Without implicitConfirm
    [Documentation]    According to RFC 9483, Section 4.1.4, the server should issue a certificate in response to a
    ...    valid p10cr request, even if implicit confirmation is not set. This test verifies that the
    ...    server correctly waits for an explicit confirmation from the End Entity (EE) before finalizing
    ...    the issuance.
    ${parsed_csr}=    Load And Parse Example CSR
    ${p10cr}=    Build P10cr From CSR
    ...    csr=${parsed_csr}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_p10cr}=    Protect Pkimessage    ${p10cr}    protection=pbmac1    password=${PRESHARED_SECRET}
    Log Asn1    ${protected_p10cr}
    # send initial request
    ${encoded}=    Encode To Der    ${protected_p10cr}
    Log Base64    ${encoded}
    ${response}=    Exchange Data With CA    ${encoded}
    ${pki_message}=    Parse PKIMessage    ${response.content}
    # could also be ip, kup, cp; consider examining the tag; the overall structure is CertRepMessage
    PKIMessage Body Type Must Be    ${pki_message}    cp
    # prepare confirmation message by extracting the certificate and getting the needed data from it
    ${cert}=    Get Cert From PKIMessage    ${pki_message}
    ${conf_message}=    Build Cert Conf    ${cert}
    ${protected_conf_message}=    Protect PKIMessage
    ...    ${conf_message}
    ...    protection=pbmac1
    ...    password=${PRESHARED_SECRET}
    ${encoded}=    Encode To Der    ${protected_conf_message}
    Log Base64    ${encoded}
    ${response}=    Exchange Data With CA    ${encoded}
    ${pki_message}=    Parse PKIMessage    ${response.content}
    ${response_type}=    Get Cmp Message Type    ${pki_message}
    PKIMessage Body Type Must Be    ${pki_message}    cp
    PKIStatus Must Be  ${pki_message}  status=accepted

CA MUST Support IR With implicitConfirm And PBMAC1 Protection
    [Documentation]    According to RFC 9483, Sections 3.1 and 4, the CA must support handling Initialization Requests
    ...    that include the `implicitConfirm` extension and are protected using PBMAC1. We send a valid
    ...    Initialization Request that is PBMAC1-protected and includes the `implicitConfirm` extension.
    ...    The CA MUST process the request, respond with a valid PKI message, and issue a valid certificate.
    [Tags]    ak    ir    rfc9483-header
    Skip If
    ...    not ${ALLOW_IR_MAC_BASED}
    ...    This test is skipped, because MAC-based-protection is not allowed for ir messages.
    Skip If    not ${ALLOW_IMPLICIT_CONFIRM}    This test is skipped because certificates need to be confirmed.
    ${csr_signed}    ${key}=    Generate CSR For Testing
    ${pki_message}=    Build IR From Csr
    ...    ${csr_signed}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=pbmac1
    ...    password=${PRESHARED_SECRET}
    ${pki_message}=    Exchange PKIMessage    ${protected_pki_message}
    ${pki_header}=    Get Asn1 Value    ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce
    Validate Sender And Recipient Nonce    ${pki_message}    ${protected_pki_message}
    PKIMessage Must Contain ImplicitConfirm Extension    ${pki_message}
    ${der_cert}=    Get Asn1 Value As DER    ${pki_message}    extraCerts/0
    Log Base64    ${der_cert}
    Certificate Must Be Valid    ${der_cert}
    Response Time Must Be Fresh    ${protected_pki_message}    ${pki_message}
    MAC Protection Algorithms Must Match
    ...    ${protected_pki_message}
    ...    ${pki_message}
    ...    strict=${STRICT_MAC_VALIDATION}
    Verify PKIMessage Protection    ${pki_message}
    PKIMessage Body Type Must Be    ${pki_message}    ip

# TODO check test cases above!

#### Section 3.1 General Description of the CMP Message Header

# Body independent, which is why the documentation says "We send a PKIMessage..."

Response PKIMessage Header Must Include All Required Fields
    [Documentation]    According to RFC 9483, Section 3 and 4, the server must include required fields in the
    ...    PKIMessage header when responding to a PKCS #10 certificate request (p10cr). This test
    ...    verifies that the server response contains header fields such as pvno, sender, recipient,
    ...    protectionAlg, transactionID, and senderNonce.
    [Tags]    headers    p10cr    rfc9483-header
    ${csr_signed}    ${key}=    Generate CSR For Testing
    Log    ${csr_signed}
    ${p10cr}=    Build P10cr From CSR
    ...    ${csr_signed}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_p10cr}=    Protect PKIMessage    ${p10cr}    protection=pbmac1    password=${PRESHARED_SECRET}
    ${pki_message}=    Exchange PKIMessage    ${protected_p10cr}
    ${pki_header}=    Get Asn1 Value    ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce
    Sender And Recipient Nonces Must Match    ${protected_p10cr}    ${pki_message}
    SenderNonce Must Be At Least 128 Bits Long    ${pki_message}
    PKIMessage Must Contain ImplicitConfirm Extension    ${pki_message}
    ${der_cert}=    Get Asn1 Value As DER    ${pki_message}    extraCerts/0
    Log Base64    ${der_cert}
    Certificate Must Be Valid    ${der_cert}
    ${cert}=    Get Cert From PKIMessage    ${pki_message}
    Response Time Must Be Fresh    ${protected_p10cr}    ${pki_message}
    MAC Protection Algorithms Must Match    ${protected_p10cr}    ${pki_message}
    Verify PKIMessage Protection    ${pki_message}
    PKIMessage Body Type Must Be    ${pki_message}    cp

# TODO extract cert if positive. or just use loop for all needed certificates.
# TODO maybe only LwCMP.

CA MUST Reject PKIMessage With Version Other Than 2 Or 3
    [Documentation]    According to RFC 9483 Section 3.1, PKIMessages must specify a protocol version number (`pvno`)
    ...    of either 2 or 3 to be considered valid. We send an Initialization Request with `pvno` set to 1.
    ...    The CA MUST reject the request, and the response may include the failinfo `unsupportedVersion`.
    [Tags]    negative    rfc9483-header    version
    ${pki_message}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    pvno=1
    ...    recipient=${RECIPIENT}
    ...    omit_field=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=unsupportedVersion    exclusive=True

# TODO maybe only LwCMP
# TODo fix body.

CA MUST Reject PKIMessage Without `directoryName` In Sender Field For MAC Protection
    [Documentation]    According to RFC 9483 Section 3.1, for MAC-based protection, the `sender` field in a PKIMessage
    ...    header must contain common name inside a the `directoryName` choice that matches the `senderKID`
    ...    to ensure authentication. We send a 'p10cr' Certification Request with MAC-based protection where the
    ...    `sender` field is not inside the `directoryName` choice, but is of type `rfc822Name`. The CA
    ...    MUST reject this request and may respond with the optional failinfo `badMessageCheck`, as
    ...    specified in Section 3.5.
    [Tags]    negative    protection    rfc9483-header    sender
    ${pki_message}=    Build P10cr From CSR    ${EXP_CSR}    sender=${SENDER}    recipient=${RECIPIENT}
    ${protected_p10cr}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject PKIMessage With Invalid Sender Field For Signature Based Protection
    [Documentation]    According to RFC 9483 Section 3.1, when using signature-based protection, the `sender` field
    ...    in a PKIMessage header must contain the subject name from the certificate associated with the
    ...    private key used for signing. We send a PKIMessage with signature-based protection but set the
    ...    `sender` field to an invalid value that does not match the subject name of the signing
    ...    certificate. The CA MUST reject the request, and the response may include the failinfo
    ...    `badMessageCheck`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    sender    signature
    ${pki_message}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${pki_message}=    Patch Sender    msg_to_patch=${pki_message}    cert=${ISSUED_CERT}    subject=False
    ${protected_p10cr}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    no_patch=True
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject PKIMessage Without messageTime
    [Documentation]    According to RFC 9483 Section 3.1, a PKIMessage must contain a valid `messageTime` field to ensure
    ...    proper validation and prevent replay attacks. We send a PKIMessage without the `messageTime` field.
    ...    The CA MUST reject the request, and the response may include the failinfo `badTime`, as specified
    ...    in Section 3.5.
    [Tags]    negative    rfc9483-header    strict    time
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=messageTime,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badTime    exclusive=True

CA MUST Reject PKIMessage With messageTime Outside Allowed Window
    [Documentation]    According to RFC 9483 Section 3.1, the `messageTime` in a PKIMessage must fall within a defined
    ...    time window to ensure message freshness and prevent replay attacks. We send a PKIMessage with a
    ...    `messageTime` outside the allowed interval. The CA MUST reject the request, and the response may
    ...    include the failinfo `badTime`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    strict    time
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    sender=${SENDER}
    ...    exclude_fields=messageTime,sender,senderKID
    ...    recipient=${RECIPIENT}
    ${date_object}=    Get Current Date    increment=${MAX_ALLOW_TIME_INTERVAL_RECEIVED}
    ${ir}=    Patch MessageTime    ${ir}    ${date_object}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badTime    exclusive=True

CA MUST Reject PKIMessage With A Long Passed messageTime
    [Documentation]    According to RFC 9483 Section 3.1, a PKIMessage must contain a valid `messageTime` field to ensure
    ...    proper validation and prevent replay attacks. We send a PKIMessage with a `messageTime` set to a
    ...    long-past date. The CA MUST reject the request, and the response may include the failinfo `badTime`,
    ...    as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    strict    time
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=messageTime,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${ir}=    Patch MessageTime    ${ir}    2024-01-01 15:30:00.000000
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badTime    exclusive=True

# TODO fix PKIBody.

CA MUST Reject PKIMessage With Different MAC Protection Algorithm Than MSG_MAC_ALG
    [Documentation]    According to RFC 9483 Section 3.1 and RFC 9481 Section 6.1, the CA must enforce the use of MAC
    ...    algorithms specified in `MSG_MAC_ALG` for requests protected by MAC. We send a PKIMessage protected
    ...    by a MAC algorithm not listed in `MSG_MAC_ALG`, such as `hmac`. The CA MUST reject the request, and
    ...    the response may include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    protectionAlg    rfc9483-header
    Skip If    not ${LWCMP}    This test is only for LwCMP.
    ${p10cr}=    Build P10cr From CSR    ${EXP_CSR}    sender=${SENDER}    recipient=${RECIPIENT}
    ${protected_p10cr}=    Protect PKIMessage    ${p10cr}    protection=hmac    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

# TODO add case with valid cert and not ski!, even though it is bad practise and will not be accepted by pkilint.

CA MUST Reject Signature Protected PKIMessage Without SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using signature-based protection, a PKIMessage must
    ...    include a valid `senderKID` that matches the `SubjectKeyIdentifier` from the CMP protection
    ...    certificate. We send a PKIMessage with signature-based protection but omit the `senderKID` field.
    ...    The CA MUST reject the request, and the response may include the failinfo `badMessageCheck`,
    ...    as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderKID    signature
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${ir}=    Patch Sender
    ...    ${ir}
    ...    cert=${ISSUED_CERT}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    no_patch=True
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject Signature Protected PKIMessage With Invalid SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using signature-based protection, the `senderKID` field
    ...    in a PKIMessage must match the `SubjectKeyIdentifier` from the CMP protection certificate.
    ...    We send a PKIMessage with signature-based protection where the `senderKID` does not match
    ...    the `SubjectKeyIdentifier` of the signing certificate. The CA MUST reject the request, and
    ...    the response may include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderKID    signature
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${ski_bytes}=    Get Field From Certificate
    ...    cert=${ISSUED_CERT}
    ...    extension=ski
    ${modified_ski_bytes}=    Manipulate First Byte    ${ski_bytes}
    ${ir}=    Patch SenderKID
    ...    ${ir}
    ...    sender_kid=${modified_ski_bytes}
    ${ir}=    Patch Sender
    ...    ${ir}
    ...    cert=${ISSUED_CERT}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    no_patch=True
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

# TODO fix PKIBody

CA MUST Reject MAC Based Protected PKIMessage Without SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using MAC-based protection, a PKIMessage must include a
    ...    `senderKID` that matches the sender's `common name` field. We send a PKIMessage with MAC-based
    ...    protection but omit the `senderKID` field. The CA MUST reject the request, and the response may
    ...    include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    rfc9483-header    senderKID
    ${p10cr}=    Build P10cr From CSR
    ...    ${EXP_CSR}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=senderKID
    ${protected_p10cr}=    Protect PKIMessage
    ...    ${p10cr}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject MAC Protected PKIMessage With Invalid SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, the `senderKID` field in a MAC-protected PKIMessage must
    ...    match the sender's common name inside the directoryName choice. We send a PKIMessage with
    ...    MAC-based protection and modify the `senderKID` so that it does not match the sender�s common
    ...    name. The CA MUST reject the request, and the response may include the failinfo
    ...    `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    rfc9483-header    senderKID
    ${pki_message}=    Build P10cr From CSR    ${EXP_CSR}    exclude_fields=senderKID,sender recipient=${RECIPIENT}
    ${pki_message}=    Patch Sender    ${pki_message}    sender_name=${SENDER}
    ${pki_message}=    Patch SenderKID    ${pki_message}    for_mac=True    negative=True
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

FailInfo Bit Must Be badDataFormat For Missing transactionID
    [Documentation]    According to RFC 9483 Section 3.5, each PKIMessage must include a `transactionID` to uniquely
    ...    identify the transaction. We send a PKIMessage omitting the `transactionID`. The CA MUST reject
    ...    the request, and the response may include the failinfo `badDataFormat`.
    [Tags]    negative    rfc9483-header    transactionId
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=transactionId,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badDataFormat    exclusive=True

CA MUST Reject PKIMessage If transactionId Is Already In Use
    [Documentation]    According to RFC 9483 Section 3.5, the CA must validate the uniqueness of the `transactionID`
    ...    for each new transaction. If a `transactionID` that is already in use is detected, the CA MUST
    ...    terminate the operation and reject the request. The response may include the failinfo
    ...    `transactionIdInUse`. We send two PKIMessages with the same `transactionID`, expecting the CA
    ...    to process the first request successfully and reject the second as a duplicate.
    [Tags]    negative    rfc9483-header    transactionId
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    exclude_fields=transactionId,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${ir}=    Patch TransactionID    ${ir}    0123456789012345678901234567891
    ${ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${csr2}    ${key2}=    Generate CSR For Testing
    ${ir2}=    Build Ir From CSR
    ...    ${csr2}
    ...    ${key2}
    ...    exclude_fields=transactionId,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${patched_ir2}=    Patch TransactionID    ${ir2}    0123456789012345678901234567891
    ${protected_ir2}=    Protect PKIMessage
    ...    pki_message=${patched_ir2}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${resp}=    Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${resp}    ip
    ${der_data}=    Encode To Der    ${protected_ir2}
    ${response}=    Exchange Data With CA    ${der_data}
    ${resp2}=    Parse PKIMessage    ${response.content}
    PKIMessage Body Type Must Be    ${resp2}    error
    PKIStatusInfo Failinfo Bit Must Be    ${resp2}    failinfo=transactionIdInUse    exclusive=True

CA MUST Reject PKIMessage Without senderNonce
    [Documentation]    According to RFC 9483 Section 3.5, the `senderNonce` field in a PKIMessage must contain at least
    ...    128 bits of random data to ensure secure transaction tracking and prevent replay attacks.
    ...    We send a PKIMessage without the `senderNonce` field. The CA MUST reject the message,
    ...    and the response may include the failinfo `badSenderNonce`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderNonce
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    exclude_fields=senderNonce,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce    exclusive=True

CA MUST Reject PKIMessage With Too Short senderNonce
    [Documentation]    According to RFC 9483 Section 3.5, the `senderNonce` in a PKIMessage must be present and contain
    ...    at least 128 bits of secure, random data to ensure proper validation and prevent replay attacks.
    ...    We send a PKIMessage    with a `senderNonce` that is only 32 bits long. The CA MUST reject this
    ...    request, and the response may include the failinfo `badSenderNonce`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderNonce
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    exclude_fields=senderNonce,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${ir}=    Patch SenderNonce
    ...    ${ir}
    ...    sender_nonce=0x12345678
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badSenderNonce    exclusive=True

CA MUST Reject First PKIMessage With recipNonce
    [Documentation]    According to RFC 9483 Section 3.1, the `recipNonce` field must be absent in the initial
    ...    PKIMessage of a CMP transaction. Including `recipNonce` in the first message violates protocol
    ...    requirements, as this field is reserved for the response message. We send a PKIMessage with a
    ...    included `recipNonce`. The CA MUST reject the message, and the response may include the failinfo
    ...    `badRecipientNonce` or `badRequest`, as specified in Section 3.5.
    [Tags]    negative    recipNonce    rfc9483-header
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    exclude_fields=recipNonce,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${ir}=    Patch RecipNonce    ${ir}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRecipientNonce,badRequest    exclusive=True

### generalInfo

CA MUST Reject PKIMessage With Invalid ImplicitConfirmValue
    [Documentation]    According to RFC 9483 Section 3.1, when a PKIMessage with an `ImplicitConfirmValue` must have
    ...    this value set to `NULL` if present. We send a PKIMessage with an invalid `ImplicitConfirmValue`
    ...    , expecting the CA to reject the request due to the non-NULL value. The response may include the
    ...    failinfo `badRequest`.
    [Tags]    negative    rfc9483-header    strict
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${ir}=    Patch GeneralInfo
    ...    pki_message=${ir}
    ...    implicit_confirm=True
    ...    neg_info_value=True
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest    exclusive=True

CA MUST Reject PKIMessage With UTCTime inside ConfirmWaitTimeValue
    [Documentation]    According to RFC 9483 Section 3.1, when a PKIMessage includes a `confirmWaitTime` value set in the
    ...    `generalInfo` field, the value must be of type `generalizedTime`. Using a `UTCTime` format for
    ...    `confirmWaitTime` violates the protocol requirements. We send a PKIMessage with a `confirmWaitTime`
    ...    value in `UTCTime` format, expecting the CA to reject the message. The CA MUST reject this request,
    ...    and the response may include the failinfo `badRequest` or `badDataFormat`.
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${ir}=    Patch GeneralInfo
    ...    pki_message=${ir}
    ...    confirm_wait_time=500
    ...    neg_info_value=True
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest,badDataFormat

CA MUST Reject PKIMessage With ImplicitConfirm And ConfirmWaitTime
    [Documentation]    According to RFC 9483 Section 3.1, if `ImplicitConfirm` is set in a PKIMessage, the
    ...    `ConfirmWaitTime` field must not be present, as the two fields are mutually exclusive.
    ...    We send a PKIMessage with both `ImplicitConfirm` and `ConfirmWaitTime` set, expecting
    ...    the CA to reject the message due to the conflicting fields. The CA MUST reject this request,
    ...    and the response may include the failinfo `badRequest`.
    [Tags]    negative    rfc9483-header    strict
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${ir}=    Patch GeneralInfo
    ...    pki_message=${ir}
    ...    implicit_confirm=True
    ...    confirm_wait_time=400
    ...    neg_info_value=True
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest   exclusive=True


# TODO add test case to check support for CertProfile
# TODO add test case to check validation if send more then one, different ones for CertProfile
# TODO add test case to check if confirmWaitTime was received and used by CA, RA.

#### Section 3.2 General Description of the CMP Message Protection

CA MUST Reject PKIMessage With Invalid Signature Protection Value
    [Documentation]    According to RFC 9483 Section 3.2, when using signature-based protection, PKIMessages must
    ...    include a valid protection value that corresponds to the `protectionAlg` field. We send a `p10cr` PKIMessage
    ...    with a signature-based `protectionAlg` set, but we modify the protection value to an invalid one. The CA MUST
    ...    reject this request and may respond with the optional `badMessageCheck`, as specified in Section 3.5.
    [Tags]    signature    negative    protection
    ${protected_ir}=    Generate Default IR Sig Protected
    ${patched_protected_ir}=    Modify PKIMessage Protection    ${protected_ir}
    ${response}=    Exchange PKIMessage    ${patched_protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

CA MUST Reject PKIMessage With Invalid MAC Protection Value
    [Documentation]    According to RFC 9483 Section 3.2, when using MAC-based protection, PKIMessages must include a
    ...    valid protection value that corresponds to the `protectionAlg` field. We send a `p10cr` PKIMessage with a
    ...    MAC-based `protectionAlg` set, but we modify the protection value to an invalid one. The CA MUST
    ...    reject this request and may respond with the optional `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    protection
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped this test because MAC-based protection is disabled.
    ${pki_message}=    Generate Default MAC Protected PKIMessage
    ${patched_message}=    Modify PKIMessage Protection    ${pki_message}
    ${response}=    Exchange PKIMessage    ${patched_message}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

CA MUST Reject PKIMessage With Protection Value But No protectionAlg
    [Documentation]    According to RFC 9483 Section 3.2, PKI messages must specify both a `protectionAlg` and a corresponding
    ...    protection value if protection is applied. We send a `p10cr` PKIMessage that includes a
    ...    protection value but omits the `protectionAlg` field. The CA MUST reject this request may respond with
    ...    the optional failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    protection
    ${p10cr}=    Build P10cr From CSR
    ...    ${EXP_CSR}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${False}
    ${patched_protected_p10cr}=    Modify PKIMessage Protection    ${p10cr}
    ${response}=    Exchange PKIMessage    ${patched_protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

CA MUST Reject PKIMessage With MAC Based protectionAlg But No Protection Value
    [Documentation]    According to RFC 9483 Section 3.2, PKI messages that include a `protectionAlg` field must also
    ...    contain a corresponding protection value. We send a `cr` PKIMessage with a MAC based
    ...    `protectionAlg` set, but the protection value is missing. The CA MUST reject this request and
    ...    may respond with the optional failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    protection
    ${p10cr}=    Build P10cr From CSR
    ...    ${EXP_CSR}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${False}
    ${patched_protected_p10cr}=    Patch ProtectionAlg    ${p10cr}    protection=${DEFAULT_MAC_ALGORITHM}
    ${response}=    Exchange PKIMessage    ${patched_protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck,badRequest   exclusive=True


CA MUST Reject PKIMessage With Signature Based protectionAlg But No Protection Value
    [Documentation]    According to RFC 9483 Section 3.2, PKIMessages that include a `protectionAlg` field must also
    ...    contain a corresponding protection value. We send a PKIMessage with a signature-based
    ...    `protectionAlg` set, but the protection value is omitted. The CA MUST reject this request,
    ...    and the response may include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    negative    protection    signature
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${ir}=    Build IR From Key
    ...    ${key}
    ...    sender=${SENDER}
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${patched_ir}=    Patch ProtectionAlg    ${ir}    private_key=${key}
    ${response}=    Exchange PKIMessage    ${patched_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

#### Section 3.3 General Description of CMP Message ExtraCerts

CA MUST Reject PKIMessage With Incorrect Protection Certificate Position
    [Documentation]    According to RFC 9483 Section 3.3, when using signature-based protection, the `extraCerts` field
    ...    must include the complete certificate chain necessary to verify the signature, with the
    ...    protection certificate placed at index 0. We send a PKIMessage with the protection
    ...    certificate positioned at the second index in the `extraCerts` field. The CA MUST reject this
    ...    request, and the response may include the failinfo `badMessageCheck`, as specified in
    ...    Section 3.5.
    [Tags]    extraCert    negative    rfc9483-validation    robot:skip-on-failure
    # can fail based on the issuer certificate.
    ${cert_chain}=    Build Cert Chain From Dir    ${ISSUED_CERT}    data/cert_logs
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    exclude_certs=True
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${patched_ir}=    Patch ExtraCerts    ${protected_ir}    ${cert_chain}    negative=True
    ${response}=    Exchange PKIMessage    ${patched_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

CA MUST Reject Requests With Signature Protection But Without extraCerts
    [Documentation]    According to RFC 9483 Section 3.3, when using signature-based protection, the `extraCerts` field
    ...    must include the complete certificate chain necessary to verify the signature. We send a
    ...    PKIMessage with signature-based protection but omit the `extraCerts` field. The CA MUST
    ...    reject this request, and the response may include the failinfo `badMessageCheck`, as specified
    ...    in Section 3.5.
    [Tags]    ak    extraCert    negative    rfc9483-validation
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${ir}=    Build IR From Key
    ...    ${key}
    ...    common_name=${cm}
    ...    exclude_fields=senderKID,sender
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${patched_ir}=    Patch Sender    ${ir}    cert=${ISSUED_CERT}
    ${protected_cr}=    Protect PKIMessage
    ...    ${patched_ir}
    ...    exclude_certs=True
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck,signerNotTrusted   exclusive=True
    # Verify StatusString    ${response}    any_text=no extra certs,no extraCerts    index=0

CA MUST Reject Signature Protected PKIMessage Without Complete Certificate Chain
    [Documentation]    According to RFC 9483 Section 3.3, when a PKIMessage is signature-protected, the `extraCerts`
    ...    field must include the complete certificate chain necessary for verifying the signature. We
    ...    send a PKIMessage with signature-based protection, containing only the end entity certificate
    ...    in the `extraCerts` field. The CA MUST reject this request, and the response may include the
    ...    failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    ak    extraCert    negative    rfc9483-validation
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${ir}=    Build IR From Key
    ...    ${key}
    ...    common_name=${cm}
    ...    exclude_fields=senderKID,sender
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    exclude_certs=True
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    VAR    @{my_list}    ${ISSUED_CERT}
    ${patched_cr}=    Patch ExtraCerts    ${protected_ir}    ${my_list}
    ${response}=    Exchange PKIMessage    ${patched_cr}
    PKIStatusInfo Failinfo Bit Must Be      ${response}    failinfo=badMessageCheck,signerNotTrusted

#### Section 3.5 Generic Validation of PKI Message

# TODO fix

CA Must Validate The Received PKI Message
    [Documentation]    Upon reception the CA must take specific validation steps before further processing.
    ...    If the CA decides to terminate the operation because of a failed check, it must send a negative
    ...    response or error message.
    ...    Ref.: 3.5. Generic Validation of PKI Message
    [Tags]    header    positive    rfc9483-validation
    ${ir}=    Generate Default IR Sig Protected
    ${response}=    Exchange PKIMessage    ${ir}
    Validate PKIMessage Header    ${response}    ${ir}
    MAC Protection Algorithms Must Match    ${ir}    ${response}    strict=${STRICT_MAC_VALIDATION}

##### Section 4

# TODO fix doc

CA MUST Reject IR With More Than One CertReqMsg Inside The IR
    [Documentation]    According to RFC 9483 Section 4.1.1, an Initialization Request (IR) must contain exactly one
    ...    `CertReqMsg` to be valid. Including more than one `CertReqMsg` in an IR violates protocol
    ...    requirements. We send an IR containing two `CertReqMsg` entries, expecting the CA to reject
    ...    the request. The CA MUST reject this request and may respond with the optional failinfo
    ...    `badRequest` or `systemFailure`, as specified in Section 3.5.
    [Tags]    ir    lwcmp    negative
    Skip If    ${LWCMP}    Skipped because this test ins only for LwCMP.
    ${key}=    Generate Default Key
    ${key2}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${cm2}=    Get Next Common Name
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}    common_name=${cm}
    ${cert_req_msg2}=    Prepare CertReqMsg    ${key2}    common_name=${cm2}
    VAR    @{msgs}    ${cert_req_msg}    ${cert_req_msg2}
    ${ir}=    Build IR From Key    signing_key=${None}    cert_req_msg=${msgs}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    exclude_certs=True
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    body_type=ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfos=badRequest,systemFailure

#### Section 4.1 cr,ir,kur

CA MUST Reject IR Request With Untrusted Anchor
    [Documentation]    According to RFC 9483 Section 4.1.1, when an End Entity (EE) requests a certificate, it must
    ...    either use MAC-based protection or prove, using a valid certificate and the corresponding
    ...    private key, that it is authorized to make the request. In this test case, we send an IR
    ...    request using a certificate signed by an untrusted anchor. The CA MUST reject the request
    ...    and may respond with the optional failinfo `signerNotTrusted`, as specified in Section 3.5.
    [Tags]    ir    negative    trust
    ${cert}    ${key}=    Build Certificate    ski=True    common_name=${SENDER}
    ${cert_template}=    Prepare CertTemplate    cert=${cert}
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${key}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${key}
    ...    cert=${cert}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatusInfo Failinfo Bit Must Be    ${response}     failinfo=signerNotTrusted

CA MUST Reject CR With Other PKI Management Entity Request
    [Documentation]    According to RFC 9483 Section 4.1.2, the certificate used by the End Entity (EE) to request a
    ...    certificate must have been issued by the PKI that it is requesting the certificate from.
    ...    In this test case, we send a `cr` message that is signed by a device certificate from a
    ...    different PKI. The CA must reject the request and may respond with the optional failinfo
    ...    `notAuthorized` or `badRequest`, as specified in Section 3.5.
    [Tags]    cr    negative    robot:skip-on-failure
    Skip If    not ${ALLOW_CR}    Skipped because the cr `PKIBody` is disabled.
    ${is_set}=    Is Certificate And Key Set    ${DEVICE_CERT}    ${DEVICE_KEY}
    Skip If    not ${is_set}    The `DEVICE_CERT` and/or `DEVICE_KEY` variable is not set, skipping test.
    ${cert_chain}=    Build Cert Chain From Dir    ee_cert=${DEVICE_CERT}    cert_dir=./certs
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Cr From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${DEVICE_KEY}
    ...    cert=${DEVICE_CERT}
    ...    cert_chain=${cert_chain}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    cp
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized,badRequest

CA MUST Reject Valid IR With Same Key
    [Documentation]    According to RFC 9483 and based on the CA's policy, a valid Initialization Request (IR) using
    ...    a key that has already been certified may either be accepted or rejected. We send a valid IR
    ...    request with a key that was previously certified. If the request is rejected, the CA may respond
    ...    with the optional failinfo `badCertTemplate`. If accepted, the CA MUST issue a new certificate.
    [Tags]    certTemplate    config-dependent    ir    negative
    Skip If    ${ALLOW_IR_SAME_KEY}    The same key is allowed for multiple certificates.
    ${cert_template}=    Prepare CertTemplate
    ...    cert=${ISSUED_CERT}
    ...    key=${ISSUED_KEY}
    ...    include_fields=publicKey,subject,extensions
    ${pki_message}=    Build IR From Key
    ...    signing_key=${ISSUED_KEY}
    ...    ee_cert=${ISSUED_CERT}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate

##### Section 4 General CertReqMsg Checks

# checks are done with IR, because IR is the only mandatory body.

CA MUST Reject IR With Missing Signature Inside POPO Structure
    [Documentation]    According to RFC 9483 Section 4.1.3, when an Initialization Request (IR) is sent for a key capable
    ...    of signing data, the Proof-of-Possession (POPO) structure must include a valid signature of the
    ...    `CertRequest` to prove that the private key is owned by the End-Entity. We send an IR message
    ...    with a key that can sign data, but omit the signature value in the `CertRequest`. The CA MUST
    ...    reject the request, and the response may include the optional failinfo `badPOP`.
    [Tags]    ir    negative    popo
    ${cm}=    Get Next Common Name
    ${key}=    Generate Default Key
    ${popo}=    Prepare POPO
    ...    signing_key=${key}
    ...    hash_alg=sha256
    ${pki_message}=    Build IR From Key
    ...    popo=${popo}
    ...    signing_key=${key}
    ...    common_name=${cm}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP

CA MUST Reject IR With Missing POPO Structure For Key Allowed For Signing
    [Documentation]    According to RFC 9483, Section 4.1.3, when an initialization request (ir) is received for a key
    ...    that can be used to sign data, the request must the Proof-of-Possession (POPO) structure, with
    ...    a valid signature of the `CertRequest` structure, to proof, that the private key is owned by the
    ...    End-Entity. We send a ir message with a key capable of signing but without `POPO` structure. The
    ...    CA MUST reject the request. The CA and may respond with the optional failinfo "badPOP".
    [Tags]    negative    popo
    ${cm}=    Get Next Common Name
    ${key}=    Generate Key    rsa
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}    common_name=${cm}    exclude_popo=True
    ${pki_message}=    Build IR From Key
    ...    signing_key=${key}
    ...    cert_req_msg=${cert_req_msg}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP

CA MUST Reject IR With Mismatched SignatureAlgorithm And PublicKey In CertTemplate
    [Documentation]    According to RFC 9483, Section 4.1.3, when an initialization request (ir) is submitted, the CA
    ...    expects consistency between the signature algorithm and public key specified in the CertTemplate.
    ...    We send an IR where the signature algorithm does not match the provided public key, and
    ...    expects the CA to reject the request. The CA should respond with failinfo codes `badPOP` and
    ...    `badCertTemplate` to indicate the detected inconsistency.
    [Tags]    certTemplate    negative    popo
    ${cm}=    Get Next Common Name
    ${key1}=    Generate Key    rsa
    ${key2}=    Generate Key    dsa
    ${cert_req}=    Prepare CertRequest    key=${key2}    common_name=${cm}
    ${der_cert_req}=    Encode To Der    ${cert_req}
    ${signature}=    Sign Data    data=${der_cert_req}    key=${key1}    hash_alg=sha256
    ${popo}=    Prepare POPO    signature=${signature}    signing_key=${key1}    hash_alg=sha256
    ${pki_message}=    Build IR From Key
    ...    popo=${popo}
    ...    signing_key=${key2}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badPOP,badCertTemplate

CA MUST Reject IR With Valid Proof-of-Possession And raVerified From EE
    [Documentation]    According to RFC 9483, Section 4.1.3, when an End Entity (EE) includes a valid Proof-of-Possession
    ...    (POPO) in a certificate request but sets `raVerified` on its own, the CA must reject the request
    ...    as unauthorized. We send a Initialization request without POPO but with `raVerified` set by the
    ...    EE, expecting the CA to respond with a failinfo indicating `notAuthorized`.
    [Tags]    negative    popo
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${pki_message}=    Build IR From Key
    ...    common_name=${cm}
    ...    ra_verified=True
    ...    signing_key=${new_key}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIStatus Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=notAuthorized

# TODO verify FailInfo!

CA MUST Reject IR With Invalid CertReqId
    [Documentation]    According to RFC 9483, Section 4.1.3, the `certReqId` field in an initialization request (ir)
    ...    must be set to 0 to indicate a valid request. We send an IR with an invalid `certReqId`
    ...    value of -1, expecting the CA to reject the request. The CA should respond with a failinfo code
    ...    of `badDataFormat` or `badRequest` to signal the invalid format or content of the `certReqId`.
    [Tags]    certReqID    ir    negative
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${ir}=    Build IR From Key
    ...    common_name=${cm}
    ...    cert_req_id=-1
    ...    signing_key=${new_key}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate,badDataFormat    exclusive=True

#### CertTemplate structure

CA MUST Reject IR With Missing Subject In CertTemplate
    [Documentation]    According to RFC 9483, Section 4.1.3, the `subject` field is mandatory in the CertTemplate for
    ...    a Initialization request. We send a IR with a CertTemplate that omits the `subject`
    ...    field, expecting the CA to reject the request. The CA should respond with a failinfo of
    ...    `badCertTemplate` to indicate the missing required field.
    [Tags]    certTemplate    ir    negative
    ${cm}=    Get Next Common Name
    ${new_key}=    Generate Default Key
    ${cert_template}=    Prepare CertTemplate    include_fields=publicKey    key=${new_key}
    ${pki_message}=    Build IR From Key
    ...    common_name=${cm}
    ...    signing_key=${new_key}
    ...    cert_template=${cert_template}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badCertTemplate

### Key Related

CA MUST Issue A ECC Certificate With A Valid IR
    [Documentation]    According to RFC 9483, Section 4.1.3, when the CA receives a valid initialization request (ir)
    ...    containing an Elliptic Curve Cryptography (ECC) key, it should issue an ECC certificate if the
    ...    algorithm is allowed by CA policy. We send an IR with an ECC key. The CA issues a
    ...    certificate when the request meets all requirements. If ECC is unsupported, the CA should
    ...    respond with a failinfo of `badCertTemplate` or `badAlg`.
    [Tags]    ir    key    positive   robot:skip-on-failure
    ${result}=    Should Contain    ${ALLOWED_ALGORITHM}    ecc
    ${ecc_key}=    Generate Key    ecc    curve=${DEFAULT_ECC_CURVE}
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement,digitalSignature
    ${pki_message}=    Build IR From Key
    ...    extensions=${extensions}
    ...    signing_key=${ecc_key}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${ECDSA_CERT}    ${cert}    scope=GLOBAL
    VAR    ${ECDSA_KEY}    ${ecc_key}    scope=GLOBAL

CA MAY Issue A Ed25519 Certificate With A Valid IR
    [Documentation]    According to RFC 9483, Section 4.1.3, the CA may issue a certificate for a valid initialization
    ...    request (ir) containing an Ed25519 key if its policy allows this algorithm. We send an ir
    ...    message with an Ed25519 key and expects the CA to issue a certificate if Ed25519 is supported.
    ...    If not, the CA should respond with the failinfo set to `badCertTemplate` or `badAlg`.
    [Tags]    key    positive   robot:skip-on-failure
    ${result}=    Should Contain    ${ALLOWED_ALGORITHM}    ed25519
    ${ecc_key}=    Load Private Key From File    ./data/keys/private-key-ed25519.pem    key_type=ed25519
    ${extensions}=    Prepare Extensions    key_usage=digitalSignature
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${ecc_key}
    ...    extensions=${extensions}
    ...    common_name=${SENDER}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${Ed25519_CERT}    ${cert}    scope=GLOBAL
    VAR    ${Ed25519_KEY}    ${ecc_key}    scope=GLOBAL

# TODO fix test case!,
# done in next merge Request.

CA Must Accept No POPO For Request With X25519 Key
    [Tags]    ir    key    popo    positive    robot:skip-on-failure
    Skip    Not implemented yet.
    ${result}=    Should Contain    ${ALLOWED_ALGORITHM}    x25519
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${csr_key}=    Load Private Key From File    ./data/keys/client-key-x25519.pem    key_type=x25519
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${csr_key}
    ...    common_name=${SENDER}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    pki_message=${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be        ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${X25519_CERT}    ${cert}    scope=GLOBAL
    VAR    ${X25519_KEY}    ${csr_key}    scope=GLOBAL

# TODO verify body!

CA MUST Reject IR With Invalid Algorithm
    [Documentation]    We Send a initialization request (ir) using Diffie-Hellman (DH) as the certificate algorithm and expect
    ...    the CA to reject the request. There is no such thing as a DH-certificate, and the CA should reject the
    ...    request with failinfo codes indicating `badCertTemplate`, `badRequest`, or `badPOP`.
    [Tags]    certTemplate    ir    key    negative
    ${extensions}=    Prepare Extensions    key_usage=keyAgreement
    ${csr_key}=    Generate Key    dh    length=${DEFAULT_KEY_LENGTH}
    ${pki_message}=    Build Ir From Key
    ...    signing_key=${csr_key}
    ...    extensions=${extensions}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate,badRequest

CA MUST Reject IR With Too Short RSA Key In CertTemplate
    [Documentation]    We send a initialization request (ir) with a certTemplate containing an RSA key that is shorter than
    ...    the minimum allowed size and expect the CA to reject the request. The CA should reject any request
    ...    with an RSA key that does not meet security requirements, setting a badCertTemplate failinfo.
    [Tags]    certTemplate    config dependent    ir    key    negative    robot:skip-on-failure
    # generate a key with bit size of 512
    ${bad_key}=    Generate Key    bad_rsa_key
    ${pki_message}=    Build Ir From Key
    ...    ${bad_key}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

CA MUST Reject IR With Too Large RSA Key In CertTemplate
    [Documentation]    We send a initialization request (ir) with a certTemplate containing an RSA key that exceeds the maximum
    ...    allowed size and expect the CA to reject the request. The CA should reject any request with an RSA key
    ...    that is too large, marking the request with a badCertTemplate failinfo.
    [Tags]    certTemplate    config dependent    ir    key    negative
    Skip If    ${LARGE_KEY_SIZE} == False    The `LARGE_KEY_SIZE` variable is not set, so this test is skipped.
    ${bad_key}=    Generate Key    length=${LARGE_KEY_SIZE}
    ${pki_message}=    Build Ir From Key
    ...    ${bad_key}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

CA MAY Issue A DSA Certificate
    [Documentation]    According to RFC 9483, Section 5.1.1, the CA processes certificate requests based on its policy.
    ...    When the CA receives a valid initialization request (ir) containing a DSA public key, it should
    ...    process the request accordingly. If the CA's policy allows issuing certificates with DSA keys,
    ...    it should issue the requested certificate. Otherwise, the CA must reject the request to maintain PKI integrity.
    [Tags]    ir    key    positive    robot:skip-on-failure    setup
    ${key}=    Generate Key    dsa    length=${DEFAULT_KEY_LENGTH}
    ${pki_message}=    Build Ir From Key
    ...    ${key}
    ...    common_name=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    ${cert}=    Get Cert From PKIMessage    ${response}
    PKIStatus Must Be    ${response}    status=accepted
    IF    not ${ALLOW_IMPLICIT_CONFIRM}
        ${cert_conf}=    Build Cert Conf From Resp
        ...    ${response}
        ...    exclude_fields=sender,senderKID
        ...    recipient=${RECIPIENT}
        ${protected_cert_conf}=    Protect PKIMessage
        ...    pki_message=${cert_conf}
        ...    protection=signature
        ...    private_key=${ISSUED_KEY}
        ...    cert=${ISSUED_CERTIFICATE}
        ${pki_conf}=    Exchange PKIMessage    ${protected_cert_conf}
        PKIMessage Body Type Must Be    ${pki_conf}    pkiconf
    END
    VAR    ${DSA_CERT}    ${cert}    scope=GLOBAL
    VAR    ${DSA_KEY}    ${key}    scope=GLOBAL

CA MUST Reject PKIMessage With Different Protection Algorithm Than MSG_SIG_ALG
    [Documentation]    According to RFC 9483 Section 3.1, the CA must enforce the use of algorithms specified in `MSG_SIG_ALG`
    ...    for signature-based protection. We send a 'ir' PKIMessage protected by a signature algorithm
    ...    not listed in `MSG_SIG_ALG`. The CA MUST reject this request and may respond with the optional failinfo
    ...    `badMessageCheck` as specified in Section 3.5.
    [Tags]    negative    protectionAlg    rfc9483-header    signature
    Skip If    not ${LWCMP}    This test is only for LwCMP.
    ${is_set}=    Is Certificate And Key Set    ${DSA_CERT}    ${DSA_KEY}
    Skip If    not ${is_set}    The variable DSA_CERTIFICATE is not set, skipping test.
    ${pki_message}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${DSA_CERTIFICATE_KEY}
    ...    cert=${DSA_CERTIFICATE}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    error
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badMessageCheck

### Section 4.1.3
# similar checks omitted.

CA MUST Either Reject Or Accept Valid KUR With Same Key
    [Documentation]    According to RFC 9483, Section 4.1.3 and 5, the CA MAY reject or accept Key Update Requests that
    ...    use the same key as the certificate being updated, depending on the PKI policy. If the policy does
    ...    not allow same-key updates, the CA MUST reject the request and may respond with the optional
    ...    failinfo `badCertTemplate`. Otherwise, the CA MUST accept the request and issue a new valid
    ...    certificate.
    [Tags]    certTemplate    kur    security
    Skip If    ${ALLOW_KUR_SAME_KEY}    Skipped because the same key is is allowed to be used.
    ${pki_message}=    Build Key Update Request
    ...    signing_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badCertTemplate

CA MUST Reject KUR With The Wrong Issuer Inside The Control Structure
    [Documentation]    According to RFC 9483, Section 4.1.3, the `controls` structure is recommended within a Key
    ...    Update Request to specify the certificate intended for update. This test sends a Key Update
    ...    Request where the `issuer` field inside the `controls` structure is invalid. The CA MUST reject
    ...    the request. The response may include the failinfo `badRequest`.
    [Tags]    controls    kur    negative
    ${new_private_key}=    Generate Default Key
    ${issuer}=    Modify Common Name Cert    cert=${ISSUED_CERT}    issuer=True
    ${controls}=    Prepare Controls Structure    cert=${ISSUED_CERT}    issuer=${issuer}
    ${pki_message}=    Build Key Update Request
    ...    signing_key=${new_private_key}
    ...    controls=${controls}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badRequest

CA MUST Reject KUR With Invalid serialNumber In Controls Structure
    [Documentation]    According to RFC 9483, Section 4.1.3, the `controls` structure is recommended within a Key
    ...    Update Request to specify the certificate intended for update. This test sends a Key Update
    ...    Request where the `serialNumber` field inside the `controls` structure is invalid. The CA MUST
    ...    reject the request. The response may include the failinfo `badRequest`.
    [Tags]    controls    kur    negative
    ${new_private_key}=    Generate Default Key
    ${serial_number}=    Get Field From Certificate    ${ISSUED_CERT}    query=serialNumber
    ${serial_number}=    Evaluate    ${serial_number} + 1
    ${controls}=    Prepare Controls Structure    cert=${ISSUED_CERT}    serial_number=${serial_number}
    ${pki_message}=    Build Key Update Request
    ...    signing_key=${new_private_key}
    ...    controls=${controls}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    kup
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=badRequest

# Section 4 Dependent Checks

CA Must Reject Valid IR With Already Updated Certificate
    [Documentation]    According to RFC 9483, Section 4.1.3, the CA must validate an initialization request (ir) to
    ...    ensure that the certificate is not already updated. We send a valid ir message using an already
    ...    updated certificate and expect the CA to reject the request. The CA should respond with a
    ...    `certRevoked` failinfo to indicate that the certificate cannot be used for issuance.
    [Tags]    ir    negative    update
    ${is_set}=    Is Certificate And Key Set    ${UPDATED_CERT}    ${UPDATED_KEY}
    Skip If    not ${is_set}    The `UPDATED_CERT` and/or `UPDATED_KEY` variables are not set.
    ${cert_template}    ${key}=    Generate CertTemplate For Testing
    ${pki_message}=    Build IR From Key
    ...    signing_key=${key}
    ...    cert_template=${cert_template}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=signature
    ...    private_key=${UPDATED_KEY}
    ...    cert=${UPDATED_CERT}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be      ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be   ${response}      failinfo=certRevoked   exclusive=True

##### Security checks #####

SenderNonces Must Be Cryptographically Secure
    [Documentation]    Check that the SenderNonce values from all the received PKIMessage structures are unique and
    ...    cryptographically secure. The latter is checked by computing the Hamming distance between each
    ...    pair of nonces and ensuring it is at least 10 bits.
    ...    Ref: 3.1. General Description of the CMP Message Header
    [Tags]    ak    crypto    security
    Log    ${COLLECTED_NONCES}
    ${count}=    Get Length    ${COLLECTED_NONCES}
    IF    not ${count}    Fail    The Nonces could not be extracted.
    Nonces Must Be Unique    ${COLLECTED_NONCES}
    Nonces Must Be Diverse    ${COLLECTED_NONCES}
