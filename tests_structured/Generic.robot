*** Test Cases ***

#unclear status of the usefulness of the test case
CA Must Reject Malformed Request
    [Documentation]    When we send an invalid PKIMessage to the CA, it must respond with a 400 status code to indicate
    ...    a client-side error in the supplied input data. Ref: RFC 6712 "3.3. General Form", "All applicable
    ...    "Client Error 4xx" or "Server Error 5xx" status codes MAY be used to inform the client
    ...    about errors."
    #What is the reference to the RFC 9483?
    #Why is this the minimal tag?
    [Tags]    negative    rfc6712    robot:skip-on-failure    status    minimal
    ${response}=    Exchange Data With CA    this dummy input is not a valid PKIMessage
    Should Be Equal
    ...    ${response.status_code}
    ...    ${400}
    ...    We expected status code 400, but got ${response.status_code}


# HEADER
# Section 3.1 General Description of the CMP Message Header

#pvno
CA MUST Reject PKIMessage With Version Other Than 2 Or 3
    [Documentation]    According to RFC 9483 Section 3.1, PKIMessages must specify a protocol version number (`pvno`)
    ...    of either 2 or 3 to be considered valid. We send an Initialization Request with `pvno` set to 1.
    ...    The CA MUST reject the request, and the response may include the failinfo `unsupportedVersion`.
    [Tags]    negative    rfc9483-header    version   minimal
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

CA MUST Reject PKIMessage With Version Other Than 2 Or 3
    [Documentation]    According to RFC 9483 Section 3.1, PKIMessages must specify a protocol version number (`pvno`)
    ...    of either 2 or 3 to be considered valid. We send an Initialization Request with `pvno` set to 1.
    ...    The CA MUST reject the request, and the response may include the failinfo `unsupportedVersion`.
    [Tags]    negative    rfc9483-header    version   minimal
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


#sender
CA MUST Reject PKIMessage Without `directoryName` In Sender Field For MAC Protection
    [Documentation]    According to RFC 9483 Section 3.1, for MAC-based protection, the `sender` field in a PKIMessage
    ...    header must contain common name inside a the `directoryName` choice that matches the `senderKID`
    ...    to ensure authentication. We send a 'p10cr' Certification Request with MAC-based protection where the
    ...    `sender` field is not inside the `directoryName` choice, but is of type `rfc822Name`. The CA
    ...    MUST reject this request and may respond with the optional failinfo `badMessageCheck`, as
    ...    specified in Section 3.5.
    [Tags]    negative    protection    rfc9483-header    sender   minimal
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
    [Tags]    negative    rfc9483-header    sender    signature  minimal
    ${pki_message}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${pki_message}=    Patch Sender    msg_to_patch=${pki_message}    cert=${ISSUED_CERT}    subject=False
    Log Asn1    ${pki_message["header"]["sender"]}
    ${protected_p10cr}=    Protect PKIMessage
    ...    ${pki_message}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    do_patch=${False}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True


#recipient


#messageTime
CA MUST Reject PKIMessage Without messageTime
    [Documentation]    According to RFC 9483 Section 3.1, a PKIMessage must contain a valid `messageTime` field to
    ...    ensure proper validation and prevent replay attacks. We send a PKIMessage without the `messageTime` field.
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
    ...    ${ir}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badTime    exclusive=True

CA MUST Reject PKIMessage With A Long Passed messageTime
    [Documentation]    According to RFC 9483 Section 3.1, a PKIMessage must contain a valid `messageTime` field to
    ...    ensure proper validation and prevent replay attacks. We send a PKIMessage with a `messageTime` set to a
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
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badTime    exclusive=True


#protectionAlg
CA MUST Reject PKIMessage With Different MAC Protection Algorithm Than MSG_MAC_ALG
    [Documentation]    According to RFC 9483 Section 3.1 and RFC 9481 Section 6.1, the CA must enforce the use of MAC
    ...    algorithms specified in `MSG_MAC_ALG` for requests protected by MAC. We send a PKIMessage protected
    ...    by a MAC algorithm not listed in `MSG_MAC_ALG`, such as `hmac`. The CA MUST reject the request, and
    ...    the response may include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    protectionAlg    rfc9483-header   minimal
    Skip If    not ${LWCMP}    This test is only for LwCMP.
    ${p10cr}=    Build P10cr From CSR    ${EXP_CSR}    sender=${SENDER}    recipient=${RECIPIENT}   for_mac=True
    ${protected_p10cr}=    Protect PKIMessage    ${p10cr}  hmac   password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badAlg,badMessageCheck    exclusive=True


CA MUST Reject PKIMessage With Different Protection Algorithm Than MSG_SIG_ALG
    [Documentation]    According to RFC 9483 Section 3.1, the CA must enforce the use of algorithms specified in
    ...    `MSG_SIG_ALG` for signature-based protection. We send a 'ir' PKIMessage protected by a signature algorithm
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

CA MUST Reject Requests That Feature Unknown Signature Algorithms
    [Documentation]    According to RFC 9483 Section 3, a PKIMessage protected by an unrecognized or unsupported
    ...    signature algorithm MUST be rejected by the CA. We send a valid p10cr PKIMessage with an unknown
    ...    signature algorithm. The CA MUST reject the request, potentially responding with the failInfo
    ...    `badAlg` for the unsupported algorithm or `systemFailure`.
    #Where does it say that in the RFC 9483 Section 3? - What are unrecognized or unsupported signature algorithms?
    #Does that work for all unrecognized or unsupported signatures?
    [Tags]    crypto    negative    p10cr  minimal
    ${data}=    Get Binary File    data/req-p10cr-prot_none-pop_sig-dilithium.pkimessage
    Log Base64    ${data}
    ${updated_pki_message}=    Patch MessageTime    ${data}
    ${prot_req}=   Default Protect PKIMessage    ${updated_pki_message}
    ${response}=   Exchange PKIMessage    ${prot_req}
    PKIMessage Body Type Must Be  ${response}  error
    PKIStatus Must Be   ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}  failinfo=badAlg,systemFailure   exclusive=True


#senderKID
CA MUST Reject Signature Protected PKIMessage Without SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using signature-based protection, a PKIMessage must
    ...    include a valid `senderKID` that matches the `SubjectKeyIdentifier` from the CMP protection
    ...    certificate. We send a PKIMessage with signature-based protection but omit the `senderKID` field.
    ...    The CA MUST reject the request, and the response may include the failinfo `badMessageCheck`,
    ...    as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderKID    signature   minimal
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
    ...    do_patch=${False}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject Signature Protected PKIMessage With Invalid SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using signature-based protection, the `senderKID` field
    ...    in a PKIMessage must match the `SubjectKeyIdentifier` from the CMP protection certificate.
    ...    We send a PKIMessage with signature-based protection where the `senderKID` does not match
    ...    the `SubjectKeyIdentifier` of the signing certificate. The CA MUST reject the request, and
    ...    the response may include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderKID    signature   minimal
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=sender,senderKID
    ...    recipient=${RECIPIENT}
    ${ir}=    Patch SenderKID
    ...    ${ir}
    ...    sender_kid=${ISSUED_CERT}
    ...    negative=True
    ${ir}=    Patch Sender
    ...    ${ir}
    ...    cert=${ISSUED_CERT}
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ...    do_patch=${False}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True

CA MUST Reject MAC Based Protected PKIMessage Without SenderKID
    [Documentation]    According to RFC 9483 Section 3.1, when using MAC-based protection, a PKIMessage must include a
    ...    `senderKID` that matches the sender's `common name` field. We send a PKIMessage with MAC-based
    ...    protection but omit the `senderKID` field. The CA MUST reject the request, and the response may
    ...    include the failinfo `badMessageCheck`, as specified in Section 3.5.
    [Tags]    mac    negative    rfc9483-header    senderKID    minimal
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
    [Tags]    mac    negative    rfc9483-header    senderKID   minimal
    ${pki_message}=    Build P10cr From CSR    ${EXP_CSR}    exclude_fields=sender_kid,sender   recipient=${RECIPIENT}
    ${pki_message}=    Patch Sender    ${pki_message}    sender_name=${SENDER}
    ${pki_message}=    Patch SenderKID    ${pki_message}    for_mac=True    negative=True
    ${pki_message}=    Protect PKIMessage
    ...    ${pki_message}
    ...    protection=${DEFAULT_MAC_ALGORITHM}
    ...    password=${PRESHARED_SECRET}
    ${response}=    Exchange PKIMessage    ${pki_message}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck    exclusive=True


#transactionID
FailInfo Bit Must Be badDataFormat For Missing transactionID
    [Documentation]    According to RFC 9483 Section 3.5, each PKIMessage must include a `transactionID` to uniquely
    ...    identify the transaction. We send a PKIMessage omitting the `transactionID`. The CA MUST reject
    ...    the request, and the response may include the failinfo `badDataFormat`.
    [Tags]    negative    rfc9483-header    transactionId   minimal
    ${ir}=    Build Ir From CSR
    ...    ${EXP_CSR}
    ...    ${EXP_KEY}
    ...    exclude_fields=transactionID,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badDataFormat    exclusive=True

CA MUST Reject PKIMessage If transactionId Is Already In Use
#copy to PKIStatusInfo_ErrorMessages
    [Documentation]    According to RFC 9483 Section 3.6.4, the CA must validate the uniqueness of the `transactionID`
    ...    for each new transaction. If a `transactionID` that is already in use is detected, the CA MUST
    ...    terminate the operation and reject the request. The response may include the failinfo
    ...    `transactionIdInUse`. We send two PKIMessages with the same `transactionID`, expecting the CA
    ...    to process the first request successfully and reject the second as a duplicate.
    [Tags]    negative    rfc9483-header    transactionId  minimal
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    exclude_fields=transactionID,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${ir}=    Patch TransactionID    ${ir}    0x01234567890123456789012345678910
    ${ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${csr2}    ${key2}=    Generate CSR For Testing
    ${ir2}=    Build Ir From CSR
    ...    ${csr2}
    ...    ${key2}
    ...    exclude_fields=transactionID,sender,senderKID
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ${patched_ir2}=    Patch TransactionID    ${ir2}    0x01234567890123456789012345678910
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

#senderNonce
CA MUST Reject PKIMessage Without senderNonce
    [Documentation]    According to RFC 9483 Section 3.5, the `senderNonce` field in a PKIMessage must contain at least
    ...    128 bits of random data to ensure secure transaction tracking and prevent replay attacks.
    ...    We send a PKIMessage without the `senderNonce` field. The CA MUST reject the message,
    ...    and the response may include the failinfo `badSenderNonce`, as specified in Section 3.5.
    [Tags]    negative    rfc9483-header    senderNonce   minimal
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
    [Tags]    negative    rfc9483-header    senderNonce   minimal
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


#recipNonce
CA MUST Reject First PKIMessage With recipNonce
    [Documentation]    According to RFC 9483 Section 3.1, the `recipNonce` field must be absent in the initial
    ...    PKIMessage of a CMP transaction. Including `recipNonce` in the first message violates protocol
    ...    requirements, as this field is reserved for the response message. We send a PKIMessage with a
    ...    included `recipNonce`. The CA MUST reject the message, and the response may include the failinfo
    ...    `badRecipientNonce` or `badRequest`, as specified in Section 3.5.
    [Tags]    negative    recipNonce    rfc9483-header  minimal
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


#generalInfo

CA MUST Reject PKIMessage With Invalid ImplicitConfirmValue
    [Documentation]    According to RFC 9483 Section 3.1, when a PKIMessage with an `ImplicitConfirmValue` must have
    ...    this value set to `NULL` if present. We send a PKIMessage with an invalid `ImplicitConfirmValue`
    ...    , expecting the CA to reject the request due to the non-NULL value. The response may include the
    ...    failinfo `badRequest`.
    [Tags]    negative    rfc9483-header    strict   minimal
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${ir}=    Patch GeneralInfo
    ...    ${ir}
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
    [Documentation]    According to RFC 9483 Section 3.1, when a PKIMessage includes a `confirmWaitTime` value set in
    ...    the `generalInfo` field, the value must be of type `generalizedTime`. Using a `UTCTime` format for
    ...    `confirmWaitTime` violates the protocol requirements. We send a PKIMessage with a `confirmWaitTime`
    ...    value in `UTCTime` format, expecting the CA to reject the message. The CA MUST reject this request,
    ...    and the response may include the failinfo `badRequest` or `badDataFormat`.
    [Tags]    negative    strict    generalInfo    minimal
    Skip If    not ${STRICT}    STRICT is deactivated, skipping test.
    ${csr}    ${key}=    Generate CSR For Testing
    ${ir}=    Build Ir From CSR
    ...    ${csr}
    ...    ${key}
    ...    sender=${SENDER}
    ...    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${ir}=    Patch GeneralInfo
    ...    ${ir}
    ...    confirm_wait_time=500
    ...    neg_info_value=True
    ${protected_ir}=    Protect PKIMessage
    ...    pki_message=${ir}
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badDataFormat

CA MUST Reject PKIMessage With ImplicitConfirm And ConfirmWaitTime
    [Documentation]    According to RFC 9483 Section 3.1, if `ImplicitConfirm` is set in a PKIMessage, the
    ...    `ConfirmWaitTime` field must not be present, as the two fields are mutually exclusive.
    ...    We send a PKIMessage with both `ImplicitConfirm` and `ConfirmWaitTime` set, expecting
    ...    the CA to reject the message due to the conflicting fields. The CA MUST reject this request,
    ...    and the response may include the failinfo `badRequest`.
    [Tags]    negative    generalInfo    strict   minimal
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
    ...    ${ir}
    ...    implicit_confirm=True
    ...    confirm_wait_time=400
    ...    neg_info_value=True
    ${protected_ir}=    Protect PKIMessage
    ...    ${ir}
    ...    signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badRequest   exclusive=True


# PROTECTION
# Section 3.2 General Description of the CMP Message Protection

CA MUST Reject PKIMessage With Invalid Signature Protection Value
    [Documentation]    According to RFC 9483 Section 3.2, when using signature-based protection, PKIMessages must
    ...    include a valid protection value that corresponds to the `protectionAlg` field. We send a `p10cr` PKIMessage
    ...    with a signature-based `protectionAlg` set, but we modify the protection value to an invalid one. The CA MUST
    ...    reject this request and may respond with the optional `badMessageCheck`, as specified in Section 3.5.
    [Tags]    signature    negative    protection   minimal
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
    [Tags]    mac    negative    protection   minimal
    Skip If    not ${ALLOW_MAC_PROTECTION}    Skipped this test because MAC-based protection is disabled.
    ${pki_message}=    Generate Default MAC Protected PKIMessage
    ${patched_message}=    Modify PKIMessage Protection    ${pki_message}
    ${response}=    Exchange PKIMessage    ${patched_message}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    failinfo=badMessageCheck   exclusive=True

CA MUST Reject PKIMessage With Protection Value But No protectionAlg
    [Documentation]    According to RFC 9483 Section 3.2, PKI messages must specify both a `protectionAlg` and a
    ...    corresponding protection value if protection is applied. We send a `p10cr` PKIMessage that includes a
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
    [Tags]    negative    protection    signature   minimal
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

# EXTRACERT
# Section 3.3 General Description of CMP Message ExtraCerts

CA MUST Reject PKIMessage With Incorrect Protection Certificate Position
    [Documentation]    According to RFC 9483 Section 3.3, when using signature-based protection, the `extraCerts` field
    ...    must include the complete certificate chain necessary to verify the signature, with the
    ...    protection certificate placed at index 0. We send a PKIMessage with the protection
    ...    certificate positioned at the second index in the `extraCerts` field. The CA MUST reject this
    ...    request, and the response may include the failinfo `badMessageCheck`, as specified in
    ...    Section 3.5.
    [Tags]    extraCert    negative    rfc9483-validation    robot:skip-on-failure   minimal
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
    [Tags]    ak    extraCert    negative    rfc9483-validation   minimal
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
    ...    exclude_cert=True
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
    [Tags]    ak    extraCert    negative    rfc9483-validation   minimal
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

# Section 3.4 Generic PKI Management Operation Prerequisites
# TODO

# Section 3.5 Generic Validation of PKI Message

CA Must Validate The Received PKI Message
    [Documentation]    Upon reception the CA must take specific validation steps before further processing.
    ...    If the CA decides to terminate the operation because of a failed check, it must send a negative
    ...    response or error message.
    ...    Ref.: 3.5. Generic Validation of PKI Message
    [Tags]    header    positive    rfc9483-validation   minimal
    ${ir}=    Generate Default IR Sig Protected
    ${response}=    Exchange PKIMessage    ${ir}
    # 200 is too short. So 95000 is the minimum.
    # There are other test cases just for the message, so could be disable here.
    Validate PKIMessage Header    ${response}    ${ir}     time_interval=95000

CA or RA MUST Reject Not Authorized Sender
    [Documentation]     According to RFC 9483 Section 3.5, the CA or RA must reject a PKIMessage if the sender is not
    ...    authorized to send the message. We send a PKIMessage with a sender that is not authorized to
    ...    send a message. The CA or RA MUST reject the request, and the response may include the failinfo
    ...    `notAuthorized`.
    [Tags]    negative    rfc9483-header    sender   notAuthorized
    Skip If    not ${ALLOW_NOT_AUTHORIZED_SENDER}    This test is skipped because not authorized sender is not allowed.
    ${cert_template}    ${key}=   Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key    ${key}    cert_template=${cert_template}   sender=${SENDER}    recipient=${RECIPIENT}
    # Can only be done if the check is done after the subject field of the certificate is checked.
    # Otherwise, the test will have to be done with a matching certificate or MAC protected.
    IF   '${NOT_AUTHORIZED_SENDER_CERT}' == '${None}'
        ${protected_ir}=   Default Protect PKIMessage  ${ir}  protection=mac
    ELSE
        ${protected_ir}=   Protect PKIMessage  ${ir}   protection=signature
        ...                private_key=${NOT_AUTHORIZED_SENDER_KEY}
        ...                cert=${NOT_AUTHORIZED_SENDER_CERT}
    END
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    notAuthorized    True
