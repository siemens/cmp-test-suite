*** Test Cases ***

CA MUST Send badCertId If

CA MUST Reject PKIMessage If transactionId Is Already In Use
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