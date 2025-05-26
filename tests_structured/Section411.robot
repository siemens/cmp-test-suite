*** Test Cases ***
# Test Cases for Section 4.1.1 

# "For this PKI management operation, the EE MUST include a sequence of one CertReqMsg in the ir. 
# If more certificates are required, further requests MUST be sent using separate PKI management operations."
CA MUST Reject IR With More Than One CertReqMsg Inside The IR
    [Documentation]    According to RFC 9483 Section 4.1.1, an Initialization Request (IR) must contain exactly one
    ...    `CertReqMsg` to be valid. Including more than one `CertReqMsg` in an IR violates protocol
    ...    requirements. We send an IR containing two `CertReqMsg` entries, expecting the CA to reject
    ...    the request. The CA MUST reject this request and may respond with the optional failinfo
    ...    `badRequest` or `systemFailure`, as specified in Section 3.5.
    [Tags]    ir    lwcmp    negative
    Skip If   not ${LWCMP}    Skipped because this test in only for LwCMP.
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
    ...    protection=signature
    ...    private_key=${ISSUED_KEY}
    ...    cert=${ISSUED_CERT}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest,systemFailure


#In case the EE included the generalInfo field implicitConfirm in the request message and the PKI management entity 
#does not need any explicit confirmation from the EE, the PKI management entity MUST include the generalInfo field 
#implicitConfirm in the response message.
CA MUST Include ImplicitConfirm In Response
    [Documentation]    According to RFC 9483 Section 4.1.1, if the EE included the `generalInfo` field
    ...    `implicitConfirm` in the request message and the PKI management entity does not need any explicit
    ...    confirmation from the EE, the PKI management entity MUST include the `generalInfo` field
    ...    `implicitConfirm` in the response message.
    [Tags]    ir    lwcmp
    Skip If   not ${LWCMP}    Skipped because this test in only for LwCMP.
    ${key}=    Generate Default Key
    ${cm}=    Get Next Common Name
    ${cert_req_msg}=    Prepare CertReqMsg    ${key}    common_name=${cm}