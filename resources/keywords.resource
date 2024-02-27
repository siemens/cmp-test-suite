*** Variables ***
${environment}    cloudpki
#${environment}    local

*** Settings ***
Resource         ../config/${environment}.robot
#Resource         ../config/local.robot
#Resource         ../config/local.robot


Library   RequestsLibrary
Library   OperatingSystem
Library   DateTime
Library   ../resources/cryptoutils.py
Library   ../resources/cmputils.py
Library   ../resources/utils.py
Library   ../resources/asn1utils.py


*** Keywords ***
Try to Log PKIMessage as ASN1
    [Documentation]    Tentatively parse a buffer, assuming it is a DER-encoded PKIMessage, and log its contents.
    ...                If that is not the case, ignore this and keep going. This is for convenience in logging.
    [Arguments]         ${payload}
    ${pki_message}=     Parse Pki Message    ${payload}
    Log Asn1            ${pki_message}


Generate CSR with RSA2048 and a predefined common name
    [Documentation]    Produce a generic, valid CSR that has a correct signature
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,L=Munich,CN=Hans Mustermann
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    # Evaluate    pdb.Pdb(stdout=sys.__stdout__).set_trace()    modules=sys, pdb
    Log    ${csr_signed}

    RETURN    ${csr_signed}

Exchange data with CA
    [Documentation]    Send a HTTP POST request to a server, and return the response.
    [Arguments]     ${payload}
    Log Base64    ${payload}
    Run Keyword And Ignore Error     Try to Log PKIMessage as ASN1    ${payload}
    # TODO check if type of payload is a pyasn1 structure, and if it is, der-encode it automatically? Maybe?

    &{headers}=     Create Dictionary    Content-Type=application/pkixcmp    Accept-Type=application/pkixcmp
    ${response}=    POST    url=${CA_CMP_URL}     data=${payload}    headers=&{headers}     verify=${False}     expected_status=any
    Log             ${response.content}
    Log base64      ${response.content}
    Run Keyword And Ignore Error     Try to Log PKIMessage as ASN1    ${response.content}
    RETURN        ${response}

Sender and Recipient nonces must match
    [Documentation]     Ensure that the recipient nonce in the response matches the sender nonce in the request
    [Arguments]         ${request}    ${response}
    ${request_nonce}=   Get Asn1 Value As Bytes    ${request}  header.senderNonce
    ${response_nonce}=  Get Asn1 Value As Bytes    ${response}  header.recipNonce
    Should Be Equal     ${request_nonce}    ${response_nonce}


Response time must be fresh
    [Documentation]     Ensure that the response time is not far off from the time of our request
    ...                 The tolerance is given in seconds, and defaults to 120 (i.e., 2 minutes)
    [Arguments]         ${request}    ${response}   ${tolerance}=${120}
    ${request_time}=    Get Asn1 Value as datetime     ${request}  header.messageTime
    ${response_time}=   Get Asn1 Value as datetime     ${response}  header.messageTime

    ${delta_verbose}=   Subtract Date From Date    ${response_time}    ${request_time}     verbose
    ${delta}=           Subtract Date From Date    ${response_time}    ${request_time}
    Should Be True      ${delta} < ${tolerance}
