*** Variables ***
${environment}    cloudpki
#${environment}    local

*** Settings ***
Resource         ../config/${environment}.robot
#Resource         ../config/local.robot
#Resource         ../config/local.robot


Library   RequestsLibrary
Library   OperatingSystem
Library   ../resources/cryptoutils.py
Library   ../resources/cmputils.py
Library   ../resources/utils.py


*** Keywords ***
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
    &{headers}=     Create Dictionary    Content-Type=application/pkixcmp    Accept-Type=application/pkixcmp
    ${response}=    POST    url=${CA_CMP_URL}     data=${payload}    headers=&{headers}     verify=${False}     expected_status=any
    Log             ${response.content}
    Log base64       ${response.content}
    RETURN        ${response}