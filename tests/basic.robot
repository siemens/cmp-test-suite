*** Settings ***
Documentation        General tests for CMP logic, not necessarily specific to the lightweight profile
Resource    ../resources/keywords.resource
Library     ../resources/utils.py



*** Test Cases ***
CA must reject request with an invalid signature
    [Documentation]    Demonstrate how to use some keywords
    ...                just an example
    [Tags]    csr    crypto    negative
    ${csr_signed}=    Generate CSR with RSA2048 and a predefined common name
    # ${manipulated_signed}=    Modify bytes    ${csr_signed}
    # ${p10_pkimessage}=    Build CMP p10cr request from CSR    ${manipulated_signed}
    Log    ${csr_signed}
    # Evaluate    pdb.Pdb(stdout=sys.__stdout__).set_trace()    modules=sys, pdb
    ${parsed_csr}=    Parse CSR    ${csr_signed}    header_included=True
    Log    ${parsed_csr} 
    ${p10_pkimessage}=    Build CMP p10cr request from CSR    ${parsed_csr}

    # ${ca_response}=    Send CMP request to CA    ${p10_pkimessage}    http://127.0.0.1:8080/pkix
    ${ca_response}=    Get Binary File    data/example-p10r.pkimessage

    ${result}=    Parse PKI Message    ${ca_response}
    ${status}=     Get CMP status from PKI Message    ${result}

    Should be equal    ${status}    rejection


# ALTERNATIVE CA must reject request with an invalid signature
#     [Documentation]    Demonstrate how to use some keywords
#     ...                just an example
#     [Tags]    csr    crypto    negative
#     Generate CSR with RSA2048 and a predefined common name
#     Modify bytes in CSR
#     Build CMP p10cr request from CSR
#     ${ca_response}=    Send CMP request to CA    http://127.0.0.1:8080/pkix
#     Parse PKI Message    ${ca_response}
#     ${status}=     Get CMP status from PKI Message
#     Should be equal    ${status}    rejection



CSR must be generated with subjectAltName support
    [Documentation]    Demonstrate how to use some keywords
    ...                just an example
    [Tags]    csr
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    ${csr_signed}=    Sign CSR    ${csr}    ${key}

    # [Teardown]    to do

STATEFUL CSR must be generated with subjectAltName support
    [Documentation]    Demonstrate how to use some keywords
    ...                just an example
    [Tags]    csr
    Generate keypair    rsa    2048
    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    Sign CSR
    Manipulate a bit in CSR
    ${result}=      Send CSR to CA
    Should be False     ${result}


    # [Teardown]    to do
