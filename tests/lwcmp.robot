*** Settings ***
Documentation        Tests specifically for the lightweight CMP profile
Resource    ../resources/keywords.resource
Library     ../resources/utils.py



*** Test Cases ***
PKIMessage header must include all required fields
    [Documentation]    Check that the PKIMessage coming from the server includes all the required fields
    [Tags]    headers
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Generate basic PKIMessage
    Send PKIMessage to server
    ${pki_message}=      Retrieve response from server
    ${required_fields_raw}=     Set variable    pvno,sender,recipient,protectionAlg,transactionID,senderNonce,implicitConfirmValue,ConfirmWaitTimeValue,CertProfileValue
    ${required_fields}=    Split String    ${required_fields_raw}   ,
    PKIMessage must contain fields      ${pki_message}      ${required_fields}
    # [Teardown]    to do

SenderNonce must be present and at least 128 bit long
    [Documentation]    Check that the PKIMessage contains the SenderNonce field and that its value is >=128 bit.
    [Tags]    headers   crypto
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Generate basic PKIMessage
    Send PKIMessage to server
    ${pki_message}=      Retrieve response from server
    ${protection}=  Get field value from PKIMessage as bytes        protection
    Buffer length must be at least      ${protection}   128
    # [Teardown]    to do

