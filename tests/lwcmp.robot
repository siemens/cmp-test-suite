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
    ...                Ref: 3.1. General Description of the CMP Message Header
    [Tags]    crypto
    ${key}=    Generate keypair    rsa    2048
    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Generate basic PKIMessage
    Send PKIMessage to server
    ${pki_message}=      Retrieve response from server
    ${protection}=  Get field value from PKIMessage as bytes        protection
    Buffer length must be at least      ${protection}   128
    # [Teardown]    to do



SenderNonces must be cryptographically secure
    [Documentation]    Check that the PKIMessage contains the SenderNonce field and that its value is >=128 bit.
    ...                Ref: 3.1. General Description of the CMP Message Header
    [Tags]    crypto
    Log     dummy test


Messages without protection must be rejected, except if not possible for error messages
    [Documentation]    Protection must always be used, unless dealing with the case of an error message where
    ...                it is impossible, as described in Section 3.6.4:
    ...                     "Protecting the error message may not be technically feasible if it is not clear which
    ...                     credential the recipient will be able to use when validating this protection, e.g.,
    ...                     in case the request message was fundamentally broken. In these exceptional cases,
    ...                     the protection of the error message MAY be omitted"
    ...                Ref: 3.2. General Description of the CMP Message Protection
    [Tags]    consistency
    No Operation

The same type of PKIProtection must be used across a PKI operation
    [Documentation]    The same type of protection is required to be used for all messages of one PKI management
    ...                operation.
    ...                Ref: 1.6. Compatibility with Existing CMP Profiles
    [Tags]    consistency
    No Operation

PKIStatusInfo must be set when an error occurred
    [Documentation]    When a negative response is sent by the RA/CA, the error details must be shown in PKIStatusInfo.
    ...                operation.
    ...                Ref: 3.6.4
    [Tags]    consistency
    No Operation
