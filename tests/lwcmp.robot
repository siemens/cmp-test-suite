*** Settings ***
Documentation        Tests specifically for the lightweight CMP profile
Resource    ../resources/keywords.resource
Library     ../resources/utils.py
Library     ../resources/asn1utils.py
Library     ../resources/cmputils.py
Library     OperatingSystem

*** Test Cases ***
PKI entity must respond with a PKIStatusInfo structure when a malformed request is received
    [Documentation]    When we send an invalid PKIMessage to a PKI entity, it MUST indicate the error condition in
    ...                the PKIStatusInfo structure
    ...                Ref:  3.6.2. Reporting Error Conditions Downstream
    ...                   "In case the PKI management entity detects any other error condition on requests [..]
    ...                   from downstream [..], it MUST report them downstream in the form of an error message as
    ...                   described in Section 3.6.4.
    [Tags]    negative  rfc9483
    ${response}=  Exchange data with CA    this dummy input is not a valid PKIMessage
    ${asn1_response}=  Parse Pki Message    ${response.content}
    ${response_type}=  Get Cmp Response Type    ${asn1_response}
    # Should Be Equal    ${response_type}  ${rp}
    Should Be Equal    error    ${response_type}


Server must issue a certificate when a correct p10cr is sent
    [Documentation]    When a correct p10cr is sent to the server, it must issue a certificate
    [Tags]    positive  rfc9483  p10cr
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${response}=  Exchange data with CA    ${der_pkimessage}

    ${pki_message}=      Parse Pki Message    ${response.content}
    Asn1 Must Contain Fields    ${pki_message}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce,implicitConfirmValue,ConfirmWaitTimeValue,CertProfileValue



Response PKIMessage header must include all required fields
    [Documentation]    Check that the PKIMessage coming from the server includes all the required fields
    [Tags]    headers   ak
    ${key}=    Generate RSA keypair
    ${csr}=    Generate CSR    CN=Hans Mustermann
    ${csr_signed}=    Sign CSR    ${csr}    ${key}
    Log             ${csr_signed}
    ${decoded_csr}=    Decode PEM string    ${csr_signed}
    ${parsed_csr}=     Parse Csr    ${decoded_csr}

    ${p10cr}=    Build P10cr From Csr    ${parsed_csr}     sender=CloudCA-Integration-Test-User    recipient=CloudPKI-Integration-Test      implicit_confirm=${True}

    ${protected_p10cr}=     Protect Pkimessage Pbmac1    ${p10cr}    SiemensIT
    Log Asn1    ${protected_p10cr}

    ${encoded}=  Encode To Der    ${protected_p10cr}
    Log Base64    ${encoded}
    ${response}=  Exchange data with CA    ${encoded}
    ${pki_message}=      Parse Pki Message    ${response.content}
    ${pki_header}=       Get Asn1 value   ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce

    Sender and Recipient nonces must match    ${protected_p10cr}      ${pki_message}
    Response time must be fresh               ${protected_p10cr}      ${pki_message}
    Protection algorithms must match          ${protected_p10cr}      ${pki_message}
    Protection must be valid                  ${pki_message}
    # [Teardown]    to do

#SenderNonce must be present and at least 128 bit long
#    [Documentation]    Check that the PKIMessage contains the SenderNonce field and that its value is >=128 bit.
#    ...                Ref: 3.1. General Description of the CMP Message Header
#    [Tags]    crypto
#    ${key}=    Generate keypair    rsa    2048
#    ${csr}=    Generate CSR    C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Hans Mustermann        hans.com,www.hans.com
#    ${csr_signed}=    Sign CSR    ${csr}    ${key}
#    Generate basic PKIMessage
#    Send PKIMessage to server
#    ${pki_message}=      Retrieve response from server
#    ${protection}=  Get field value from PKIMessage as bytes        protection
#    Buffer length must be at least      ${protection}   128
#    # [Teardown]    to do



#SenderNonces must be cryptographically secure
#    [Documentation]    Check that the PKIMessage contains the SenderNonce field and that its value is >=128 bit.
#    ...                Ref: 3.1. General Description of the CMP Message Header
#    [Tags]    crypto
#    Log     dummy test
#
#
#Messages without protection must be rejected, except if not possible for error messages
#    [Documentation]    Protection must always be used, unless dealing with the case of an error message where
#    ...                it is impossible, as described in Section 3.6.4:
#    ...                     "Protecting the error message may not be technically feasible if it is not clear which
#    ...                     credential the recipient will be able to use when validating this protection, e.g.,
#    ...                     in case the request message was fundamentally broken. In these exceptional cases,
#    ...                     the protection of the error message MAY be omitted"
#    ...                Ref: 3.2. General Description of the CMP Message Protection
#    [Tags]    consistency
#    No Operation
#
#The same type of PKIProtection must be used across a PKI operation
#    [Documentation]    The same type of protection is required to be used for all messages of one PKI management
#    ...                operation.
#    ...                Ref: 1.6. Compatibility with Existing CMP Profiles
#    [Tags]    consistency
#    No Operation
#
#PKIStatusInfo must be set when an error occurred
#    [Documentation]    When a negative response is sent by the RA/CA, the error details must be shown in PKIStatusInfo.
#    ...                operation.
#    ...                Ref: 3.6.4
#    [Tags]    consistency
#    No Operation
