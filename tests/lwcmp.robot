*** Settings ***
Documentation        Tests specifically for the lightweight CMP profile
Resource    ../resources/keywords.resource
Resource    ../config/${environment}.robot
Library     ../resources/utils.py
Library     ../resources/asn1utils.py
Library     ../resources/cmputils.py
Library     OperatingSystem
Library     Collections

Suite Setup    Initialize Global Variables


*** Variables ***
# This variable is a collector of nonces that the server sent back to us throughout all the tests. In the end we use
# it to check that the server is not sending the same nonce twice, and that the nonces are cryptographically secure.
@{collected_nonces}    ${EMPTY}

# normally this would be provided from the command line
${environment}    cloudpki

*** Keywords ***
Initialize Global Variables
    [Documentation]    Define global variables that will be used in the test suite and accessible within any test case
    Set Global Variable    @{collected_nonces}    @{EMPTY}

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

    ${p10cr}=    Build P10cr From Csr    ${parsed_csr}     sender=${SENDER}    recipient=${RECIPIENT}      implicit_confirm=${True}

    ${protected_p10cr}=     Protect Pkimessage Pbmac1    ${p10cr}    ${PRESHARED_SECRET}
    Log Asn1    ${protected_p10cr}

    ${encoded}=  Encode To Der    ${protected_p10cr}
    Log Base64    ${encoded}
    ${response}=  Exchange data with CA    ${encoded}
    ${pki_message}=      Parse Pki Message    ${response.content}
    ${pki_header}=       Get Asn1 value   ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce

    Sender and Recipient nonces must match    ${protected_p10cr}      ${pki_message}
    SenderNonce must be at least 128 bits long  ${pki_message}

    Collect nonce from PKIMessage    ${pki_message}   ${collected_nonces}

    PKIMessage must contain implicitConfirm extension   ${pki_message}

    ${der_cert}=    Get Asn1 value as DER    ${pki_message}    extraCerts/0
    Log base64    ${der_cert}
    Certificate must be valid    ${der_cert}

    Response time must be fresh               ${protected_p10cr}      ${pki_message}
    Protection algorithms must match          ${protected_p10cr}      ${pki_message}
    Protection must be valid                  ${pki_message}
    PKIMessage body type must be              ${pki_message}    cp
    # [Teardown]    to do



CA must issue certificate via p10cr without implicitConfirm
    [Documentation]    Ensure that the server can issue certificates and wait for a confirmation to be sent by the EE
    [Tags]    headers   ak
    ${parsed_csr}=     Load and parse example CSR
    ${p10cr}=    Build P10cr From Csr    ${parsed_csr}     sender=CN=CloudCA-Integration-Test-User    recipient=CN=CloudPKI-Integration-Test      implicit_confirm=${False}
    ${protected_p10cr}=     Protect Pkimessage Pbmac1    ${p10cr}    ${PRESHARED_SECRET}
    Log Asn1    ${protected_p10cr}

    # send initial request
    ${encoded}=  Encode To Der    ${protected_p10cr}
    Log Base64    ${encoded}
    ${response}=  Exchange data with CA    ${encoded}
    ${pki_message}=      Parse Pki Message    ${response.content}
    # could also be ip, kup, ccp; consider examining the tag; the overall structure is CertRepMessage
    PKIMessage body type must be              ${pki_message}    cp

    # prepare confirmation message by extracting the certifiate and getting the needed data from it
    ${cert}=    Get Cert From Pki Message    ${pki_message}
    ${conf_message}=    Build Cert Conf    ${cert}
    ${protected_conf_message}=     Protect Pkimessage Pbmac1    ${conf_message}    ${PRESHARED_SECRET}
    ${encoded}=  Encode To Der    ${protected_conf_message}
    Log Base64    ${encoded}
    ${response}=  Exchange data with CA    ${encoded}
    ${pki_message}=      Parse Pki Message    ${response.content}
    ${response_type}=  Get CMP response type    ${pki_message}
    Log      ${response_type}
#    PKIMessage body type must be              ${pki_message}    cp


CA must support p10cr with password-based-mac protection
    [Documentation]    Check that the CA can handle a p10cr that is protected with a password-based-mac
    [Tags]    headers   ak
    ${parsed_csr}=     Load and parse example CSR
    ${p10cr}=    Build P10cr From Csr    ${parsed_csr}     sender=${SENDER}    recipient=${RECIPIENT}      implicit_confirm=${True}     protection=password-based-mac
    ${protected_p10cr}=     Protect Pkimessage password based mac    ${p10cr}    ${PRESHARED_SECRET}
    Log Asn1    ${protected_p10cr}

    ${encoded}=  Encode To Der    ${protected_p10cr}
    Log Base64    ${encoded}
    ${response}=  Exchange data with CA    ${encoded}
    ${pki_message}=      Parse Pki Message    ${response.content}
    ${pki_header}=       Get Asn1 value   ${pki_message}    header
    Asn1 Must Contain Fields    ${pki_header}    pvno,sender,recipient,protectionAlg,transactionID,senderNonce

    Sender and Recipient nonces must match    ${protected_p10cr}      ${pki_message}
    SenderNonce must be at least 128 bits long  ${pki_message}

    Collect nonce from PKIMessage    ${pki_message}   ${collected_nonces}

    PKIMessage must contain implicitConfirm extension   ${pki_message}

    ${der_cert}=    Get Asn1 value as DER    ${pki_message}    extraCerts/0
    Log base64    ${der_cert}
    Certificate must be valid    ${der_cert}

    Response time must be fresh               ${protected_p10cr}      ${pki_message}
    Protection algorithms must match          ${protected_p10cr}      ${pki_message}
    Protection must be valid                  ${pki_message}
    PKIMessage body type must be              ${pki_message}    cp



SenderNonces must be cryptographically secure
    [Documentation]    Check that the SenderNonce values from all the received PKIMessage structures are unique and
    ...                cryptographically secure. The latter is checked by computing the Hamming distance between each
    ...                pair of nonces and ensuring it is at least 10 bits.
    ...                Ref: 3.1. General Description of the CMP Message Header
    [Tags]    crypto    ak
    Log     ${collected_nonces}
    Nonces Must Be Unique    ${collected_nonces}
    Nonces Must Be Diverse   ${collected_nonces}



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

#
#PKIStatusInfo must be set when an error occurred
#    [Documentation]    When a negative response is sent by the RA/CA, the error details must be shown in PKIStatusInfo.
#    ...                operation.
#    ...                Ref: 3.6.4
#    [Tags]    consistency
#    No Operation
