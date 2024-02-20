*** Settings ***
Documentation        General tests for CMP logic, not necessarily specific to the lightweight profile
Resource    ../resources/keywords.resource
Library     OperatingSystem
Library     ../resources/utils.py
Library     ../resources/asn1utils.py


*** Test Cases ***
CA must reject malformed reqest
    [Documentation]    When we send an invalid PKIMessage to the CA, it must respond with a 400 status code to indicate
    ...                a client-side error in the supplied input data.
    ...                Ref: "3.3.  General Form",  "All applicable "Client Error 4xx" or "Server Error 5xx" status codes
    ...                MAY be used to inform the client about errors."
    [Tags]    negative  status  rfc6712     robot:skip-on-failure
    ${response}=  Exchange data with CA    this dummy input is not a valid PKIMessage
    Should Be Equal    ${response.status_code}  ${400}

CA must reject requests that feature unknown signature algorithms
    [Documentation]    When we send an valid PKIMessage to the CA, it must respond with a 400 status code to indicate
    ...                a client-side error in the supplied input data.
    [Tags]    negative  crypto
    ${data}=  Get Binary File  data/1.3.6.1.4.1.2.267.7.4.4-dilithium2/req-p10cr-prot_none-pop_sig.pkimessage
    Log base64    ${data}
    ${response}=  Exchange data with CA    ${data}
    Should Be Equal    ${response.status_code}  ${400}



CA must issue a certificate when the CSR is valid
    [Documentation]    When we send a valid CSR, the CA should respond with a valid certificate.
    [Tags]    csr    positive
    ${der_pkimessage}=  Load And Decode Pem File    data/example-rufus-01-p10cr.pem
    ${result}=  Exchange data with CA    ${der_pkimessage}
    ${pki_message}=     Parse Pki Message    ${result.content}
    ${value}=       Get Asn1 Value As String   ${pki_message}    header.sender.directoryName.rdnSequence/0/0.value
    Should Be Equal    ${value}    Siemens PKI

CA must reject request when the CSR signature is invalid
    [Documentation]    When we send a CSR with a broken signature, the CA must respond with an error.
    [Tags]    csr    negative   crypto
    No Operation

CA must reject request when the CSR is not valid asn1
    [Documentation]    When we send a structure that is not valid DER-encoded ASN1, the CA must respond with an error.
    [Tags]    csr    negative   asn1
    No Operation


#CA must reject request with an invalid signature
#    [Documentation]    Demonstrate how to use some keywords
#    ...                just an example
#    [Tags]    csr    crypto    negative
#    ${csr_signed}=    Generate CSR with RSA2048 and a predefined common name
#    Log    ${csr_signed}
#    ${parsed_csr}=    Parse CSR    ${csr_signed}
#    Log    ${parsed_csr}
#    ${p10_pkimessage}=      Build P10cr From Csr    ${parsed_csr}
#    ${ca_response}=    Get Binary File    data/example-p10r.pkimessage
#    ${result}=    Parse PKI Message    ${ca_response}
#    ${status}=     Get CMP status from PKI Message    ${result}
#    Should be equal    ${status}    rejection
