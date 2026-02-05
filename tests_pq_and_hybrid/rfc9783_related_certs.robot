# SPDX-FileCopyrightText: Copyright 2024 Siemens AG  # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation    This test suite contains test cases related to RFC 9763, which defines the usage of two related
...              certificates. This tests are in the context of CMP. The tests in this suite will focus on scenarios
...              where two certificates are used together, which one is a post-quantum certificate and the other one
...              is a traditional certificate. The tests will cover the issuance, validation, and usage of these
...              related certificates in various scenarios.

Resource            ../resources/keywords.resource
Resource            ../resources/setup_keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/certextractutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/general_msg_utils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_verify_logic.py

Test Tags           rfc9783    related-certs    hybrid    hybrid-certs   pqc
Suite Setup         Set Up Related Certificates Suite


*** Variables ***
# Just defining the variables here, but they
# will be set during the tests, to have a better overview of which
# variables are used in the tests and to avoid any issues with variable scope.
${PQ_SIG_CERT}         ${None}
${PQ_SIG_KEY}          ${None}
${REVOKED_CERT}        ${None}
${REVOKED_KEY}         ${None}
${UPDATED_CERT}        ${None}
${UPDATED_KEY}         ${None}
${CA_CERT}             ${None}
${CA_KEY}              ${None}
${RELATED_KEY}         ${None}
${RELATED_CERT}        ${None}
${RELATED_KEY_SEC}     ${None}
${RELATED_CERT_SEC}    ${None}


*** Test Cases ***
# #### positive tests #####

CA MUST Accept valid Request with CSR with related Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    Issue New PQ Sig Cert For Testing
    ${cert_url}=  Prepare Related Cert URL    ${PQ_SIG_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${PQ_SIG_CERT}
    ...            cert_a_key=${PQ_SIG_KEY}   uri=${cert_url}
    ${trad_key}=   Generate Default Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${trad_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${trad_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Related Cert Extension    ${cert}    ${PQ_SIG_CERT}
    VAR   ${RELATED_KEY}    ${trad_key}   scope=Suite
    VAR   ${RELATED_CERT}    ${cert}    scope=Suite
    VAR   ${RELATED_KEY_SEC}    ${PQ_SIG_KEY}   scope=Suite
    VAR   ${RELATED_CERT_SEC}   ${PQ_SIG_CERT}   scope=Suite

CA SHOULD Accept CSR with related cert from different CA
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an valid related certificate
    ...                from a different CA. The CA SHOULD accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive   different-ca
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    # TODO uncomment, if needed.
    # get a new cert, if the CA requires to issue a related cert in time.
    # ${ir}=    Generate Default IR Sig Protected
    # ${response}=   Exchange PKIMessage    ${ir}
    # PKIMessage Body Type Must Be    ${response}    ip
    # PKIStatus Must Be    ${response}    accepted
    # ${new_cert}=   Get Cert From PKIMessage    ${response}
    # ${key}=    Get From List    ${burned_keys}    -1
    # must then change the variables.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}
    ${pq_key}=    Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted

# TODO decide how to handle the multiple auth in CertTemplate!
# Technically one to one for x509 inside the CertTemplate.
# But not defined, so either added in a experimental file or excluded.

##### negative tests #####

CA MUST Reject Invalid POP for Cert A
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an invalid POPO for the signature inside the
    ...                `RequesterCertificate` structure. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badPOP`.
    [Tags]         multiple-auth   csr   negative   popo
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}   bad_pop=True
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

# TODO may change the failInfo to a more fitting one.

CA MUST Validate that the URI is reachable
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                unreachable URI for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badRequest`.
    [Tags]         multiple-auth   csr   negative   uri
    Skip if   '${NEG_URI_RELATED_CERT}' == None    The Not reachable URI for multiple auth is not defined.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${NEG_URI_RELATED_CERT}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    systemFailure,badPOP

CA MUST Check If The Related Certificate Is Not Revoked.
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    Revoked New PQ Sig Cert
    ${cert_url}=  Prepare Related Cert URL    ${REVOKED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${REVOKED_CERT}
    ...            cert_a_key=${REVOKED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid  all_text=revoked

CA MUST Check If The Related Certificate Is Not Updated
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    Update New PQ Sig Cert
    ${cert_url}=  Prepare Related Cert URL    ${UPDATED_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${UPDATED_CERT}
    ...            cert_a_key=${UPDATED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   ${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid, update, updated

CA MUST Reject Related Cert With Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not for
    ...                an end entity. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    Issue New PQ CA Cert For Testing
    ${cert_url}=  Prepare Related Cert URL    ${CA_CERT}
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${CA_CERT}
    ...            cert_a_key=${CA_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA MUST Reject Related Cert For Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   '${URI_RELATED_CERT}' == None   The URI for related cert is not defined.
    ${cert_url}=  Prepare Related Cert URL    ${ISSUED_CERT}
    ${extns}=   Prepare Extensions    is_ca=True
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}
    ...            cert_a_key=${ISSUED_KEY}   uri=${cert_url}
    ${pq_key}=   Generate Default PQ SIG Key
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True   extensions=${extns}
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${ca_url}=  Get Related Cert URL
    ${response}=  Exchange PKIMessage    ${protected_p10cr}   ${ca_url}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA Could Support Composite Signature with Related Cert
    [Documentation]    A CA could support a PKIMessage signed with composite signature with a related
    ...                certificate. We send a certificate request, which is signed with a composite signature.
    ...                The CA should correctly validate the signature and issue the certificate.
    [Tags]    hybrid-auth  composite-sig
    ${result}=  Is Certificate And Key Set    ${RELATED_CERT}    ${RELATED_KEY}
    SKIP IF    not ${result}    The Related Certificate and Key are not set.
    ${key}=   Generate Default Key
    ${ir}=   Build Ir From Key  ${key}  exclude_fields=senderKID,sender
    ${protected_ir}=    Protect Hybrid PKIMessage
    ...    ${ir}
    ...    protection=composite
    ...    private_key=${RELATED_KEY}
    ...    cert=${RELATED_CERT}
    ...    alt_signing_key=${RELATED_KEY_SEC}
    ${protected_ir}=   Add Certs To PKIMessage  ${protected_ir}    ${RELATED_CERT_SEC}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}    ${MULTI_AUTH_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted


*** Keywords ***
Issue New PQ Sig Cert For Testing
    [Documentation]    This keyword issues a new PQ signature certificate, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is valid, and the CA must accept the request.
    ${pq_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${pq_key}
    VAR   ${PQ_SIG_CERT}   ${pq_cert}   scope=Suite
    VAR   ${PQ_SIG_KEY}    ${pq_key}    scope=Suite

Revoked New PQ Sig Cert
    [Documentation]    This keyword revokes the current PQ signature certificate and issues a new one, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is revoked, and the CA must reject the request.
    ${pq_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${pq_key}
    ${rr}=   Build CMP Revoke Request   cert=${pq_cert}   reason=keyCompromise
    ...           recipient=${RECIPIENT}
    ${prot_rr}=  Protect PKIMessage    ${rr}   signature   private_key=${pq_key}   cert=${pq_cert}
    ${response}=  Exchange PKIMessage    ${prot_rr}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted
    Wait Until Server Revoked Cert
    VAR   ${REVOKED_CERT}   ${pq_cert}   scope=Suite
    VAR   ${REVOKED_KEY}   ${pq_key}   scope=Suite

Update New PQ Sig Cert
    [Documentation]    This keyword updates the current PQ signature certificate, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is updated, and the CA must reject the request.
    ${pq_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${pq_key}
    ${new_pq_key}=    Generate Default PQ SIG Key
    ${rr}=   Build Key Update Request   ${new_pq_key}
    ...           recipient=${RECIPIENT}   implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${prot_rr}=  Protect PKIMessage    ${rr}   signature   private_key=${pq_key}   cert=${pq_cert}
    ${response}=  Exchange PKIMessage    ${prot_rr}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    accepted
    Confirm Certificate If Needed  ${response}    url=${pq_url}
    Wait Until Server Updated Cert
    VAR   ${UPDATED_CERT}   ${pq_cert}   scope=Suite
    VAR   ${UPDATED_KEY}   ${pq_key}   scope=Suite

Issue New PQ CA Cert For Testing
    [Documentation]    This keyword issues a new CA certificate, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is not an end entity certificate.
    ${ca_key}=   Generate Default PQ SIG Key
    ${extns}=   Prepare Extensions    is_ca=True
    ${ir}=   Build Ir From Key    ${ca_key}   recipient=${RECIPIENT}   extensions=${extns}
    ...      exclude_fields=senderKID,sender   implicit_confirm=${ALLOW_IMPLICIT_CONFIRM}
    ${prot_ir}=  Default Protect PKIMessage    ${ir}
    ${pq_url}=   Get PQ Issuing URL
    ${response}=  Exchange PKIMessage    ${prot_ir}   ${pq_url}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${ca_cert}=   Confirm Certificate If Needed    ${response}   url=${pq_url}
    VAR   ${CA_CERT}   ${ca_cert}   scope=Suite
    VAR   ${CA_KEY}   ${ca_key}   scope=Suite
