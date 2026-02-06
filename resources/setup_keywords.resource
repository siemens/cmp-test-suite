# SPDX-FileCopyrightText: Copyright 2025 Siemens AG   # robocop: off=COM04
#
# SPDX-License-Identifier: Apache-2.0
#

*** Settings ***
Documentation  Contain common keywords for setup the CMP tests, like overwriting variables or initializing resources.
Resource            ../config/${environment}.robot
Resource            ../resources/keywords.resource


*** Variables ***
${environment}          cloudpki


*** Keywords ***
Set Up PQ Sig Suite
    [Documentation]    Initializes the test suite for PQ signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ issuing endpoint for certificate requests using stateless PQ signature algorithms
    ...                (e.g., ML-DSA).
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE   # robocop: off=VAR05

Set Up PQ Stateful Sig Suite
    [Documentation]    Initializes the test suite for PQ stateful signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ stateful issuing endpoint for certificate requests using XMSS, XMSSMT, or HSS algorithms.
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ stateful-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Stateful Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE   # robocop: off=VAR05

Set Up PQ KEM Suite
    [Documentation]    Initializes the test suite for PQ KEM (Key Encapsulation Mechanism) tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                PQ issuing endpoint for certificate requests using PQ KEM algorithms
    ...                (e.g., ML-KEM).
    ...
    ...                The CA_CMP_URL suite variable is updated to the PQ-specific endpoint.
    Set Up Test Suite
    ${url}=   Get PQ Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE

Set Up Hybrid Sig Suite
    [Documentation]    Initializes the test suite for hybrid/composite signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                composite issuing endpoint for certificate requests using hybrid signature algorithms
    ...                (combinations of PQ and traditional algorithms).
    ...
    ...                The CA_CMP_URL suite variable is updated to the composite-specific endpoint.
    Set Up Test Suite
    ${url}=   Get Composite Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE   # robocop: off=VAR05

Set Up Composite Sig Suite
    [Documentation]    Initializes the test suite for composite signature algorithm tests.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                composite issuing endpoint for certificate requests using composite signature algorithms
    ...                (combinations of PQ and traditional algorithms).
    ...
    ...                The CA_CMP_URL suite variable is updated to the composite-specific endpoint.
    Set Up Test Suite
    ${url}=   Get Composite Issuing URL
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE   # robocop: off=VAR05

Set Up Related Certificates Suite
    [Documentation]    Initializes the test suite for related certificate tests as defined in RFC 9763.
    ...
    ...                Executes the shared suite setup and configures the CMP URL to point to the
    ...                related certificate issuing endpoint for certificate requests that involve multiple certificates
    ...                (e.g., a traditional certificate and a PQ certificate issued together).
    ...
    ...                The CA_CMP_URL suite variable is updated to the related certificate-specific endpoint.
    Set Up Test Suite
    ${url}=   Add URL Suffix   ${CA_BASE_URL}    ${RELATED_CERT_SUFFIX}
    VAR   ${CA_CMP_URL}    ${url}   scope=SUITE   # robocop: off=VAR05


##############################################
## Issue New Certificates for Testing Keywords
##############################################
# Now Creates Setup Keywords for issuing fresh certificates using different types of algorithms for setup purposes,
# which can be used in test suites to ensure they are testing against the correct endpoints and configurations
# for each algorithm type.

Issue New PQ Sig Cert For Testing
    [Documentation]    This keyword issues a new PQ signature certificate, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is valid, and the CA must accept
    ...                the request.
    ${pq_key}=   Generate Default PQ SIG Key
    ${pq_url}=  Get PQ Issuing URL
    ${pq_cert}  ${_}=   Issue New Cert For Testing    ${pq_url}   ${pq_key}
    VAR   ${PQ_SIG_CERT}   ${pq_cert}   scope=Suite
    VAR   ${PQ_SIG_KEY}    ${pq_key}    scope=Suite

Revoked New PQ Sig Cert
    [Documentation]    This keyword revokes the current PQ signature certificate and issues a new one, to be used in
    ...                the related cert tests. It is used to test the scenario where the related certificate is
    ...                revoked, and the CA must reject the request.
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
    VAR   ${REVOKED_PQ_CERT}   ${pq_cert}   scope=Suite
    VAR   ${REVOKED_PQ_KEY}   ${pq_key}   scope=Suite

Update New PQ Sig Cert
    [Documentation]    This keyword updates the current PQ signature certificate, to be used in the related cert tests.
    ...                It is used to test the scenario where the related certificate is updated, and the CA must reject
    ...                the request.
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
    VAR   ${UPDATED_PQ_CERT}   ${pq_cert}   scope=Suite
    VAR   ${UPDATED_PQ_KEY}   ${pq_key}   scope=Suite

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
    VAR   ${PQ_CA_CERT}   ${ca_cert}   scope=Suite
    VAR   ${PQ_CA_KEY}   ${ca_key}   scope=Suite
