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
