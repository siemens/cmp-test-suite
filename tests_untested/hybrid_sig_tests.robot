# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP logic, not necessarily specific to the lightweight profile

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/pq_validation_utils.py


#Suite Setup         Do PQ SIG Tests
Test Tags           pqc  hybrid-sig

*** Variables ***

# New Tags: composite-sig, multiple-auth

#${uri_multiple_auth}=   https://localhost:8080/cmp/cert-bindings-for-multiple-authentication
${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}
${DEFAULT_ML_DSA_ALG}=   ml-dsa-87
${Allowed_freshness}=   500

*** Test Cases ***

############################
# Composite Signature Tests
############################

#### Composite Signature Positive Tests ####
