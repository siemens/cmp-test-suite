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

Test Tags           rfc9783    related-certs    hybrid    hybrid-certs
Suite Setup         Set Up Related Certificates Suite


*** Test Cases ***
first
    Log    Hello World
