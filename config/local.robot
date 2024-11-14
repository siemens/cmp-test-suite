# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.

*** Variables ***
${CA_CMP_URL}    http://127.0.0.1:8000/pkix

${CERT_PATH}        config/cert
${CA_CLIENT_CERT}   ${CERT_PATH}/PPKI_Playground_CMP.p12
${CA_CLIENT_KEY}    ${CERT_PATH}/PPKI_Playground_CMP.p12

# Root certificates that we trust when verifying the identity of the server, this applies when sending CMP-over-HTTP
# requests
@{CA_TRUSTED_ROOTS}=    Create List     ${CERT_PATH}/PPKIPlaygroundECCRootCAv10.crt    ${CERT_PATH}/PPKIPlaygroundInfrastructureRootCAv10.crt     ${CERT_PATH}/PPKIPlaygroundRSARootCAv10.crt


${DEFAULT_RSA_LENGTH}    2048
${DEBUG_ASN1_DECODE_REMAINDER}    True
${DEFAULT_ALGORITHEM}    rsa
${DEFAULT_EC_CURVE}    None
${ALLOW_ONLY_HTTP_STATUS_CODE}    200, 201, 202, 203, 3xx, 4xx, 5xx
${DEFAULT_X509NAME}    C=DE,L=Munich,CN=Hans MustermannG11111111111111111111