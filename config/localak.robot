# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.

*** Variables ***
${CA_CMP_URL}    http://139.25.105.164:5556/lraserver/default/

${PRESHARED_SECRET}    SiemensIT
${SENDER}              CloudCA-Integration-Test-User
${RECIPIENT}           CloudPKI-Integration-Test

#${CA_CMP_URL}    https://signservice-playground.ct.siemens.com/ejbca/publicweb/cmp/PlaygroundMdcNameExtension
${CERT_PATH}        config/cert
${CA_CLIENT_CERT}   ${CERT_PATH}/PPKI_Playground_CMP.p12
${CA_CLIENT_KEY}    ${CERT_PATH}/PPKI_Playground_CMP.p12

${DEFAULT_RSA_LENGTH}    2048
${DEBUG_ASN1_DECODE_REMAINDER}    True
${DEFAULT_ALGORITHEM}    rsa
${DEFAULT_EC_CURVE}    None
${ALLOW_ONLY_HTTP_STATUS_CODE}    200, 201, 202, 203, 3xx, 4xx, 5xx
${DEFAULT_X509NAME}    C=DE,L=Munich,CN=Hans MustermannG11111111111111111111