*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.

*** Variables ***
# the dev-environment always runs the latest version
# qa - the stable version
${CA_CMP_URL}    https://broker.sdo-qa.siemens.cloud/.well-known/cmp
#${CA_CMP_URL}    https://broker.sdo-dev.siemens.cloud/.well-known/cmp

${PRESHARED_SECRET}    SiemensIT
${SENDER}              CN=CloudCA-Integration-Test-User
${RECIPIENT}           CN=CloudPKI-Integration-Test
${DEFAULT_RSA_LENGTH}    2048
${debug_asn1_decode_remainder}    ${True}
${DEFAULT_ALGORITHEM}    rsa
${DEFAULT_EC_CURVE}    None
${ALLOW_ONLY_HTTP_STATUS_CODE}    200, 201, 202, 203, 3xx, 4xx, 5xx
${DEFAULT_X509NAME}    C=DE,L=Munich,CN=Hans MustermannG11111111111111111111