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
