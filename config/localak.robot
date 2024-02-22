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

