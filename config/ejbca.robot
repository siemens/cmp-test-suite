*** Settings ***
Documentation    Resource file to access local docker EJBCA .

*** Variables ***
${CA_CMP_URL}          http://127.0.0.1:6080/ejbca/publicweb/cmp/cmp_imprint_RA
${PRESHARED_SECRET}    SecretCmp

${SENDER}      CN=CUSTOMER_ISSUING_CA
${RECIPIENT}   CN=test-genCMPClientDemo/OU=For testing purposes only/O=Siemens/C=DE
#export EJBCA_CMP_SUBJECT_IMPRINT=${EJBCA_CMP_SUBJECT}/OU=IDevID

${CERT_PATH}           config/cert
${CA_CLIENT_CERT}      ${CERT_PATH}/PPKI_Playground_CMP.p12
${CA_CLIENT_KEY}       ${CERT_PATH}/PPKI_Playground_CMP.p12
