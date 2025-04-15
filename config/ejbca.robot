# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation    Resource file to access local docker EJBCA .

*** Variables ***
${CA_CMP_URL}          http://127.0.0.1:6080/ejbca/publicweb/cmp/cmp_imprint_RA
${CA_BASE_URL}         http://127.0.0.1:6080/ejbca/publicweb/cmp/cmp_imprint_RA
${PRESHARED_SECRET}    SecretCmp

${SENDER}      CN=CUSTOMER_ISSUING_CA
${RECIPIENT}   CN=test-genCMPClientDemo/OU=For testing purposes only/O=Siemens/C=DE
#export EJBCA_CMP_SUBJECT_IMPRINT=${EJBCA_CMP_SUBJECT}/OU=IDevID

${CERT_PATH}           config/cert
${CA_CLIENT_CERT}      ${CERT_PATH}/PPKI_Playground_CMP.p12
${CA_CLIENT_KEY}       ${CERT_PATH}/PPKI_Playground_CMP.p12

${DEFAULT_ALGORITHEM}    rsa
${DEFAULT_EC_CURVE}    None
${ALLOW_ONLY_HTTP_STATUS_CODE}    200, 201, 202, 203, 3xx, 4xx, 5xx
${DEFAULT_X509NAME}    C=DE,L=Munich,CN=Hans MustermannG11111111111111111111

##### About Algorithms
${DEFAULT_KEY_LENGTH}    2048
${DEFAULT_ALGORITHM}    rsa
${DEFAULT_ECC_CURVE}   secp256r1
${DEFAULT_MAC_ALGORITHM}   password_based_mac
${DEFAULT_KGA_ALGORITHM}   rsa
${DEFAULT_PQ_SIG_ALGORITHM}   ml-dsa-44
${DEFAULT_PQ_KEM_ALGORITHM}   ml-kem-512
${DEFAULT_KEY_AGREEMENT_ALG}   x25519
${DEFAULT_KEY_ENCIPHERMENT_ALG}   ml-kem-768

##### Extra Issuing Logic
${CA_RSA_ENCR_CERT}    ${None}
${CA_X25519_CERT}   ${None}
${CA_X448_CERT}     ${None}
${CA_ECC_CERT}      ${None}
${CA_HYBRID_KEM_CERT}   ${None}
${CA_KEM_CERT}     ${None}

##### About CertTemplate
${ALLOWED_ALGORITHM}   ed25519,rsa,ecc,ed448,x25519,x448,dsa
${ALLOW_ISSUING_OF_CA_CERTS}  ${True}
# Sensitive Service so maybe disallowed
${ALLOW_CMP_EKU_EXTENSION}  ${True}

# Hybrid Endpoints

${PQ_ISSUING_SUFFIX}    ${None}
${URI_MULTIPLE_AUTH}   ${None}
${ISSUING_SUFFIX}    ${None}
${COMPOSITE_URL_PREFIX}    ${None}
${CATALYST_SIGNATURE}    ${None}
${SUN_HYBRID_SUFFIX}    ${None}
${CHAMELEON_SUFFIX}    ${None}
${RELATED_CERT_SUFFIX}    ${None}
${MULTI_AUTH_SUFFIX}    ${None}
${CERT_DISCOVERY_SUFFIX}    ${None}