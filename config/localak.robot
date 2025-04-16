# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     An example resource file with configuration options that are meant for use on your local development
...               system. Use this file as a template when adapting the tests to a specific environment.

*** Variables ***
${CA_CMP_URL}    http://139.25.105.164:5556/lraserver/default/
${CA_BASE_URL}    http://139.25.105.164:5556/lraserver/default/

# The initial issued certificate and key for running the tests.
${ISSUED_KEY}    ${None}
${ISSUED_CERT}   ${None}
${INIT_SUFFIX}   ${None}

${PRESHARED_SECRET}    SiemensIT
${SENDER}              CloudCA-Integration-Test-User
${RECIPIENT}           CloudPKI-Integration-Test

#${CA_CMP_URL}    https://signservice-playground.ct.siemens.com/ejbca/publicweb/cmp/PlaygroundMdcNameExtension
${CERT_PATH}        config/cert
${CA_CLIENT_CERT}   ${CERT_PATH}/PPKI_Playground_CMP.p12
${CA_CLIENT_KEY}    ${CERT_PATH}/PPKI_Playground_CMP.p12

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
${DEFAULT_ML_DSA_ALG}    ml-dsa-87
${DEFAULT_ML_KEM_ALG}    ml-kem-768

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


# Certificates and Keys to set.
${INITIAL_KEY_PATH}    ${None}
${INITIAL_CERT_PATH}   ${None}
${INITIAL_KEY_PASSWORD}   11111

# Device certificate and key (None means not provided).
${DEVICE_CERT}   ${None}
${DEVICE_KEY}  ${None}

# Section 5.2 and 5.3
# Other trusted PKI and Key (None means not provided, so test are skipped).
${OTHER_TRUSTED_PKI_KEY}    ${None}
${OTHER_TRUSTED_PKI_CERT}    ${None}

# A certificate used to verify, if it is supported
# that another trusted PKI Management Entity can revoke a certificate.
${RR_CERT_FOR_TRUSTED}   ${None}

# Relevant for CRR requests.
${TRUSTED_CA_CERT}      ${None}
${TRUSTED_CA_KEY}       ${None}
${TRUSTED_CA_KEY_PASSWORD}   ${None}
${TRUSTED_CA_DIR}            ${None}

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