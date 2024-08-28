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
${test_suite_cfg}      ./test_suite_config.yaml