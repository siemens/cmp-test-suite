# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       A minimal RobotFramework test suite that does nothing, except
...                 making sure that the test environment is set up correctly and
...                 the suite is actually running.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             String



*** Test Cases ***
The smoke test must pass
    [Documentation]    A basic hello world test case.
    [Tags]    smoke
    Log       Hello, world!
    ${rc} 	  ${output} = 	Run and Return RC and Output 	uname -a
    Log       ${output}

OQS dependencies must be available
    [Documentation]    Checks if the OQS (openquantumsafe) dependencies are available https://github.com/open-quantum-safe/liboqs-python
    [Tags]    smoke
    ${rc} 	  ${output} = 	Run and Return RC and Output 	python -c "import oqs"
    Should be Equal    ${rc}    ${0}



PQ keypair must be able get generated
    [Documentation]    Generates a PQ keypair and prints the public key
    [Tags]    smoke
    ${key}=   Generate Key    ml-kem-768
    Log    ${key.public_key().public_bytes_raw()}
    Should Not Be Empty    ${key.public_key().public_bytes_raw()}