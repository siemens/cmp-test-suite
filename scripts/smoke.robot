# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       A minimal RobotFramework test suite that does nothing, except
...                 making sure that the test environment is set up correctly and
...                 the suite is actually running.

Library             OperatingSystem

*** Test Cases ***
The smoke test must pass
    [Documentation]    A basic hello world test case.
    [Tags]    smoke
    Log       Hello, world!
    ${rc} 	  ${output} = 	Run and Return RC and Output 	uname -a
    Log       ${output}
