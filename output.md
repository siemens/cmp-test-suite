<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->


# Documentation of the output
If you want to share the report, consider including the configuration file. The configuration file contains essential settings and parameters that were used during the test execution, which can help others replicate the test environment and understand the context of the results.
However, caution should be exercised when sharing these reports and configurations files. Always review the content of the report and configuration file to ensure that no confidential information is inadvertently shared.

Tests can have three types of status in the Robot Framework.
- pass: all conditions in the test cases passed
- fail: a condition in the test case failed 
- skip: can have multiple reasons:
    - a test case was not relevant in your setup of the test and was therefore skipped.
    - a test failed, but it isn’t required for RFC compliance.

## Output files
Running tests generates the following three result files:
- report.html
- log.html
- output.xml

Adjustments to the location of the output can be made by modifying the command line options when running a test.
For example `robot --outputdir=out tests/smoke.robot` stores the results in the out directory. 

### report.html
Higher-level test report.

Under the section "Test Details" tab "All" you will find the name, documentation, tags, status and if failed the message of the tests you have run. 
- The background of the report is green if all tests pass. 
- It is red if at least one test fails (or is skipped).

By clicking on one of the tests, you will be navigated to the log.html.
Additionally, you can switch between the report.html view and the log.html view in the top right corner. 

### log.html
Detailed test execution log.

The Test Execution Log shows a detailed sequence of keywords used, along with their documentation and output. 
This can be used for a detailed analysis of failed or skipped test cases.

### output.xml
Results in machine-readable XML format.


## Smoke test
The smoke test is a quick check to ensure that the basic functionality of the test suite is working correctly. It verifies that the environment is set up properly and that the test suite can communicate with the server. The smoke test does not cover all features but serves as a preliminary validation step.

