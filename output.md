<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->


# Documentation of the output
If you want to share the report, consider to include the configuration file. The configuration file contains essential settings and parameters that were used during the test execution, which can help others replicate the test environment and understand the context of the results.
However, caution should be exercised when sharing these reports and configuration file. Always review the content of the report and configuration file to ensure that no confidential information is inadvertently shared.

Tests can have three types of status.
- pass: all conditions in the test cases passed
- fail: a condition in the test case failed 
- skip: can have mutlipe reasons:
    - a test case was not relevant in your set up of the test and there for skipped
    - a test failed, but isn´t needed for RFC compliance

## Output files
Running tests generates the following three result files:
- report.html
- log.html
- output.xml

For the smoke test the output files can be found in the same folder as cmp-test-suite. 

Adjustments to the location of the output can be made through adjusting the command line options when running a test:
`--outputdir=out` stores the results in the out directory.

### report.html
Higher level test report.

Under the section "Test Details" tab "All" you will find the name, documentation, tags, status and if failed the message of the tests you´ve run. 
The background of the Report is green, if all tests passed. It is red, if at least one test is failed (or skipped).
By clicking in one of the tests you will be navigated to the log.html.

You can switch between the report.html view and the log.html view in the top right corner. 

### log.html
Detailed test execution log.

The Test Execution Log shows a detailed sequence of keywords used, their documentation and output. 
This can be used for a detailed analysis for failed or skipped test cases.
### output.xml
Results in machine readable XML format.

<!---
Maybe add a section about the smoke test:

## Smoke test
What does it mean? ... explanation here...
What does it cover? ... explanation here...
