<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Overview
The CMP test suite is a tool for verifying implementations of the Certificate Management Protocol (CMP). It generates
CMP requests, sends them to the server and checks if responses match expectations. The results are logged in a report,
which includes all the transmitted and received messages in base64 and in human-readable form.

Test cases are written in a domain-specific language (DSL) tailored for PKI and X509 certificate parsing. The provided
scenarios evaluate *server* implementations of CMP [RFC](https://datatracker.ietf.org/doc/draft-ietf-lamps-rfc4210bis/) and the CMP lightweight profile [RFC 9483](https://datatracker.ietf.org/doc/html/rfc9483). 

Several usage scenarios are possible:
- Run it "as is" and check whether your CMP server conforms to the specification.
- Adapt the test suite to your needs, by writing test scenarios using the provided DSL.

Additionally, the DSL can also be used for writing client-oriented tests. A usage scenarios could be: 
- Extend the DSL, adding new keywords and correcting errors in existing ones.

What makes this test suite unique is the high-level notation it is written in, making the reports and test scenarios
readable not only to software engineers, but also to PKI experts without programming experience. Another key benefit is
the emphasis on replicability - a test report is sufficient for someone to understand exactly what was transmitted to
the server and how the responses were processed.

These instructions assume a linux-based system, but it is designed to be used with other platforms as well. Occasionally some additional Windows commands are provided. 
Skills used here are: 
- Basic use of git
- Basic understanding of choosen operating system
- Basic use of python virtual environment
For further reading footnotes and a bibliography are provided. 

The [contribution guidelines](CONTRIBUTING.md) explain how to contribute to the project.


# Configuration
Create a [Python virtual environment](https://docs.python.org/3/library/venv.html) by installing the dependencies from `requirements.txt`:

1. Create a virtual environment: `python3 -m venv venv-cmp-tests`
   - If you use WSL 2.0, run `apt install libpython3-dev python3-venv` if the command above fails.
2. Activate the environment:
   - on Linux or cygwin: `source venv-cmp-tests/bin/activate`
   - on Windows with Powershell: `.\venv-cmp-tests\Scripts\Activate.ps1`
3. Install the dependencies: `pip install -r cmp-test-suite/requirements.txt`



# Usage
Note that if you haven´t yet activated the environment, do so now.

1. Navigate into the test suite: `cd cmp-test-suite`
2. Run `robot --variable environment:local tests` to run everything in `tests/` against the `local` environment. 
3. In your directory in the folder of cmp-test-suite you will find `report.html` 


## Advanced usage examples
Adjust the settings in the `config/local.robot` file to match your environment. 

You can run specific tests on specific environments by adjusting command line options. Consider this example:
`robot --outputdir=out --variable environment:cloudpki --include crypto tests`

- `--outputdir=out` - store the results in the `out` directory
- `--variable environment:cloudpki` - use the settings given in the `config/cloudpki.robot` file (replace as needed)
- `--include crypto` - run only the tests that have the `crypto` tag

## Other useful commands
- `make test` - run all the tests, store the results in `out/`, use the `config/local.robot` settings.
- `make testlog` - run all the tests, store the results in subdirectories like `out/2024-01-20_17-45_January-1`, so that
  you can keep track of the history of test runs, instead of overwriting them. This will use the default test environment.
- `make testlog env=cloudpki` - as above, but use the `config/cloudpki.robot` settings.
- `make testlog env=ejbca` - as above, but use the `config/ejbca.robot` settings.
- `make docs` - generate HTML documentation for test suites and available keywords, store in `doc/`.
- `make unittest` - run unit tests that verify the functionality of the library itself.

The [detailed documentation](/cmp-test-suite/doc/index.html) covers test suites and available keywords. 
If the referenced documentation is not available, run `make docs` to generate it.

# Bibliographyy 
<sup>1</sup> [Python virtual environment](https://docs.python.org/3/library/venv.html)

<sup>2</sup> [Python dependencies](https://docs.python.org/3/installing/index.html)


# Acknowledgments
The development of the CMP test suite was partly funded by the German Federal Ministry of Education and Research
in the project Quoryptan through grant number 16KIS2033.
