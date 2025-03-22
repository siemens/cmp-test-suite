<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Overview
The CMP test suite is a tool for verifying implementations of the Certificate Management Protocol (CMP). It generates
CMP requests, sends them to the server and checks if responses match expectations. The results are logged in a report,
which includes all the transmitted and received messages in base64 and in human-readable form.

Test cases are written in a domain-specific language (DSL) tailored for PKI and X509 certificate parsing. The provided
scenarios evaluate *server* implementations of CMP and the CMP lightweight profile. However, the DSL can also be used
for writing client-oriented tests.

Several usage scenarios are possible:
- Run it "as is" and check whether your CMP server conforms to the specification.
- Adapt the test suite to your needs, by writing test scenarios using the provided DSL.
- Extend the DSL, adding new keywords and correcting errors in existing ones.

What makes this test suite unique is the high-level notation it is written in, making the reports and test scenarios
readable not only to software engineers, but also to PKI experts without programming experience. Another key benefit is
the emphasis on replicability - a test report is sufficient for someone to understand exactly what was transmitted to
the server and how the responses were processed.

The [contribution guidelines](CONTRIBUTING.md) explain how to contribute to the project.


# Configuration
Create a Python virtual environment by installing the dependencies from `requirements.txt`:

1. Create a virtual environment: `python -m venv venv-cmp-tests`
   - If you use WSL 2.0, run `apt install libpython3-dev python3-venv` if the command above fails.
   - And then run `python3 -m venv venv-cmp-tests`. Also on ubuntu and debian. 
2. Activate the environment:
   - on Linux or cygwin: `source venv-cmp-tests/bin/activate`
   - on Windows with Powershell: `.\venv-cmp-tests\Scripts\Activate.ps1`
3. Install the dependencies: `pip install -r requirements.txt`

Note: If you use WSL 2.0, you might need to run this first `sudo apt update && sudo apt install libpython3-dev python3-venv`.


# Usage
1. Adjust the settings in the `config/local.robot` file to match your environment.
2. Run `robot --variable environment:local tests` to run everything in `tests/` against the `local` environment.
3. Explore `report.html` to see the results.

## Advanced usage examples
You can run specific tests on specific environments by adjusting command line options. Consider this example:
`robot --outputdir=out --variable environment:cloudpki --include crypto tests`

- `--outputdir=out` - store the results in the `out` directory
- `--variable environment:cloudpki` - use the settings given in the `config/cloudpki.robot` file (replace as needed)
- `--include crypto` - run only the tests that have the `crypto` tag

### Using the pre-configured EJBCA docker image
The image is useful if you want to debug the test suite, but have no CA to test. This approach will spin up an
instance of EJBCA with some preconfigured CMP endpoints, so you don't have to set up your own.

To use this approach, adjust the command line arguments to `--variable environment:ejbca`.

Prerequisites:
- Linux or WSL (in this case, ensure to use the Linux filesystem).
- Docker with [compose](https://github.com/docker/compose)


## Other useful commands
- `make test` - run all the tests, store the results in `out/`, use the `config/local.robot` settings.
- `make testlog` - run all the tests, store the results in subdirectories like `out/2024-01-20_17-45_January-1`, so that
  you can keep track of the history of test runs, instead of overwriting them. This will use the default test environment.
- `make testlog env=cloudpki` - as above, but use the `config/cloudpki.robot` settings.
- `make testlog env=ejbca` - as above, but use the `config/ejbca.robot` settings.
- `make doc` - generate HTML documentation for test suites and available keywords, store in `doc/`.
- `make unittest` - run unit tests that verify the functionality of the library itself.
