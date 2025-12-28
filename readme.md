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

Additionally, the DSL can also be used for writing client-oriented tests. A usage scenario could be: 
- Extend the DSL, adding new keywords and correcting errors in existing ones.

What makes this test suite unique is the high-level notation it is written in, making the reports and test scenarios
readable not only to software engineers, but also to PKI experts without programming experience. Another key benefit is
the emphasis on replicability - a test report is sufficient for someone to understand exactly what was transmitted to
the server and how the responses were processed.

These instructions assume a Debian-based Linux system, but it is designed to be used with other platforms as well. Occasionally, additional Windows commands are provided.


The [contribution guidelines](CONTRIBUTING.md) explain how to contribute to the project.

# Quick start with Docker
On a system where [Docker is available](https://docs.docker.com/engine/install/), the easiest way to run the test suite is `docker run --rm -it ghcr.io/siemens/cmp-test`. This will invoke a smoke test just to confirm that the basics are in place. Add `--help` to learn about what other commands are available.

To run a minimal test against an actual CA, try `docker run --rm -it ghcr.io/siemens/cmp-test --minimal http://example.com --ephemeral` (replace the URL with your CMP endpoint).

A thorough evaluation that covers all the features of CMP requires a configuration file, where you specify preshared passwords, keys, algorithms to use, etc. (see `--customconfig` for details).

# Advanced usage
While the Docker-based approach makes it easy to get started, it essentially treats the test suite as a black box. However, if you want to customize, extend or debug it, it is necessary to dive deeper and understand how it works "under the hood".


## Configuration
Create a Python virtual environment by installing the dependencies from `requirements.txt` as follows:

1. Create a virtual environment: `python3 -m venv venv-cmp-tests`
   - If you use WSL 2.0, run `apt install libpython3-dev python3-venv` if the command above fails.
2. Activate the environment:
   - on Linux or cygwin: `source venv-cmp-tests/bin/activate`
   - on Windows with Powershell: `.\venv-cmp-tests\Scripts\Activate.ps1`
3. Install the dependencies: `pip install -r cmp-test-suite/requirements.txt`


## Usage
Note that if you have not activated the environment yet, do so now.

1. Navigate into the test suite: `cd cmp-test-suite`
2. Adjust the settings in the config/local.robot file to match your environment.
   - To run the smoke test, this step is not necessary. 
3. Run the test:
   - Run `robot tests/smoke.robot` to run the smoke test, that checks if everything works so far.
   - Run `robot --variable environment:local tests` to run everything in `tests/` against the `local` environment. 
4. In your directory in the folder of cmp-test-suite you will find `report.html`.
  - [Detailed explanation of the output](output.md)

### Additional RobotFramework commands
You can run specific tests on specific environments by adjusting command line options. Consider this example:
`robot --outputdir=out --variable environment:cloudpki --include crypto tests`

- `--outputdir=out` - store the results in the `out` directory
- `--variable environment:cloudpki` - use the settings given in the `config/cloudpki.robot` file (replace as needed)
- `--include crypto` - run only the tests that have the `crypto` tag

### Other useful commands
- `make test` - run all the tests, store the results in `out/`, use the `config/local.robot` settings.
- `make testlog` - run all the tests, store the results in subdirectories like `out/2024-01-20_17-45_January-1`, so that
  you can keep track of the history of test runs, instead of overwriting them. This will use the default test environment.
- `make testlog env=cloudpki` - as above, but use the `config/cloudpki.robot` settings.
- `make testlog env=ejbca` - as above, but use the `config/ejbca.robot` settings.
- `make docs` - generate HTML documentation for test suites and available keywords, store in `doc/`.
- `make unittest` - run unit tests that verify the functionality of the library itself.

The [detailed documentation](./doc/index.html) covers test suites and available keywords. 
If the referenced documentation is not available, run `make docs` to generate it.


# Mock CA
To facilitate easy testing and development, this repository includes a **Mock CA**. 
This is a simulated Certificate Authority that runs locally, allowing you to execute the test 
suite without needing access to an external CA infrastructure.

**Why use the Mock CA?**
- **Instant Setup:** Run tests immediately without configuring complex server software.
- **Advanced Features:** It includes **Post-Quantum (PQ) cryptography** and **hybrid certificate issuance**, which may not yet be available in a lot of CAs.
- **Research & Debugging:** Perfect for verifying test logic and experimenting with new CMP features in a controlled environment.

For detailed instructions on configuration and usage, please refer to the [Mock CA Documentation](MockCA_readme.md).

Start the server:

```sh
   make start-mock-ca
```

Run tests against it (in a new shell):

```sh
   make test env=mock_ca
```

# Acknowledgments
The development of the CMP test suite was partly funded by the German Federal Ministry of Education and Research
in the project Quoryptan through grant number 16KIS2033.
