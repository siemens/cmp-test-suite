# Overview
The CMP test suite is a tool for verifying implementations of the Certificate Management Protocol (CMP). It generates
CMP requests, sends them to the server and checks if responses match expectations. The results are logged in a report,
which includes all the transmitted and received messages in base64 and in human-readable form.

Test cases are written in a domain-specific language (DSL) tailored for PKI and X509 certificate parsing. The provided
scenarios evaluate *server* implementations of CMP and the CMP lightweight profile. However, the DSL can be used for
writing client-oriented tests.

## Usage scenarios
- Run it "as is" and check whether your CMP server conforms to the specification.
- Adapt the test suite to your needs, by writing test scenarios using the provided DSL.
- Extend the DSL, adding new keywords and correcting errors in existing ones.

## Repository structure
- `tests` - test scenarios written with keywords implemented in RF (Robot Framework)
- `resources` - source code of the keywords themselves, written in RF or Python
- `data` - pre-generated test data (e.g., keys, certificates) used in some test cases
- `config` - configuration options (e.g., IP addresses, port numbers, etc.) for target environments to test
- `unit_tests` - tests for the Python primitives of the library itself
- `doc` - generated documentation of the test suite and its keywords


# Configuration
Create a Python virtual environment by installing the dependencies from `requirements.txt`:

1. Create a virtual environment: `python -m venv venv-cmp-tests`
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
- Docker
- [compose compose v2](https://github.com/docker/compose)


## Other useful commands
- `make test` - run all the tests, store the results in `out/`, use the `config/local.robot` settings.
- `make testlog` - run all the tests, store the results in subdirectories like `out/2024-01-20_17-45_January-1`, so that
  you can keep track of the history of test runs, instead of overwriting them. This will use the default test environment.
- `make testlog env=cloudpki` - as above, but use the `config/cloudpki.robot` settings.
- `make testlog env=ejbca` - as above, but use the `config/ejbca.robot` settings.
- `make doc` - generate HTML documentation for test suites and available keywords, store in `doc/`.
- `make unittest` - run unit tests that verify the functionality of the library itself.


# Design considerations
## Constant data
In many cases it is better to use the same data across runs, instead of generating something on-the-fly. This supports
replicability, because the test will always send the same data, therefore it is easier for the authors of the system
under test to answer the question "what exactly happened when the error occurred?". Consider the example of sending a
CSR - if you generate it on-the-fly, its signature will be different, even if everything else in the CSR is identical.

Follow these principles when building your tests:
- if possible, use the same data all the time (e.g., by loading a payload from a file)
- include the tool (function, script, list of steps, etc.) that was used to generate the file
- allow exceptions to the rule if necessary, e.g. a nonce or timestamp might have to be unique in a particular scenario

A good practice is to generate new data on-demand once, e.g., by running a script that generates all the required data,
and then using the same data in subsequent runs. Make sure to document the process of generating the data!

## Type Design
- Where `univ.<ClassName>` appears in the code comments, it is assumed to refer to the `pyasn1.type.univ`, e.g.,
  `univ.ObjectIdentifier`

- When you encounter `rfc<num>.<ClassName>`, it is assumed to be from `pyasn1_alt_modules`, e.g.,
  `from pyasn1_alt_modules import rfc9480`. Example: `rfc9480.PKIMessage`.

## Plaintext vs binary
Prefer to store data in textual form, rather than binary. This makes it easier to visually inspect the data, copy some
chunks for experimentation, logging, or for sharing with colleagues.

For example, payloads in PKI are often DER-encoded, but you can also use PEM. The difference in storage size can be
neglected, while transforming one into the other is easy and can be automated (e.g., write keywords and functions that
convert automatically to whatever makes sense, and accept either format at the input).

## Documenting tests
Point to the section of the RFC where the requirement is discussed, include a relevant quote.

## Tagging tests
Consider what tags can be used to categorize your tests. Their main benefit is that the test suite can be run in a way
that includes or excludes specific tests, such that you can focus on specific functionality.

## String parameters
Throughout the test suite, you will encounter places where numeric parameters are passed as strings. This is because
RF will pass a parameter as a string unless you convert it to an integer, i.e., `2` is passed as `"2"` (str), while
`${2}` is passed as `2` (number). For convenience, we allow both notations and encourage the use of the string notation,
such that the test cases are more readable.

On a source code level, see `typingutils.Strint`, which stands for "stringified integer".

## Mask internal-use Python functions
By default, RF will expose all Python functions as keywords for the test suite. You can suppress that with the
`not_keyword` decorator: `robot.api.deco.not_keyword`. When writing new Python functions, consider whether they need
to be exposed or not. Here is how one can use the decorator:

```
@not_keyword
def this_is_not_a_keyword():
    pass
```


# Preparing test data
This section explains how OpenSSL can be used to generate test data, such as key-pairs or CSRs.

- Get list of supported algorithms `openssl list -signature-algorithms`, let's say you will use `RSA`.
- Generate a private key `openssl genpkey -algorithm RSA -out private-key-rsa.pem`.
- Generate a CSR `openssl req -new -key private-key-rsa.pem -out csr-rsa.pem -nodes -subj /CN=testSubject` (note that
  on Windows you might have to write the latter part as `//CN=testSubject`).
- Generate a PKIMessage `ir`: `openssl cmp -cmd ir -server https://example.com/.well-known/cmp -recipient //CN=test -ref 11111 -csr csr-rsa.pem -secret pass:presharedPass -popo 1 -certout result-cert.pem -newkey private-key-rsa.pem -reqout req-ir.pkimessage`


# Supporting materials
- https://docs.robotframework.org/docs/getting_started/ide How to use this with an IDE.

# Development
1. Install the dependencies: `pip install -r requirements-dev.txt`
2. If using IntelliJ or PyCharm, set the source directory: `File/Project Structure/Modules`, click on the `resources`
   folder, select `Source` and apply.
3. Alternatively, you can also do this in the code `import sys; sys.path.append("./resources")`
