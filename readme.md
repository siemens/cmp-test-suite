# Overview
A library of primitives for automating PKI- and CMP-related tests using RobotFramework.

## Structure
- `tests` - the test suites themselves
- `resources` - reusable keywords written in RF or Python
- `data` - pre-generated test data (e.g., keys, certificates), if required
- `config` - a place for storing configuration options (e.g., IP addresses, port numbers, etc.) for target environments
   you want to test.
- `unit_tests` - tests for the library itself, specifically its Python primitives
- `doc` - generated documentation of the test suite and the keywords it is made of


# Configuration
Prepare your environment by installing the dependencies from `requirements.txt`. Using a Python virtualenv is a good
practice:

1. Create a virtual environment: `python -m venv venv-cmp-tests`
2. Activate the environment:
   - on Linux or cygwin: `source venv-cmp-tests/bin/activate`
   - on Windows with Powershell: `.\venv-cmp-tests\Scripts\Activate.ps1`
3. Install the dependencies: `pip install -r requirements.txt`

Note: If WSL 2.0 is being used, run the following commands to fix the python3-venv error:

1. `sudo apt update`
2. `sudo apt-get install libpython3-dev`
3. `sudo apt-get install python3-venv`


# Usage
1. Run `robot tests` to execute all the tests in the `tests/` directory.
2. Explore `report.html` to see the results.

## Advanced usage examples
You can run specific tests on specific environments by adjusting command line options. Consider this example:
`robot --outputdir=out  --variable environment:cloudpki  --include crypto tests`

- `--outputdir=out` - store the results in the `out` directory
- `--variable environment:cloudpki` - use the settings given in the `config/cloudpki.robot` file
- `--include crypto` - run only the tests that have the `crypto` tag

### using pre-configured EJBCA docker
prerequisites  
- Linux or WSL (for windows)  
  When using WSL make sure to use the Linux filesystem.
- docker
- [compose compose v2](https://github.com/docker/compose?tab=readme-ov-file)

To use EJBCA docker, you need to set the `--variable environment` to `ejbca`.

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
and then using the same data in subsequent runs.

## Plaintext vs binary
Prefer to store data in textual form, rather than binary. This makes it easier to visually inspect the data, copy some
chunks for experimentation, sharing with colleagues or logging.

For example, payloads in PKI are often DER-encoded, but you can also use PEM. The difference in storage size can be
neglected, while transforming one into the other is easy and can be automated (e.g., write keywords and functions that
convert automatically to whatever makes sense, and accept either format at the input).

## Documenting tests
Point to the section of the RFC where the requirement is discussed, include a relevant quote.

## Tagging tests
Use the RFC

## String parameters
NOTE that we're not passing it as a
                   list of str, this is syntactic sugar for invocation from within RobotFramework tests.
    :returns: None, raise ValueError of the required fields are not present"""


## Mask internal-use Python functions

```
from robot.api.deco import not_keyword

@not_keyword
def this_is_not_a_keyword():
    pass
```


# Preparing test data
This section explains how OpenSSL can be used to generate test data, such as key-pairs or CSRs.


- Get list of supportfed algorithms `openssl list -signature-algorithms`, let's say you will use `RSA`.
- Generate a private key `openssl genpkey -algorithm RSA -out private-key-rsa.pem`.
- Generate a CSR `openssl req -new -key private-key-rsa.pem -out csr-rsa.pem -nodes -subj /CN=testSubject` (note that
  on Windows you might have to write the latter part as `//CN=testSubject`).
- Generate a PKIMessage `ir`: `openssl cmp -cmd ir -server https://broker.sdo-dev.siemens.cloud/.well-known/cmp -recipient //CN=test -ref 11111 -csr csr-rsa.pem -secret pass:SiemensIT -popo 1 -certout result-cert.pem -newkey private-key-rsa.pem -reqout req-ir.pkimessage`


# Supporting materials
- https://docs.robotframework.org/docs/getting_started/ide How to use this with an IDE.

# Development

1. Install the dependencies: `pip install -r requirements-dev.txt`
2. Change Source DIR
   If using IntelliJ or PyCharm
   `File -> Project Structure... -> Modules` -> click on the resources folder and click on `Source` and apply.

another Option might be:

```
import sys
sys.path.append("./resources")
```
