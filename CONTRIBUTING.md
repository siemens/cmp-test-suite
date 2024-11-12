# How to contribute
Help is welcome, and you can contribute in various ways:

- Write new test cases to extend coverage of the RFC.
- Point out issues in existing test cases, e.g., if the RFC was not interpreted correctly by the test authors.
- Implement new keywords in the DSL, or fix existing ones.
- Provide additional test data that is specific to your use case.


# Getting started
## Repository structure
- `tests` - test scenarios written with keywords implemented in RF (Robot Framework)
- `resources` - source code of the keywords themselves, written in RF or Python
- `data` - pre-generated test data (e.g., keys, certificates) used in some test cases
- `config` - configuration options (e.g., IP addresses, port numbers, etc.) for target environments to test
- `unit_tests` - tests for the Python primitives of the library itself
- `doc` - generated documentation of the test suite and its keywords

## Preparing the development environment
1. Install the dependencies: `pip install -r requirements-dev.txt`
2. If using IntelliJ or PyCharm, set the source directory: `File/Project Structure/Modules`, click on the `resources`
   folder, select `Source` and apply.
3. You can also do this in the code, e.g., if not using an IDE `import sys; sys.path.append("./resources")`

For more details about usage of RF with an IDE: https://docs.robotframework.org/docs/getting_started/ide.




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




# Contribution Checklist

- The code passes the CI pipeline checks.
- References to specific RFC sections are provided when relevant.
- If reporting errors, include a report generated by RF.
