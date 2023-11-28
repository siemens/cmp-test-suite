# Overview
A library of primitives for automating PKI- and CMP-related tests using RobotFramework.

## Structure
- `tests` - the test suites themselves
- `resources` - reusable keywords written in RF or Python
- `data` - pre-generated test data (e.g., keys, certificates), if required
- `config` - a place for storing configuration options (e.g., IP addresses, port numbers, etc.)


# Configuration
Prepare your environment by installing the dependencies from `requirements.txt`. Using a Python virtualenv is a good
practice. In this case you would run `pip install -r requirements.txt` inside the environment.

# Usage
1. Run `robot tests` to execute all the tests in the `tests/` directory.
2. Explore `report.html` to see the results.


Other useful commands
- `make test` - run all the tests
- `make doc` - generate HTML documentation for test suites and available keywords, store in `doc/`.


# Supporting materials
- https://docs.robotframework.org/docs/getting_started/ide How to use this with an IDE.