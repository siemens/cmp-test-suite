# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

help:
	@echo  'Commands:'
	@echo  '  test         - Run all compliance tests (results will be in reports/)'
	@echo  '  teslog       - Run all compliance tests, store results in timestamped subirectories in reports/'
	@echo  '  docs          - Produce documentation files and store them in doc/'
	@echo  '  unittest     - Run unit tests for the test suite itself '
	@echo  '  unittest-docker    - Run unit tests in a docker container'
	@echo  '  autoformat   - Run ruff on all the source files, to resolve all issues automatically '
	@echo  '  verify  - Run a bunch of checks, to see if there are any obvious deficiencies in the code '
	@echo  '  verifyformat   -  Check formatting only '
	@echo  '  stats   -  Write the key encapsulation statistics to a data/stats/ directory '
	@echo  '  invalid-sig   -  Verify all pqc-certificates in data/pqc-certificates/ and show all invalid signatures '
	@echo  '  start-mock-ca   -  Start the mock CA server, so that it can listens to requests '
	@echo  '  test-mock-ca   -  Run the test against the mock CA server '
	@echo  ''


# By default, run the tests against the local environment from config/local.robot
# You can override it, e.g., `make test env=cloudpki`
env ?= cloudpki
test: check_ejbca
	robot --pythonpath=./ --outputdir=reports --variable environment:$(env) tests

# As above, but keep the results in timestamped subdirectories, so they keep accumulating. This is useful because you
# won't overwrite test reports from previous runs, which may contain interesting information about exotic errors you
# encountered.
testlog:
	robot --pythonpath=./ --outputdir=reports/`date +%Y-%m-%d_%H-%M_%B-%d` --variable environment:$(env) tests


DOCKERFILE_UNITTEST = data/dockerfiles/Dockerfile.unittest

build-unittest:
	@echo "Building unittest Docker image..."
	docker build -t unittest-image -f $(DOCKERFILE_UNITTEST) .

unittest-docker: build-unittest
	@echo "Running unittest Docker container..."
	docker run --rm -t --workdir=/app unittest-image

unittest:
	# adjust path such that the unit tests can be started from the root directory, to make it easier to load
	# example files from data/
	PYTHONPATH=./resources python -m unittest discover -s unit_tests
	# On Windows Powershell: `$env:PYTHONPATH = "./resources"; python -m unittest discover -s unit_tests`

check_ejbca:
ifeq ($(env), ejbca)
	$(MAKE) -f Makefile_EJBCA start_EJBCA
endif

docs:
	python -m robot.libdoc --pythonpath=./ resources/keywords.resource doc/keywords.html
	python -m robot.libdoc --pythonpath=./ resources/cryptoutils.py doc/cryptoutils.html
	python -m robot.libdoc --pythonpath=./ resources/cmputils.py doc/cmputils.html
	python -m robot.libdoc --pythonpath=./ resources/asn1utils.py doc/asn1utils.html
	python -m robot.libdoc --pythonpath=./ resources/httputils.py doc/httputils.html
	python -m robot.libdoc --pythonpath=./ resources/keyutils.py doc/keyutils.html
	python -m robot.libdoc --pythonpath=./ resources/protectionutils.py doc/protectionutils.html
	python -m robot.libdoc --pythonpath=./ resources/compareutils.py doc/compareutils.html
	python -m robot.libdoc --pythonpath=./ resources/general_msg_utils.py doc/general_msg_utils.html
	python -m robot.libdoc --pythonpath=./ resources/cert_related_utils.py doc/cert_related_utils.html
	python -m robot.libdoc --pythonpath=./ resources/ca_kga_logic.py doc/ca_kga_logic.html
	python -m robot.libdoc --pythonpath=./ resources/envdatautils.py doc/envdatautils.html
	python -m robot.libdoc --pythonpath=./ resources/extra_issuing_logic.py doc/extra_issuing_logic.html
	python -m robot.libdoc --pythonpath=./ resources/ca_ra_utils.py doc/ca_ra_utils.html
	python -m robot.libdoc --pythonpath=./ pq_logic/hybrid_prepare.py doc/hybrid_prepare.html
	python -m robot.libdoc --pythonpath=./ pq_logic/pq_verify_logic.py doc/pq_verify_logic.html
    # Test documentation
	python -m robot.testdoc tests/ doc/test-suites.html
	python -m robot.testdoc tests_pq_and_hybrid/ doc/test-pq-hybrid-suites.html

autoformat:
	ruff check --fix .

verify:
	reuse lint
	ruff check .
	pylint .
	PYTHONPATH=./resources pyright
	# on Windows Powershell: `$env:PYTHONPATH = "./resources"; pyright`

verifyformat:
	ruff check .

dryrun:
	robot --dryrun --pythonpath=./ --variable environment:$(env) tests tests_pq_and_hybrid

check-sigs:
	python test_load_pqc.py
	python vis_pqc_verify.py

test-pq-hybrid:
    # Start the tests for PQ and Hybrid algorithms/mechanisms.
	robot --pythonpath=./ --outputdir=reports --variable environment:$(env) tests_pq_and_hybrid

start-mock-ca:
	python ./mock_ca/ca_handler.py

test-mock-ca:
    # exclude sec-awareness for faster execution.
	# robot --exclude sec-awareness --pythonpath=./ --outputdir=reports --variable environment:mock_ca tests
	robot --pythonpath=./ --outputdir=reports --variable environment:mock_ca tests tests_pq_and_hybrid

