help:
	@echo  'Commands:'
	@echo  '  test         - Run all compliance tests (results will be in out/)'
	@echo  '  doc          - Produce documentation files and store them in doc/'
	@echo  '  unittest     - Run unit tests for the test suite itself
	@echo  ''

test:
	robot --outputdir=out  --variable environment:local tests

unittest:
	# adjust path such that the unit tests can be started from the root directory, to make it easier to load
	# example files from data/
	PYTHONPATH=./resources python -m unittest discover -s unit_tests

docs:
	python -m robot.libdoc resources/keywords.resource doc/keywords.html
	python -m robot.libdoc resources/cryptoutils.py doc/cryptoutils.html
	python -m robot.libdoc resources/cmputils.py doc/cmputils.html
	python -m robot.libdoc resources/asn1utils.py doc/asn1utils.html
	python -m robot.testdoc tests/ doc/tests-suites.html
