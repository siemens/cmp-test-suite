help:
	@echo  'Commands:'
	@echo  '  test         - Run all compliance tests (results will be in out/)'
	@echo  '  doc          - Produce documentation files and store them in doc/'
	@echo  ''

test:
	robot --outputdir=out  --variable environment:local tests

docs:
	python -m robot.libdoc resources/keywords.resource doc/keywords.html
	python -m robot.libdoc resources/cryptoutils.py doc/cryptoutils.html
	python -m robot.libdoc resources/cmputils.py doc/cmputils.html
	python -m robot.testdoc tests/ doc/tests-suites.html
