init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python setup.py sdist
publish:
	python -m twine upload dist/* -u __token__
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*