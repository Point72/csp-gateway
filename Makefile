#########
# BUILD #
#########
.PHONY: develop-py develop-js develop
develop-py:
	python -m pip install -e .[develop]

develop-js:
	cd js; pnpm install

develop: develop-js develop-py  ## setup project for development

.PHONY: build-py build-js build
build-py:
	python -m build -w -n

build-js:
	cd js; pnpm build

build: build-js build-py  ## build the project

.PHONY: install
install:  ## install python library
	python -m pip install .

#########
# LINTS #
#########
.PHONY: lint-py lint-js lint lints
lint-py:  ## run python linter with ruff
	python -m ruff check csp_gateway
	python -m ruff format --check csp_gateway

lint-js:  ## run js linter
	cd js; pnpm lint

lint: lint-js lint-py  ## run project linters

# alias
lints: lint

.PHONY: fix-py fix-js fix format
fix-py:  ## fix python formatting with ruff
	python -m ruff check --fix csp_gateway
	python -m ruff format csp_gateway

fix-js:  ## fix js formatting
	cd js; pnpm fix

fix: fix-js fix-py  ## run project autoformatters

# alias
format: fix

################
# Other Checks #
################
.PHONY: check-manifest checks check

check-manifest:  ## check python sdist manifest with check-manifest
	check-manifest -v

checks: check-manifest

# alias
check: checks

#########
# TESTS #
#########
.PHONY: test-py tests-py coverage-py
test-py:  ## run python tests
	python -m pytest -v csp_gateway/tests

# alias
tests-py: test-py

coverage-py:  ## run python tests and collect test coverage
	python -m pytest -v csp_gateway/tests --cov=csp_gateway --cov-report term-missing --cov-report xml

.PHONY: test-js tests-js coverage-js
test-js:  ## run js tests
	cd js; pnpm test

# alias
tests-js: test-js

coverage-js: test-js  ## run js tests and collect test coverage

.PHONY: test coverage tests
test: test-py test-js  ## run all tests
coverage: coverage-py coverage-js  ## run all tests and collect test coverage

# alias
tests: test

###########
# VERSION #
###########
.PHONY: show-version patch minor major

show-version:  ## show current library version
	@bump-my-version show current_version

patch:  ## bump a patch version
	@bump-my-version bump patch

minor:  ## bump a minor version
	@bump-my-version bump minor

major:  ## bump a major version
	@bump-my-version bump major

########
# DIST #
########
.PHONY: dist dist-py dist-js dist-check publish

dist-py:  # build python dists
	python -m build -w -s

dist-js:  # build js dists
	cd js; pnpm pack

dist-check:  ## run python dist checker with twine
	python -m twine check dist/*

dist: clean build dist-js dist-py dist-check  ## build all dists

publish: dist  # publish python assets

#############
# BENCHMARK #
#############
.PHONY: benchmark benchmark-view

benchmark: ## run benchmark
	python -m asv run --config csp_gateway/benchmarks/asv.conf.jsonc --verbose `git rev-parse --abbrev-ref HEAD`^!

benchmark-quick: ## run quick benchmark
	python -m asv run --quick --config csp_gateway/benchmarks/asv.conf.jsonc --verbose `git rev-parse --abbrev-ref HEAD`^!

benchmark-local: ## run benchmark using the local env
	python -m asv run --python=same --config csp_gateway/benchmarks/asv.conf.jsonc --verbose

benchmark-debug: ## debug a failing benchmark
	if [ -z "${BENCHMARK_NAME}" ]; then echo 'Usage: make benchmark-debug BENCHMARK_NAME=<name of benchmark> [PARAM_INDEX=<index of param permutation>]'; exit 1; fi
	if [ -z "${PARAM_INDEX}" ]; then \
		python -m pdb -m asv.benchmark run csp_gateway/benchmarks/benchmarks ${BENCHMARK_NAME} "{}" /dev/null /dev/null; \
	else \
		python -m pdb -m asv.benchmark run csp_gateway/benchmarks/benchmarks ${BENCHMARK_NAME}-${PARAM_INDEX} "{}" /dev/null /dev/null; \
	fi;

benchmark-view:  ## generate viewable website of benchmark results
	python -m asv publish --config csp_gateway/benchmarks/asv.conf.jsonc
	python -m asv preview --config csp_gateway/benchmarks/asv.conf.jsonc


#########
# CLEAN #
#########
.PHONY: deep-clean clean

deep-clean: ## clean everything from the repository
	git clean -fdx

clean: ## clean the repository
	rm -rf .coverage coverage cover htmlcov logs build dist *.egg-info

############################################################################################

.PHONY: help

# Thanks to Francoise at marmelab.com for this
.DEFAULT_GOAL := help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

print-%:
	@echo '$*=$($*)'
