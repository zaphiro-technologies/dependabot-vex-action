.PHONY: ci-pre-build test

ci-pre-build:
	@mkdir -p build

test:
	yarn test:cov
