.PHONY: clean coverage coverage-check coverage-clean coverage-install docker-unit-test docker-integration docker-test docker-clean fmt-check help

DOCKER_BUILD_CHECK_IMAGE := panopticon-build-check
BPF_TOOLCHAIN := nightly-2026-02-17
COVERAGE_MIN_LINES ?= 74
COVERAGE_SUMMARY_FILE := target/coverage/summary.txt
COVERAGE_PACKAGES := -p panopticon-common -p xtask -p panopticon-agent

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

fmt-check: ## Check formatting with pinned nightly rustfmt
	cargo +$(BPF_TOOLCHAIN) fmt --all -- --check

coverage-install: ## Install cargo-llvm-cov
	cargo install cargo-llvm-cov --locked

coverage-clean: ## Remove old coverage artifacts
	cargo llvm-cov clean --workspace

coverage: coverage-clean ## Run coverage for testable crates and print summary
	@mkdir -p target/coverage
	bash -o pipefail -c 'AYA_BUILD_SKIP=1 cargo llvm-cov $(COVERAGE_PACKAGES) --summary-only | tee $(COVERAGE_SUMMARY_FILE)'

coverage-check: coverage-clean ## Enforce minimum line coverage for testable crates
	@mkdir -p target/coverage
	bash -o pipefail -c 'AYA_BUILD_SKIP=1 cargo llvm-cov $(COVERAGE_PACKAGES) --summary-only --fail-under-lines $(COVERAGE_MIN_LINES) | tee $(COVERAGE_SUMMARY_FILE)'

docker-unit-test: ## Build and run all unit tests in a Linux container
	docker build -f Dockerfile.build-check -t $(DOCKER_BUILD_CHECK_IMAGE) .

docker-integration: ## Run full E2E integration tests (services + traffic + validation)
	cd tests/integration && bash runner.sh

docker-test: docker-unit-test docker-integration ## Run unit tests then E2E integration

clean: ## Remove target/, temp dirs, and build artifacts
	cargo clean
	rm -rf tests/integration/output/

docker-clean: ## Remove Docker containers and images
	cd tests/integration && docker compose down --remove-orphans --volumes 2>/dev/null || true
	docker rmi $(DOCKER_BUILD_CHECK_IMAGE) 2>/dev/null || true
	docker rmi tests-integration-agent 2>/dev/null || true
	docker rmi tests-integration-traffic-gen 2>/dev/null || true
