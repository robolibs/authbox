SHELL := /bin/bash

PROJECT_NAME := $(shell sed -n '/^[[:space:]]*[^#\[[:space:]]/p' PROJECT | head -1 | tr -d '[:space:]')
PROJECT_VERSION := $(shell sed -n '/^[[:space:]]*[^#\[[:space:]]/p' PROJECT | sed -n '2p' | tr -d '[:space:]')
ifeq ($(PROJECT_NAME),)
    $(error Error: PROJECT file not found or invalid)
endif

TOP_DIR := $(CURDIR)
CARGO := cargo
EXAMPLE ?= simple_example
FEATURES ?=

HAS_REL := $(shell command -v git-rel 2>/dev/null)

$(info ------------------------------------------)
$(info Project: $(PROJECT_NAME) v$(PROJECT_VERSION))
$(info ------------------------------------------)

.PHONY: build b compile c run r test test-feature t check fmt fmt-check clippy docs bench clean help h

build:
	@$(CARGO) build --lib --all-features

b: build

compile:
	@$(CARGO) clean
	@$(MAKE) build

c: compile

run:
	@$(CARGO) run --example $(EXAMPLE)

r: run

test:
	@$(CARGO) test --all-targets --all-features

test-feature:
	@if [ -z "$(FEATURES)" ]; then \
		$(CARGO) test --all-targets; \
	else \
		$(CARGO) test --features "$(FEATURES)" --all-targets; \
	fi

t: test

check:
	@$(CARGO) check --all-targets --all-features

clippy:
	@$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	@$(CARGO) fmt --all

fmt-check:
	@$(CARGO) fmt --all -- --check

clean:
	@$(CARGO) clean

docs:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --all-features --no-deps

release:
	@if [ -z "$(HAS_REL)" ]; then \
		echo "git-rel is not installed. Please install it first."; \
		exit 1; \
	fi
	@if [ -z "$(TYPE)" ]; then \
		echo "Release type not specified. Use 'make release TYPE=[patch|minor|major|m.m.p]'"; \
		exit 1; \
	fi
	@git rel $(TYPE)

help:
	@echo
	@echo "Usage: make [target]"
	@echo
	@echo "Available targets:"
	@echo "  build        Build the library"
	@echo "  compile      Clean and rebuild"
	@echo "  run          Run a development example (if examples exist)"
	@echo "  test         Run all tests"
	@echo "  test-feature Run the CI feature-matrix test lane (FEATURES=\"...\")"
	@echo "  check        Run cargo check on all targets"
	@echo "  fmt          Format the workspace"
	@echo "  fmt-check    Check Rust formatting without rewriting files"
	@echo "  clippy       Run Clippy on all targets with warnings as errors"
	@echo "  docs         Build Rust API docs with warnings as errors"
	@echo "  clean        Remove Cargo build artifacts"
	@echo "  release      Release a new version"
	@echo
	@echo "Examples:"
	@echo "  make run"
	@echo "  make run EXAMPLE=simple_example"
	@echo "  make test-feature FEATURES=\"tracing config\""
	@echo

h: help
