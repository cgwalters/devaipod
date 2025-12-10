# Understanding Makefile vs Justfile:
#
# This file should primarily *only* involve
# invoking tools which *do not* have side effects outside
# of the current working directory. In particular, this file MUST NOT:
# - Spawn podman or virtualization tools
# - Invoke `sudo`
#
# Stated positively, the code invoked from here is only expected to
# operate as part of "a build" that results in binaries plus data files.
# The two key operations are `make` and `make install`. As this is Rust,
# the generated binaries are in the current directory under `target/`
# by default.
#
# The Justfile contains rules for things like integration tests,
# container builds, etc.

prefix ?= /usr

# Build all binaries
.PHONY: bin
bin:
	cargo build --release --workspace

install:
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/devaipod
	install -d -m 0755 $(DESTDIR)$(prefix)/lib/devaipod/upcalls
	install -D -m 0755 -t $(DESTDIR)$(prefix)/lib/devaipod/upcalls target/release/gh-restricted

.PHONY: validate
validate:
	cargo fmt -- --check -l
	cargo test --no-run
	cargo clippy -- -D warnings

.PHONY: clean
clean:
	cargo clean
