
# authbox

Header-only C++20 toolkit for PKI certificate handling, chain validation, CRLs, CSRs, DID URI parsing, and certificate verification workflows.

## Modules

- `include/pki/` - PKI primitives (X.509 parse/build/validate, trust store, CRL/CSR, verify protocol)
- `include/did/` - DID URI validation and parsing
- `include/authbox.hpp` - top-level include + startup logging/version helpers

## Build

Use the repository Makefile:

```bash
make config
make build
make test
```

Examples and tests are auto-discovered from `examples/*.cpp` and `test/*.cpp`.

## Namespace Notes

- Main namespace: `authbox`
- PKI namespace: `authbox::pik`
- Compatibility alias: `authbox::pki` -> `authbox::pik`
- Short alias: `ab` -> `authbox`
