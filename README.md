# pe

pe-rs is a zero-copy Portable Executable parser written in Rust. Basic header
parsing is implemented, but some data directory implementations are missing.
They can be added easily.

## Example uses

- The [tests](src/tests.rs) and [examples](examples/) have some usage examples.
- [pe2sgxs utility](https://github.com/jethrogb/sgx-utils/blob/master/sgxs/src/bin/pe2sgxs.rs)
- Your project here? File a PR.
