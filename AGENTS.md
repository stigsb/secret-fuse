# secret-fuse

A read-only FUSE filesystem that renders files with secrets from 1Password
on the fly. No secrets are stored on disk.

## Quick Start

```bash
cargo build                                    # build
cargo test -- --test-threads=1                 # run tests (single-threaded due to env var mocking)
cargo run -- --config fixtures/inline_config.yaml check  # validate test config
```

## Project Structure

- `src/config.rs` -- YAML config parsing (3 source types: content, template, secret)
- `src/resolver.rs` -- 1Password `op` CLI wrapper with TTL cache (SecretString)
- `src/template.rs` -- minijinja templates with `op()` function and filters
- `src/fs.rs` -- FUSE filesystem (fuser::Filesystem trait, read-only)
- `src/harden.rs` -- process hardening (mlockall, anti-ptrace, core dump prevention)
- `src/service.rs` -- launchd/systemd service file generation
- `src/main.rs` -- CLI entry point (mount/unmount/check/install)
- `fixtures/bin/op` -- mock `op` CLI script for tests (controlled via env vars)

## Testing

Tests use a mock `op` script at `fixtures/bin/op` instead of the real
1Password CLI. The mock is controlled via environment variables
(`MOCK_OP_RESPONSE`, `MOCK_OP_EXIT_CODE`, `MOCK_OP_STDERR`), so tests must
run single-threaded (`--test-threads=1`) to avoid env var races.

## Documentation

Read these docs for deeper context:

- [docs/architecture.md](docs/architecture.md) -- component design, data flow, and design decisions
- [docs/usage.md](docs/usage.md) -- installation, configuration, commands, and troubleshooting
- [docs/security.md](docs/security.md) -- threat model and memory hardening details
