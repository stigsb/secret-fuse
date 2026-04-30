# Security Model

secret-fuse is designed to keep secrets out of files on disk. This document
describes the threat model and protections in place.

## What secret-fuse protects against

- **Secrets in plaintext files.** Config files like `.env`, `.npmrc`, and
  `database.yml` often contain API keys and passwords as plain text. With
  secret-fuse, these files are virtual -- the secrets exist only in memory.

- **Secrets in swap.** `mlockall()` is called at startup to prevent the
  process's memory from being swapped to disk.

- **Secrets in core dumps.** Core dumps are disabled via
  `setrlimit(RLIMIT_CORE, 0)`.

- **Secrets lingering in freed memory.** Cached secrets use `SecretString`
  (from the `secrecy` crate) which zeroizes memory on drop. Rendered file
  content caches also zeroize on eviction.

- **Same-user process inspection.** `PT_DENY_ATTACH` (macOS) and
  `PR_SET_DUMPABLE=0` (Linux) prevent other processes from attaching to read
  memory.

## What secret-fuse does NOT protect against

- **Root access.** A root user can bypass all of these protections.

- **Secrets in the reading process.** Once an application reads a secret from
  the mounted file, that secret lives in the application's memory, which
  secret-fuse has no control over.

- **1Password CLI authentication.** secret-fuse delegates authentication to
  `op`. If `op` is compromised or misconfigured, secrets are exposed.

- **Template files on disk.** Template files (referenced via `template:`)
  live on the real filesystem. They don't contain secrets themselves (only
  `op://` URIs), but they reveal which secrets are used and where.

- **Config file on disk.** The config file reveals the structure of the
  virtual filesystem and which 1Password items are referenced.

## Hardening details

All hardening is applied at startup before any secrets are loaded. Failures
are logged as warnings but don't prevent the daemon from starting (some
environments restrict `mlockall` or `ptrace` settings).

| Protection | System call | Platform |
|---|---|---|
| Memory locking | `mlockall(MCL_CURRENT \| MCL_FUTURE)` | Both |
| Core dump prevention | `setrlimit(RLIMIT_CORE, 0)` | Both |
| Anti-ptrace | `ptrace(PT_DENY_ATTACH)` | macOS |
| Anti-ptrace | `prctl(PR_SET_DUMPABLE, 0)` | Linux |
| Secret zeroization | `secrecy::SecretString` + `zeroize` | Both |
| Content zeroization | `CachedContent::drop` + `zeroize` | Both |
