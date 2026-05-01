# Architecture

secret-fuse is a read-only FUSE filesystem that renders files with secrets
fetched from 1Password at read time. No secrets are stored on disk.

## Components

```
┌─────────────────────────────────────────────────────┐
│                    CLI (main.rs)                     │
│  mount / unmount / check / install                  │
├──────────┬──────────┬──────────┬────────────────────┤
│  Config  │  Secret  │ Template │  FUSE Layer        │
│  Loader  │ Resolver │  Engine  │  (fs.rs)           │
│          │          │          │                    │
│ YAML     │ op CLI   │ minijinja│ fuser::Filesystem  │
│ parsing  │ + cache  │ + op()   │ read-only          │
└──────────┴──────────┴──────────┴────────────────────┘
```

### Config Loader (`config.rs`)

Parses `~/.config/secretfuse/config.yaml`. Each file entry has one of three
source types:

- `content:` -- inline Jinja2 template string
- `template:` -- path to a template file on disk
- `secret:` -- a single `op://` URI (rendered as-is, no template)

Supports tilde expansion (`~/`) in paths. Validates that referenced template
files exist on disk.

### Secret Resolver (`resolver.rs`)

Wraps calls to `op read <uri>` with an in-memory TTL cache.

- Cache is keyed by `op://` URI, so shared secrets across templates are
  fetched once.
- Default TTL: 300 seconds (configurable via `cache_ttl` in config).
- Cache values use `SecretString` (zeroized on drop).
- `SIGHUP` clears the cache.

### Template Engine (`template.rs`)

Uses minijinja (Jinja2-compatible) to render templates.

**Functions:**
- `op(uri)` -- fetches a secret via the resolver

**Filters:**
- `trim` -- strip whitespace (op CLI sometimes returns trailing newlines)
- `tojson` -- JSON string escaping (adds quotes + escapes)
- `totoml` -- TOML basic string escaping
- `base64encode` -- base64 encoding

Also provides `validate_syntax()` for the `check` command (parses templates
without fetching secrets).

### FUSE Layer (`fs.rs`)

Implements `fuser::Filesystem` as a read-only virtual filesystem.

- Directory tree is synthesized from config paths at mount time.
- Inodes are assigned sequentially (root = 1).
- File content is rendered on first `getattr`/`open` and cached with TTL.
- Rendered content cache uses zeroize-on-drop for security.
- All write operations return `EACCES`.
- Permissions: directories `0555`, files `0444`.

### Service Installation (`service.rs`)

Generates platform-specific service files:
- macOS: launchd plist at `~/Library/LaunchAgents/com.stigbakken.secret-fuse.plist`; logs via Apple unified logging (subsystem `com.stigbakken.secret-fuse`)
- Linux: systemd user unit at `~/.config/systemd/user/secret-fuse.service`; logs via journald

### Process Hardening (`harden.rs`)

Applied at startup before any secrets are loaded:
- `mlockall` -- prevents memory from being swapped to disk
- `setrlimit(RLIMIT_CORE, 0)` -- disables core dumps
- `PT_DENY_ATTACH` (macOS) / `PR_SET_DUMPABLE=0` (Linux) -- prevents ptrace

All hardening is best-effort (warns on failure, doesn't block startup).

## Data Flow

```
1. App reads ~/secrets/myapp/.env (via symlink)
2. FUSE layer receives read() for inode
3. Check content cache (TTL-based)
4. If miss: template engine renders the template
5. Template calls op("op://...") for each secret placeholder
6. Resolver checks its cache, or calls `op read` subprocess
7. Rendered content returned to app (and cached)
```

## Design Decisions

**Read-only filesystem.** Writes are blocked with `EACCES`. A future version
could detect what template change a write would correspond to, but this is
complex and out of scope for v1.

**Symlink-based integration.** Rather than mounting at multiple locations,
users create symlinks from where apps expect files to a single mountpoint.
This keeps the FUSE layer simple and avoids multi-mount complexity.

**`op` CLI subprocess model.** We shell out to `op read` rather than using a
direct API. This leverages the user's existing 1Password authentication
(biometric unlock, etc.) without needing to manage tokens ourselves.

**Render-on-getattr.** File size must be known before `read()` is called, so
we render eagerly on `getattr`. Since `getattr` is typically followed by
`read`, this avoids double rendering while keeping size reporting accurate.
