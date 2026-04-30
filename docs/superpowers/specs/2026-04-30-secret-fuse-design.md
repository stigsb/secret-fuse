# secret-fuse Design Spec

A FUSE filesystem that renders files containing secrets fetched from 1Password on the fly, eliminating the need to store secrets in local files.

## Problem

Development environments need config files with secrets (API tokens, database passwords, etc.) at specific filesystem paths. Currently these end up as plaintext files on disk. secret-fuse provides a virtual filesystem where files are rendered from templates at read time, pulling secret values from 1Password via the `op` CLI.

## Primary Use Case

Development environments where apps read config files (`.env`, `database.yml`, API configs) from well-known paths. Users create symlinks from where apps expect the files to the FUSE mountpoint.

## Technology

- **Language:** Rust
- **FUSE library:** `fuser` (pure Rust, supports macFUSE + libfuse)
- **Template engine:** `minijinja` (Jinja2-compatible, custom functions/filters)
- **Config parsing:** `serde` + `serde_yaml`
- **Platforms:** macOS (macFUSE), Linux (libfuse)

## Architecture

Four main components:

1. **Config Loader** -- Parses config YAML, validates entries, resolves template file paths
2. **Secret Resolver** -- Calls `op read` to fetch secrets, manages in-memory TTL cache
3. **Template Engine** -- Renders templates via minijinja with custom `op()` function and filters
4. **FUSE Layer** -- Read-only filesystem via `fuser`, serves rendered files at configured paths

### Data Flow

```
App reads ~/secrets/myapp/.env
  -> FUSE layer receives read() for "myapp/.env"
  -> Looks up config entry for that path
  -> Template engine renders the template
  -> Secret resolver fetches/caches op:// values
  -> Rendered content returned to the app
```

## Config Format

Config file location: `~/.config/secretfuse/config.yaml` (XDG-compliant, overridable via `--config`).

```yaml
# Global settings
mountpoint: ~/secrets
cache_ttl: 300  # seconds, default 5 minutes

# Files to render
files:
  # Inline template
  npm/.npmrc:
    content: |
      //registry.npmjs.org/:_authToken={{ op("op://Development/npm/token") }}

  # File-referenced template
  myapp/.env:
    template: ~/.config/secretfuse/templates/myapp.env.tmpl

  # Simple single-value shorthand
  myapp/api-key:
    secret: op://Production/myapp/api-key
```

- Paths under `files:` are relative to the mountpoint
- Intermediate directories are auto-created in the virtual filesystem
- `secret:` shorthand avoids needing a template for single-value files
- `op()` is a template function (not bare `op://` interpolation) for unambiguous parsing

## Secret Resolver & Caching

### Fetching

- Invokes `op read <op://vault/item/field>` as a subprocess
- 5-second timeout per `op` call to avoid hanging the filesystem
- If `op` isn't authenticated, returns `EIO` and logs: "1Password CLI not authenticated -- run `eval $(op signin)`"

### Cache

- In-memory `HashMap<String, CachedSecret>` keyed by `op://` URI
- Each entry stores the secret value and an expiry timestamp
- Cache is per-secret, not per-file -- shared secrets across templates are fetched once
- Global TTL from config, default 300 seconds

### Cache Invalidation

- Natural TTL expiry
- `SIGHUP` clears the entire cache, forcing re-fetch on next read

### Error Handling

- `op` not found at startup: exit with clear error message
- `op` returns non-zero: return `EIO` for that file read, log stderr
- Timeouts / network errors: return `EIO`, serve stale cache if available

## FUSE Layer

### Filesystem Properties

- **Read-only** -- all write operations return `EACCES`
- Directory tree synthesized from config paths at mount time
- File permissions: `0444`, directory permissions: `0555`, owned by mounting user

### Inode Management

- Inodes assigned at mount time from config -- root dir is inode 1, sequential for the rest
- Static filesystem (set of files doesn't change at runtime)

### Supported FUSE Operations

- `lookup` -- resolve a name in a directory
- `getattr` -- return file/dir metadata
- `readdir` -- list directory contents
- `read` -- render template and return content
- `open` -- validate file exists, read-only mode only
- All other operations return `EACCES` or `ENOSYS`

### File Size Reporting

Render on first `getattr`/`open` and cache the rendered content. Since the cache TTL covers freshness, and `getattr` is typically followed by `read`, this avoids the problem of reporting incorrect sizes.

## Template Engine & Filters

### Template Functions

- `op(uri)` -- fetches a secret from 1Password. Usage: `{{ op("op://vault/item/field") }}`

### Built-in Filters

- `tojson` -- JSON string escaping
- `totoml` -- TOML-appropriate escaping
- `base64` -- base64 encoding
- `trim` -- strip whitespace (1Password values sometimes have trailing newlines)

### Example Templates

```ini
# .env style
DATABASE_URL=postgres://app:{{ op("op://Dev/postgres/password") | trim }}@localhost/mydb
```

```json
{
  "apiKey": {{ op("op://Dev/api/key") | tojson }},
  "dbPassword": {{ op("op://Dev/postgres/password") | tojson }}
}
```

### Error Handling

- If `op()` fails for a specific secret, the template render fails and the file read returns `EIO`
- Errors are logged with the `op://` URI that failed (never the secret value)

## CLI Commands

- `secret-fuse mount` -- mount in foreground (Ctrl-C to unmount)
- `secret-fuse mount --daemon` -- mount in background
- `secret-fuse unmount` -- unmount the filesystem
- `secret-fuse check` -- parse all templates and validate syntax without fetching secrets
- `secret-fuse install` -- generate launchd plist (macOS) or systemd unit (Linux)

## Symlink Workflow

Users create symlinks from where apps expect config files to the FUSE mount:

```bash
ln -s ~/secrets/npm/.npmrc ~/.npmrc
ln -s ~/secrets/myapp/.env ~/projects/myapp/.env
```

The FUSE filesystem is read-only. Tools that try to modify symlinked files will get `EACCES`. This is the intended behavior for v1.

## Out of Scope (v1)

- Write support / reverse-templating writes
- Per-file cache TTL overrides
- Multiple mountpoints
- Direct 1Password Connect API (vs `op` CLI)
- File watching / config hot-reload
