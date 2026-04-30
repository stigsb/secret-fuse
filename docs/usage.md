# Usage Guide

## Prerequisites

1. **macFUSE** (macOS) or **libfuse** (Linux):
   ```bash
   # macOS
   brew install macfuse

   # Debian/Ubuntu
   sudo apt install libfuse-dev
   ```

2. **1Password CLI** (`op`):
   Install from https://developer.1password.com/docs/cli/

3. Sign in to 1Password CLI:
   ```bash
   eval $(op signin)
   ```

## Installation

```bash
cargo install --path .
```

## Configuration

Create `~/.config/secretfuse/config.yaml`:

```yaml
mountpoint: ~/secrets
cache_ttl: 300  # seconds (default: 300)

files:
  # Inline template -- good for one-liners
  npm/.npmrc:
    content: |
      //registry.npmjs.org/:_authToken={{ op("op://Development/npm/token") }}

  # Template file -- good for multi-line configs
  myapp/.env:
    template: ~/.config/secretfuse/templates/myapp.env.tmpl

  # Single secret -- no template needed
  myapp/api-key:
    secret: op://Production/myapp/api-key
```

### File Source Types

| Type | Use case | Example |
|------|----------|---------|
| `content:` | Inline template string | Small configs, one-liners |
| `template:` | Path to a `.tmpl` file | Multi-line configs with multiple secrets |
| `secret:` | Raw `op://` URI | Single secret value, no formatting needed |

### Template Syntax

Templates use Jinja2 syntax via minijinja.

**The `op()` function** fetches a secret:
```
{{ op("op://vault/item/field") }}
```

**Filters** transform the fetched value:

```ini
# Strip whitespace (op sometimes returns trailing newlines)
PASSWORD={{ op("op://Dev/db/password") | trim }}

# JSON-encode (adds quotes and escapes special chars)
{ "key": {{ op("op://Dev/api/key") | tojson }} }

# TOML string
password = {{ op("op://Dev/db/password") | totoml }}

# Base64 encode
token = {{ op("op://Dev/api/key") | base64encode }}
```

## Commands

### `secret-fuse check`

Validates config and template syntax without fetching any secrets:

```bash
secret-fuse check
# or with a custom config
secret-fuse --config /path/to/config.yaml check
```

Run this after editing your config to catch syntax errors early.

### `secret-fuse mount`

Mounts the filesystem in the foreground (logs to stderr, Ctrl-C to unmount):

```bash
secret-fuse mount
```

### `secret-fuse unmount`

Unmounts the filesystem (reads mountpoint from config):

```bash
secret-fuse unmount
```

### `secret-fuse install`

Generates a system service file so secret-fuse starts automatically at login:

```bash
secret-fuse install
```

- **macOS**: writes a launchd plist to `~/Library/LaunchAgents/`
- **Linux**: writes a systemd user unit to `~/.config/systemd/user/`

After installing:
```bash
# macOS
launchctl load ~/Library/LaunchAgents/ai.sunstoneinstitute.secret-fuse.plist

# Linux
systemctl --user enable --now secret-fuse
```

## Symlink Workflow

Create symlinks from where applications expect config files to the mountpoint:

```bash
# npm
ln -sf ~/secrets/npm/.npmrc ~/.npmrc

# Project-specific .env
ln -sf ~/secrets/myapp/.env ~/projects/myapp/.env

# Docker compose
ln -sf ~/secrets/docker/.env ~/projects/myapp/docker/.env
```

The filesystem is read-only. Tools that try to modify these files will get
"Operation not permitted" -- this is intentional.

## Cache Behavior

- Secrets are cached in memory for `cache_ttl` seconds (default: 300).
- Cache is per-secret (`op://` URI), not per-file. Two templates referencing
  the same secret share one cached value.
- Rendered file content is also cached with the same TTL.
- Send `SIGHUP` to the process to clear all caches immediately.
- All cached secret memory is zeroized on eviction/drop.

## Troubleshooting

### "1Password CLI (op) not found"

Install the 1Password CLI: https://developer.1password.com/docs/cli/

### "op CLI failed: not signed in"

Sign in first: `eval $(op signin)`

If using biometric unlock, make sure the 1Password desktop app is running.

### Mount fails with "Operation not permitted"

On macOS, macFUSE requires a kernel extension. After installing, approve it
in System Settings > Privacy & Security, then reboot.

### Slow first read

The first read of a file triggers secret fetching from 1Password. Subsequent
reads within the TTL window are served from cache.

### Logging

Set the `RUST_LOG` environment variable for debug output:

```bash
RUST_LOG=debug secret-fuse mount
```
