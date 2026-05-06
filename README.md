# secret-fuse

A FUSE filesystem that renders files with secrets from 1Password on the fly.

No secrets are stored on disk. Files are rendered from templates at read time,
pulling values from 1Password via the `op` CLI.

## Requirements

- [macFUSE](https://osxfuse.github.io/) (macOS) or libfuse (Linux)
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`)

## Install

```bash
cargo install --path .
```

## Configuration

Create `~/.config/secretfuse/config.yaml`:

```yaml
mountpoint: ~/secrets
cache_ttl: 300  # seconds, default 5 minutes

files:
  # Inline template
  npm/.npmrc:
    content: |
      //registry.npmjs.org/:_authToken={{ op("op://Development/npm/token") }}

  # Template file reference
  myapp/.env:
    template: ~/.config/secretfuse/templates/myapp.env.tmpl

  # Single secret value
  myapp/api-key:
    secret: op://Production/myapp/api-key
```

## Usage

```bash
# Validate config and templates
secret-fuse check

# Mount (foreground)
secret-fuse mount

# Mount with custom config
secret-fuse --config /path/to/config.yaml mount

# Unmount
secret-fuse unmount

# Install as system service
secret-fuse install
```

## Symlinks

Point config files to the mount:

```bash
ln -s ~/secrets/npm/.npmrc ~/.npmrc
ln -s ~/secrets/myapp/.env ~/projects/myapp/.env
```

## Template Syntax

Templates use [Jinja2 syntax](https://jinja.palletsprojects.com/) via minijinja.

### Functions

- `op(uri)` -- fetch a secret: `{{ op("op://vault/item/field") }}`

### Filters

- `trim` -- strip whitespace
- `tojson` -- JSON string escaping
- `totoml` -- TOML string escaping
- `base64encode` -- base64 encoding

### Examples

```ini
DB_PASSWORD={{ op("op://Dev/postgres/password") | trim }}
```

```json
{ "apiKey": {{ op("op://Dev/api/key") | tojson }} }
```

## Cache

Secrets are cached in memory (default 5 minutes). Send `SIGHUP` to clear the cache.

## Development

A `.pre-commit-config.yaml` mirrors the CI lint job (`cargo fmt --check` on
commit, `cargo clippy --all-targets --locked -- -D warnings` on push). Install
the hooks once after cloning:

```bash
pre-commit install --hook-type pre-commit --hook-type pre-push
```

(Requires the [pre-commit](https://pre-commit.com/) tool: `brew install pre-commit` or `pip install pre-commit`.)
