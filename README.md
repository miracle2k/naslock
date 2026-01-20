# naslock

Unlock TrueNAS/FreeNAS encrypted datasets using secrets stored in a KeePass database.

## Overview

`naslock` is a small CLI that:

1. Prompts for your KeePass master password.
2. Opens the KeePass database and reads:
   - NAS auth credentials (username/password or API key).
   - Dataset unlock secret (passphrase or key).
3. Calls the TrueNAS REST API to unlock a dataset.

## Config

Default config location:

- macOS: `~/Library/Application Support/naslock/config.toml`
- Linux: `~/.config/naslock/config.toml`
- Windows: `%APPDATA%\\naslock\\config.toml`

Override with `NASLOCK_CONFIG` or `--config`.

See `config.example.toml` for a full example.

### KeePass entry selectors

Entries are referenced by **title** or **UUID**:

- Title (default): `NAS Login`
- UUID: `uuid:3d6f0b0c-6f7a-4c72-9d1b-badbeefcafe0`
- Force title: `title:NAS Login`

## Usage

```bash
naslock unlock tank-media
```

## TrueNAS API notes

This uses the REST v2.0 endpoint:

```
POST /api/v2.0/pool/dataset/unlock
```

On newer TrueNAS releases the REST API is deprecated but still works; if it is disabled in your environment you may need to enable it or switch to the WebSocket API in the future.

## Build

```bash
cargo build --release
```

The resulting binary will be at `target/release/naslock`.
