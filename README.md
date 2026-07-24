# FST — fileserving-toolkit

Suckless file server: Archive Light web UI, resumable single-stream transfers (TB-scale), optional post-quantum at-rest encryption.

## Quick start (no encryption)

```bash
cp config.example.toml config.toml   # or use the bundled config.toml
cargo run --release
# open http://127.0.0.1:8080
```

## Encryption mode

1. Set `encryption.enabled = true` in `config.toml`.
2. Hash a password and add a user:

```bash
cargo run -- hash-password 'your-password'
# paste the hash into [[auth.users]] password_hash
```

3. Unlock the shared library keystore at boot:

```bash
export FST_SHARED_PASSWORD='your-shared-secret'
cargo run --release
```

4. Optional: pre-create keystores

```bash
cargo run -- init-keys admin 'your-password'
cargo run -- init-keys shared "$FST_SHARED_PASSWORD"
```

- `shared/*` files are sealed to the **shared** ML-KEM key.
- `~username/*` files are sealed to that user's key (unlocked at login).
- AES-256-GCM framed chunks + ML-KEM-768 DEK wrap (FIPS 203).

## Layout

| Path | Role |
|------|------|
| `shared/` | Library visible to all (authenticated) users |
| `~user/` | Per-user home |
| Single-admin | Configure one `admin` user only |

## Transfers

Resumable upload protocol (single stream):

1. `POST /api/upload/init` `{path, size}` → `{id, offset}`
2. `PUT /api/upload/:id` with `X-FST-Offset` + body chunk (≤64 MiB)
3. `POST /api/upload/:id/complete`

Downloads use HTTP `Range`. State survives process restart under `upload_state_dir`.

Large transfers open the **Transfer Dial** UI.

The browse UI can upload whole folders (picker or drag-and-drop). Nested paths are preserved under the current directory; parent folders are created automatically. Empty folders and zero-byte files are skipped.

## Media

Optional `ffmpeg` / `ffprobe` for remux when the browser cannot play a container/codec natively. Leave paths empty / missing binaries to disable — zero cost when idle.

## Idle cost

Release binary, 2 tokio workers by default, no background polls except hourly session/upload GC. No database.

## License

[PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) — see `LICENSE`.
