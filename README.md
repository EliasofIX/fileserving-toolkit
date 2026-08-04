# FST — fileserving-toolkit

Suckless file server: Archive Light web UI, resumable single-stream transfers (TB-scale), optional post-quantum at-rest encryption, and a remote CLI for agents and scripts.

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

## Remote CLI

Agents and scripts use the same accounts as humans. Give the agent a username/password (or write `~/.config/fst/credentials.toml`), then:

```bash
export FST_URL=https://fst.tailxyz.ts.net
export FST_USER=claude
export FST_PASSWORD='…'

fst login
fst ls
fst ls shared/
fst mkdir ~claude/inbox
fst put ./report.pdf shared/inbox/report.pdf
fst get shared/inbox/report.pdf ./report.pdf
fst cat shared/notes.md
fst mv ~claude/draft.pdf ~claude/inbox/draft.pdf
fst rm ~claude/tmp/scratch.bin
fst whoami
fst logout
```

Or a credentials file (mode `600` — the CLI refuses to load it if group/other-readable):

```toml
# ~/.config/fst/credentials.toml
url = "https://fst.tailxyz.ts.net"
username = "claude"
password = "…"
```

Sessions are cached in `~/.config/fst/session` (also mode `600`) and sent as `Authorization: Bearer`. On `401` the CLI re-logins with the stored password.

`mv` only works within the same space (`shared/…` → `shared/…`, or `~user/…` → `~user/…`). Cross-space moves need `get` + `put` (re-encrypt). Use `--json` for machine-readable output.

Agent how-to: [`.agents/skills/fst-cli/SKILL.md`](.agents/skills/fst-cli/SKILL.md) (Cursor skill — invoke with `/fst-cli` or when the agent needs FST file ops).

## Transfers

Resumable upload protocol (single stream):

1. `POST /api/upload/init` `{path, size}` → `{id, offset}`
2. `PUT /api/upload/:id` with `X-FST-Offset` + body chunk (≤64 MiB)
3. `POST /api/upload/:id/complete`

Downloads use HTTP `Range`. Rename/move: `POST /api/rename` `{from, to}` (same principal). State survives process restart under `upload_state_dir`.

Large transfers open the **Transfer Dial** UI.

## Media

Optional `ffmpeg` / `ffprobe` for remux when the browser cannot play a container/codec natively. Leave paths empty / missing binaries to disable — zero cost when idle.

## Idle cost

Release binary, 2 tokio workers by default, no background polls except hourly session/upload GC. No database.

## License

[PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) — see `LICENSE`.
