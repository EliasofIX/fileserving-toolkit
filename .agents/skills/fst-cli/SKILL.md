---
name: fst-cli
description: >-
  Use the FST (fileserving-toolkit) remote CLI to upload, download, list, mkdir,
  rename/move, and delete files on an FST server. Use when an agent needs to
  interact with FST, Archive Light, shared/ or ~user/ paths, put/get files on a
  tailnet or local file server, or when the user mentions fst login, fst put,
  fst get, or the fileserving-toolkit CLI.
---

# FST remote CLI

FST is a drop box / transfer hub (not a backup mirror). Agents are normal users:
username + password, same ACL as the web UI.

## Before anything

1. Confirm `fst` is on `PATH` (`fst --help`).
2. Confirm credentials exist (env or credentials file). Do **not** invent a server URL or password.
3. Prefer `--json` for machine-readable output.

### Auth

```bash
export FST_URL=https://fst.example          # required
export FST_USER=agentname                   # when encryption/auth is on
export FST_PASSWORD='…'                     # when encryption/auth is on
```

Or `~/.config/fst/credentials.toml` (mode `600`):

```toml
url = "https://fst.example"
username = "agentname"
password = "…"
```

Optional overrides: `--url`, `--user`, `--password`, `--credentials PATH`.

```bash
fst login          # cache session in ~/.config/fst/session
fst whoami
fst logout
```

Sessions are sent as `Authorization: Bearer`. On `401`, the CLI re-logins once with the stored password. A cached session is only reused when **both** URL and username match — always set `FST_USER` (or credentials.toml username) in auth mode. Open mode (encryption off) needs only `FST_URL`.

`put` refuses local symlinks (does not follow them). `get` resumes only via a `.fst-part` + `.fst-part.json` marker tied to that remote path — it will not append into an unrelated existing local file.

Never commit passwords, session files, or credentials.toml.

## Path model

Virtual paths only:

| Path | Meaning |
|------|---------|
| `shared/…` | Shared library (all authenticated users) |
| `~YOURUSER/…` | Your home (only you, unless admin) |

Empty `ls` lists roots you can see. There is no `/` filesystem root and no escaping via `..`.

## Commands

```bash
fst ls [path]
fst mkdir <path>
fst rm <path>
fst mv <from> <to>                 # same space only
fst put <local-file> <remote-path>
fst get <remote-path> [local-path]
fst cat <remote-path>              # stdout
fst whoami
```

Always pass `--json` when parsing in scripts/tools:

```bash
fst --json ls shared/inbox
fst --json whoami
```

### Upload / download

- `put` is resumable (init → chunked PUT → complete). Point at a **file**, not a directory.
- Remote path must include the filename: `shared/inbox/report.pdf`.
- `get` writes to `./<basename>` if local path omitted; resumes via HTTP Range if the local file already exists.
- `cat` streams to stdout (good for small text; use `get` for binaries / large files).

### Rename / move

`mv` only works **within the same space**:

- ✅ `shared/a.pdf` → `shared/inbox/a.pdf`
- ✅ `~alice/draft.pdf` → `~alice/out/draft.pdf`
- ❌ `~alice/x` → `shared/x` — rejected (needs re-encrypt). Do `get` then `put`, then `rm` if needed.

Destination must not already exist.

## Typical agent workflows

**Drop outputs into shared**

```bash
fst mkdir shared/runs/2026-08-04
fst put ./result.pdf shared/runs/2026-08-04/result.pdf
fst put ./notes.md shared/runs/2026-08-04/notes.md
fst --json ls shared/runs/2026-08-04
```

**Work in your home, then publish one file**

```bash
fst mkdir ~"$FST_USER"/scratch
fst put ./draft.bin ~"$FST_USER"/scratch/draft.bin
fst get ~"$FST_USER"/scratch/draft.bin ./draft.bin   # if you need it local again
fst put ./draft.bin shared/inbox/draft.bin           # cross-space = put, not mv
```

**Pull something and inspect**

```bash
fst --json ls shared/inbox
fst get shared/inbox/task.json ./task.json
# or for small text:
fst cat shared/inbox/readme.md
```

**Tidy**

```bash
fst mv shared/inbox/a.pdf shared/archive/a.pdf
fst rm ~"$FST_USER"/scratch/old.bin
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 2 | Auth / missing URL or credentials |
| 3 | Forbidden |
| 4 | Not found |
| 1 | Other error |

## Do not

- Do not build rsync/mirrors — upload/download the files you need.
- Do not `mv` across `shared` ↔ `~user`; use `get` + `put`.
- Do not put directories with `put` (file only).
- Do not echo `FST_PASSWORD` or write it into the repo.
- Do not assume admin: you only see `shared/` + your own `~user/` unless configured as admin.

## Quick check

```bash
fst whoami && fst ls && fst --json ls shared
```

If that fails with auth errors, fix `FST_URL` / user / password (or credentials.toml) before retrying transfers.
