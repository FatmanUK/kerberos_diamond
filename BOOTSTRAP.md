# BOOTSTRAP.md — Kerberos Diamond

Written so a fresh agent — or a competing LLM — can resume this project after
total loss of session state. If this file and the repo disagree, **the repo
wins**: this is a snapshot, not a source of truth.

Read `CLAUDE.md` first. It is the working contract and is loaded into every
session; this file is the orientation around it.

## 1. Current Goal

A from-scratch **Go** reimplementation of **Kerberos 5**, behaviour-
compatible with the original — while deliberately replacing six things
that have aged worst in the C:

| Kerberos 5 (C) | Kerberos Diamond (Go) |
|---|---|
| Manual memory management | Go, memory-safe |
| Unencrypted connections | **TLS only** |
| Flat-file database | **Postgres** with GORM |
| autotools | Rootless **Podman** container |
| complex save and restore routines | crash-only architecture |
| high-availability very hard or impossible | high-availability almost effortless |

### Where it stands

- Still in planning.

## 2. Next Three Steps

To be determined by planning, though the plan's first step will be to update
`CLAUDE.md` and `BOOTSTRAP.md`.

## 3. Project State

### 3.1 Key Logic

- Nothing decided yet.

### 3.2 Architecture

- Nothing decided yet.

### 3.3 Decisions

Departures from the plan or from naive C-to-Go translation, recorded so they
are not "fixed" back by accident.

**Structural:**

- **The C reference is a submodule** at `kerberos/`, pinned to tag krb5-1.22.2-final
  rather than a moving branch. This is the upstream C reference.

**Compatibility choices:**

- **TLS only** — no cleartext, no STARTTLS.
- **Argon2id passwords**, with legacy algorithms read but not written.
- **New code says TLS, not SSL** — it's been TLS for over 20 years. Time to
  drop the SSL nomenclature (except where it would cause a problem).

### 3.4 Other

- **Go source is 70 columns, tab counted as 8.**
- **Store tests must never share a database with a real world.** The scratch
  schema goes in the connection string, not a `SET search_path`: GORM pools
  connections, so the SET reaches one of them and every other query lands in
  `public`.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**External Go modules** (`go.mod`):

- `golang.org/x/crypto` — Argon2id
- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`) — persistence

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `kerberos/`.

`kerberos/` is a leaf that only the generator scripts and `make golden-build`
read. No Go package imports it.

## 5. Version Log

Most recent first.

| Commit | Summary |
|---|---|
| `02c5b04` | Add source submodule |

Working branch: `mother`. Never merge the `kerberos/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

Nothing tested yet.
