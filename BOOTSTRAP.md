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

- **No Go in the tree yet** — no `go.mod`, no packages, nothing tested. The
  repository holds this file, `CLAUDE.md`, `.gitmodules` and the `kerberos/`
  submodule.
- Planning is complete and the architecture in §3.2 and §3.3 is settled. §2
  is the order of work.

## 2. Next Three Steps

Planning is done; the plan file holds the detail. The increment it describes
is a vertical slice — a stock `kinit`, built from the `kerberos/` submodule
and otherwise unmodified, obtaining a TGT from the Go KDC, with the golden
harness proving the AS-REP matches the C KDC's field for field. It does not
attempt the TGS exchange, kadmin, FAST or cross-realm.

1. **The repository skeleton.** `go.mod`, the `Makefile`, the container and
   deployment files, CI, and the package layout. No Kerberos logic.
2. **The C oracle.** The container that builds Kerberos 5 from the submodule
   and sets up a realm non-interactively. It depends on no Go at all, so it
   comes before any protocol code and every later commit has a reference to
   check against.
3. **The protocol slice.** `internal/crypto` (two AES enctypes behind a
   dispatch table), `internal/wire` (the ASN.1 the AS exchange touches),
   `internal/store` (principals in Postgres), then the AS exchange itself and
   the differential test.

## 3. Project State

### 3.1 Key Logic

- Nothing implemented yet. The first enctypes will be
  `aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96` — what a stock
  client negotiates by default — behind a dispatch table from the outset, so
  later enctype families are rows rather than special cases.

### 3.2 Architecture

Decided, not yet built.

- **Packages**: `internal/config` (12-factor env), `internal/store`
  (Postgres/GORM), `internal/wire` (ASN.1/DER), `internal/crypto` (RFC
  3961/3962), `internal/kdc` (the exchanges), `internal/transport` (the
  listener), `internal/golden` (the harness).
- **Binaries**: `cmd/kdiamond`, the KDC daemon, and `cmd/kdiamond-proxy`, the
  client-side KKDCP shim described in §3.3.

### 3.3 Decisions

Departures from the plan or from naive C-to-Go translation, recorded so they
are not "fixed" back by accident.

**Structural:**

- **The C reference is a submodule** at `kerberos/`, pinned to tag krb5-1.22.2-final
  rather than a moving branch. This is the upstream C reference.

**Compatibility choices:**

- **TLS only** — no cleartext, no STARTTLS.
- **The wire transport is MS-KKDCP over HTTPS.** The KDC is an HTTPS server;
  KDC messages travel in a DER `KDC-PROXY-MESSAGE` posted as
  `application/kerberos`, and `kerb-message` carries the 4-byte big-endian
  length prefix as though it were the TCP payload. This was chosen because
  upstream already supports it on the client side
  (`lib/krb5/os/sendto_kdc.c:604`, `lib/krb5/os/locate_kdc.c:217`), so "TLS
  only" costs no client compatibility: a realm stanza naming
  `kdc = https://host:port/path` is all a capable client needs.
- **No OpenSSL anywhere, including in the C oracle.** Upstream's `k5tls`
  plugin is the only part of Kerberos 5 that wants it — core crypto defaults
  to `CRYPTO_IMPL=builtin` (`src/configure.ac:266-273`) — so the oracle is
  built `--with-tls-impl=no`. `configure.ac:296-322` accepts only `openssl`,
  `auto` or `no`, and `auto` links libssl if it happens to be installed, so
  the flag is passed explicitly.
- **`cmd/kdiamond-proxy` carries TLS for clients that cannot.** A client
  built without a TLS module — the oracle's, for one — reaches the KDC
  through this shim: plain Kerberos TCP on loopback in, KKDCP over HTTPS
  out, TLS by Go's `crypto/tls`. It is a supported component rather than a
  test fixture, because any real client built without a TLS module needs
  exactly this. The loopback hop is cleartext, so a test using it
  demonstrates protocol interoperability, not that the client negotiated
  the TLS itself.
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

**There is no `go.mod` yet.** This section is the *intended* dependency set,
not a reading of the tree.

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
| `5b2cc58` | Add initial CLAUDE.md and BOOTSTRAP.md |
| `02c5b04` | Add source submodule |

Working branch: `mother`. Never merge the `kerberos/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

Nothing tested yet.
