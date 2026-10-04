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

- **The skeleton is in**: `go.mod`, the package layout, both binaries, the
  `Makefile`, the container and deployment files, CI, and the formatting
  tool. `make check` is green.
- **The C oracle works.** `make golden-build` builds Kerberos 5 from the
  submodule into a container that creates its realm from nothing at start-up,
  and `make golden` drives it: six tests pass, covering a KRB-ERROR to a
  malformed frame, a padata-free single round trip, the PA-ENC-TIMESTAMP path,
  TCP-only transport, a TGT in the credential cache, and a wrong password
  being refused as a wrong password.
- **`internal/crypto` is done** for the two RFC 3962 AES types: the enctype
  table, n-fold, DR/DK derivation, PBKDF2 string-to-key, AES-CTS, and the
  HMAC-SHA1-96 integrity tag. Every vector upstream publishes for those is
  checked, and the default salt is cross-checked against what the C KDC
  actually computes.
- **No wire format, store or KDC yet.** `internal/wire`, `internal/store`,
  `internal/kdc` and `internal/transport` hold a doc comment and nothing
  else, and both binaries refuse to run with "not implemented yet" after
  loading their configuration.
- Planning is complete and the architecture in §3.2 and §3.3 is settled. §2
  is the order of work; steps 1 and 2 are done and step 3 is under way.

## 2. Next Three Steps

Planning is done; the plan file holds the detail. The increment it describes
is a vertical slice — a stock `kinit`, built from the `kerberos/` submodule
and otherwise unmodified, obtaining a TGT from the Go KDC, with the golden
harness proving the AS-REP matches the C KDC's field for field. It does not
attempt the TGS exchange, kadmin, FAST or cross-realm.

1. ~~The repository skeleton.~~ Done.
2. ~~The C oracle.~~ Done.
3. **The protocol slice**, in this order, because each needs the one before
   it: `internal/crypto` (aes256- and aes128-cts-hmac-sha1-96 behind a
   dispatch table, tested against the RFC 3962 vectors upstream already has
   runnable in `lib/crypto/crypto_tests/`), `internal/wire` (the ASN.1 the AS
   exchange touches, round-tripped against `tests/asn.1/reference_encode.out`),
   `internal/store` (principals in Postgres, modelled on
   `kadmin/dbutil/tabdump.c`'s relations), then the AS exchange and the
   differential comparison.

## 3. Project State

### 3.1 Key Logic

- **`aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96`** are
  implemented, behind a dispatch table from the outset so later enctype
  families are rows rather than special cases. `Profile(enctype)` is the only
  way in; nothing calls a cipher directly.
- **The single-block CTS quirk is load-bearing.** Upstream encrypts a
  one-block message with plain CBC and a *forced zero IV*, discarding the
  caller's (`lib/crypto/builtin/enc_provider/aes.c:253-261`). A derivation
  constant is exactly one block, so the whole key-derivation path goes
  through that case; a "tidier" implementation that honoured the IV would
  derive different keys from every password.
- **A PBKDF2 iteration count below the enctype default is refused**, not
  honoured (`lib/crypto/krb/s2k_pbkdf2.c:116-126`). The count arrives from
  the network in `s2kparams`, so without the floor a hostile KDC could talk a
  client into a one-iteration derivation.
- **The default salt has no separator**: realm followed by the name
  components, concatenated (`lib/krb5/krb/pr_to_salt.c:36-67`). Principals
  can therefore collide — realm `EXAMPLE.COM` name `ab` salts identically to
  realm `EXAMPLE.COMa` name `b` — and that is simply how Kerberos salts.
  Inserting a separator would disagree with every other implementation, and
  would surface as "bad password" rather than as a salt fault.

### 3.2 Architecture

The layout exists; all but `internal/config` is still empty.

- **Packages**: `internal/config` (12-factor env), `internal/store`
  (Postgres/GORM), `internal/wire` (ASN.1/DER), `internal/crypto` (RFC
  3961/3962), `internal/kdc` (the exchanges), `internal/transport` (the
  listener), `internal/golden` (the harness).
- **Binaries**: `cmd/kdiamond`, the KDC daemon, and `cmd/kdiamond-proxy`, the
  client-side KKDCP shim described in §3.3.
- **Configuration is environment-only.** Every setting is a `KD_`-prefixed
  variable: no configuration file, no flag that persists anything, nothing
  read from the database at startup. `internal/config` reports *all* of a
  bad environment's faults at once, because reporting the first costs one
  restart per mistake.
- **Tools**: `tools/reflow` rewraps comment paragraphs to 70 columns.
  `gofmt` does not wrap, so the rule in `CLAUDE.md` is otherwise
  unenforceable; `make fmt` runs gofmt, reflow, then gofmt again.

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
- **The oracle's `configure` is generated, not shipped.** The pinned release
  carries `configure.ac` but no `configure`, no `util/reconf` and no
  `include/autoconf.h.in`, so the oracle image runs `autoconf -f --include=.`
  and `autoheader --include=.` first. `aclocal` is deliberately not run and
  neither is a bare `autoreconf -i`: `aclocal.m4` is hand-maintained and
  checked in, and regenerating it would discard Kerberos' own macros. `bison`
  is a hard build dependency, because `kadmin/cli/getdate.y` and
  `lib/krb5/krb/x-deltat.y` ship with no generated `.c`.
- **The KDC lookaside cache is left enabled** in the oracle, at upstream's
  default. It returns a byte-identical cached reply for a repeated request
  within 120 seconds, which reads like a trap for a differential harness —
  but every request carries a fresh random nonce, so two runs of the same
  exchange never key to the same entry and the cache cannot fire. Disabling
  it would diverge from a real KDC for no gain.
- **The oracle's realm is fixed, not generated.** Realm, passwords and key
  version numbers are all constants, because the master key is *derived* —
  `string_to_key` over the master password salted with `K/M@REALM` — so a
  fixed password gives a reproducible master key and reproducible stored
  keys. The realm is built at container start rather than baked into the
  image, so each run begins from an identical database with no history.
- **Argon2id passwords**, with legacy algorithms read but not written.
- **New code says TLS, not SSL** — it's been TLS for over 20 years. Time to
  drop the SSL nomenclature (except where it would cause a problem).

### 3.4 Other

- **Go source is 70 columns, tab counted as 8.**
- **Store tests must never share a database with a real world.** The scratch
  schema goes in the connection string, not a `SET search_path`: GORM pools
  connections, so the SET reaches one of them and every other query lands in
  `public`.
- **A published Podman port says nothing about the container being
  ready.** Rootless Podman's port forwarder binds the host port as soon as the
  container is created, so dialling it succeeds immediately and a request
  arriving before the service is listening comes back as a connection reset.
  Readiness must be established by a real request-and-reply, not a successful
  dial. The oracle probes with the malformed frame its liveness test uses.
- **`podman exec` does not inherit the entrypoint's environment.** It starts a
  process with the *image's* ENV, so anything a start-up script exports is
  invisible to a later `exec`. The oracle's client variables are therefore
  image ENV; without that, `kinit` run through `exec` misses the realm
  configuration and silently falls back to DNS.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**`go.mod` requires nothing yet**, because nothing imports anything yet. The
modules below are the *intended* set and are added as the code that needs
them lands — a `require` for an unimported module is one `go mod tidy` away
from deletion, so listing them early would not survive.

**External Go modules** (intended):

- `golang.org/x/crypto` — Argon2id, when §3.3's password work lands
- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`) — persistence

The standard library covers more of this than it might seem:
`encoding/asn1` for the wire types, `crypto/aes`, `crypto/hmac`,
`crypto/sha1` and `crypto/pbkdf2` for the RFC 3962 enctypes, `crypto/tls`
for the transport, and `net/http` for the KKDCP listener.

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `kerberos/`.

`kerberos/` is a leaf that only the generator scripts and `make golden-build`
read. No Go package imports it.

## 5. Version Log

Most recent first.

| Commit | Summary |
|---|---|
| `9729e0b` | Sweep oracle containers a killed test run leaves behind |
| `82a0814` | Add the C oracle, and six tests that drive it |
| `3510d19` | Add the repository skeleton |
| `8ee600e` | Correct the record in the docs, and settle the transport |
| `5b2cc58` | Add initial CLAUDE.md and BOOTSTRAP.md |
| `02c5b04` | Add source submodule |

Working branch: `mother`. Never merge the `kerberos/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

`make check` runs `go vet`, the formatting check, the 70-column check and the
tests. It is green.

- **`internal/config`** — covered. Defaults, empty-is-unset, whitespace-is-
  unset, the duration parse, and that a bad environment reports *every*
  missing variable rather than the first.
- **`internal/crypto`** — covered, and anchored rather than
  self-consistent. Every n-fold vector from `t_nfold.c`, every RFC 3962
  appendix B string-to-key vector from `t_str2key.c`, all six AES Kc/Ke/Ki
  derivations from `t_derive.c`, and both AES keyed-checksum vectors from
  `t_cksums.c`. Plus the negative cases that a round-trip test cannot reach:
  tampering, a wrong key usage, a truncated ciphertext, and a weak iteration
  count.
- **One gap, deliberate and recorded.** Multi-block AES-CTS is round-tripped
  and checked against plain CBC with the final two blocks swapped, but is not
  anchored to a published vector: upstream's `t_cts.c` prints its results
  rather than asserting them, and says in its own header comment that it does
  not even compile. The real check arrives with the AS exchange, when the C
  client has to decrypt a reply this code encrypted.
- **Everything else** — not written, so not tested. The packages hold a
  doc comment and nothing else.
- **`internal/golden`** — the oracle half is covered by six tests against the
  real C KDC. They skip, rather than fail, when the image has not been built,
  so `make check` stays green on a machine that has not spent four minutes
  compiling Kerberos 5. `make golden` runs them for real.
- **Nothing is compared yet.** The harness can drive the C KDC and read its
  answers, but there is no Go KDC to put beside it, so `compare.go` and the
  normalisation it needs arrive with the protocol slice.

The 70-column rule is checked over the whole tree, not just a diff, and CI
is not allowed to ignore it.
