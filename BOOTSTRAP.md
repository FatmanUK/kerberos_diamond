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
- **The TGS exchange works.** A TGT from the AS path is spent for a service
  ticket, and the service's own key opens it. The tests start from a ticket
  this KDC actually issued rather than from one assembled by hand, so a bug
  in either path cannot hide behind the other.
- **The vertical slice is closed, and a stock `kinit` proves it.** An
  unmodified `kinit` built from the `kerberos/` submodule obtains a TGT from
  the Go KDC through `kdiamond-proxy`, on both the padata-free and the
  PA-ENC-TIMESTAMP path, and `klist` lists it. Nothing about the client is
  patched. That is the only evidence in the project that
  "behaviour-compatible" means anything in practice.
- **The golden harness also compares the messages.** One encoded AS-REQ goes
  to the C KDC in a container and to the Go KDC in process; both replies are
  decrypted — including the EncTicketPart that only the krbtgt key opens —
  and compared field by field. They match.
- **`internal/store` is done** for what the AS exchange needs: the schema,
  principal lookup, the stored-key blob layout, the kvno/enctype key search
  ported from `krb5_dbe_def_search_enctype`, and `SetPassword` for
  provisioning. Tests run against a real Postgres in a scratch schema and
  skip when `KD_TEST_DATABASE_URL` is unset.
- **`internal/wire` covers both exchanges**: AS-REQ, AS-REP, Ticket,
  EncTicketPart, EncKDCRepPart, KRB-ERROR, PA-ENC-TS-ENC, PA-ETYPE-INFO2,
  PA-PAC-REQUEST, the MS-KKDCP envelope and the TCP framing, plus AP-REQ, the
  Authenticator and the TGS messages. Every one of them is decoded from
  upstream's own byte-exact reference output and re-encoded to identical
  octets.
- **`internal/kdc` and `internal/transport` are done** for the AS exchange,
  padata-free and preauth paths both, and the ordinary TGS exchange beside
  it. Both binaries run: `kdiamond serve`
  listens on HTTPS speaking MS-KKDCP, and `kdiamond-proxy` carries TLS for a
  client built without a module of its own.
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
3. ~~**The protocol slice.**~~ Done. `internal/crypto`, `internal/wire`,
   `internal/store`, the AS exchange in `internal/kdc`, the KKDCP transport,
   and the differential comparison that proves the Go AS-REP matches the C
   KDC's field for field. `make golden` runs it.

**What is next, in the plan file's order:**

1. **The TGS exchange's differential case and a stock `kvno`.** The exchange
   is tested in process; it is not yet driven through the golden harness or
   by a real client, which is how the AS path's last two divergences were
   found.
2. **The remaining enctypes**, aes-sha2 (RFC 8009) first, because its
   KDF-HMAC-SHA2 derivation is a genuinely different scheme and will prove
   the enctype dispatch table is a table and not a special case.

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
**The TGS exchange:**

- **Only the ordinary case is implemented.** A client spends a TGT for a
  service ticket. Renewal, validation, postdating, forwarding, proxying and
  user-to-user (`ENC-TKT-IN-SKEY`) are all *refused* rather than ignored:
  their policy rules are ported so that a request asking for one gets the
  error upstream would give, but nothing issues such a ticket yet. Neither
  is S4U2Self or S4U2Proxy, nor cross-realm.
- **No replay cache.** Upstream does not keep one for a TGS exchange either
  — "Don't use a replay cache" (`kdc/kdc_util.c:188`) — so the authenticator's
  clock skew is the whole of the replay window, as it is there. A KDC that
  added one here would diverge.
- **Addresses are not checked.** Upstream compares the request's source
  address against the ticket's address list when it has one
  (`kdc_util.c:196-202`); the realm fixture sets `noaddresses = true`, so
  there is nothing to compare, and the check is not written.

**The AS exchange:**

- **No Windows PAC.** A stock MIT KDC puts a signed MS-PAC in every AS
  ticket unless the client declines one (`kdc/kdc_authdata.c:479-493`,
  `include_pac_p` at `kdc/kdc_preauth.c:1581-1609`). This KDC issues none:
  MS-PAC is NDR-encoded Windows interop carrying two keyed checksums, and it
  is nowhere near the AS slice. The golden harness declines the PAC with
  `PA-PAC-REQUEST(false)` — something an unmodified client is entitled to do
  — so the comparison covers the whole reply with no skipped fields, and the
  gap is recorded here instead of hidden in an exemption. A Windows client
  expecting a PAC will not be satisfied by this KDC yet.
- **No FAST.** Upstream's hint list leads with an empty `PA-FX-FAST` to
  advertise it (`kdc/kdc_preauth.c:380`). This does not advertise what it
  cannot do: claiming FAST would invite a client to negotiate something that
  then fails.
- **No authorization data, and `last-req` is upstream's stub.**
  `fetch_last_req_info` returns one constant `{KRB5_LRQ_NONE, 0}` entry
  (`kdc/kdc_util.c:677-688`); matching the stub is deliberate, because
  implementing last-req properly would diverge from every C transcript
  immediately.

**The principal store:**

- **The schema follows `kadmin/dbutil/tabdump.c`, not `krb5_db_entry`.**
  `include/kdb.h:191-213` is the field inventory, but tabdump already projects
  that struct into flat relations — `keydata`, `princ_flags`, `princ_lockout`,
  `princ_meta`, `princ_stringattrs`, `princ_tktpolicy`, `alias` — and that
  projection is the schema. Following it means a `tabdump` and a `SELECT` line
  up field for field, which is what makes the two implementations comparable.
  Every column of tabdump's `princ_meta` (`:443-513`) is *derived* from
  tl-data rather than being a struct field; here they are real columns.
- **tl-data types 1, 2, 3, 8 and 0x0b are promoted to columns**, and
  everything else is kept verbatim in a generic `tl_data(principal, type,
  contents)` table. Upstream's `tl_data` is an open extensibility bag and a
  KDB can carry types this implementation has never heard of — PAC logon
  info, server referrals, X.509 subject names. Dropping them on import would
  silently lose data another KDC put there, so dump and load stay possible.
- **Stored key material keeps upstream's blob layout**:
  `uint16le(true key length)` followed by the master-key-encrypted key,
  decrypted with **key usage 0** and no IV, and truncated to the declared
  length because the plaintext may be longer (`lib/kdb/decrypt_key.c:76-98`).
  The length prefix is not redundant — the ciphertext's plaintext carries a
  confounder — and the blob records no enctype of its own, so a `Key` row's
  enctype is the *key's*, not the ciphertext's. Keeping the layout is what
  lets an existing KDB be read and a dump round-trip.
- **The master-key indirection is kept, and the stash file is not.** Relying
  on database-level encryption instead was considered and rejected: a KDC
  assumes that reading the database is not the same as holding every
  principal's long-term key, and a `pg_dump` of plaintext key columns would
  end that assumption. Instead the key is derived at startup from
  `KD_MASTER_PASSWORD` by string-to-key over the salt for `K/M@REALM`,
  exactly as `kdb5_util create` does
  (`kadmin/dbutil/kdb5_create.c:223-231`). Realm plus password plus enctype
  determine it completely, so there is nothing on disk to stash and a
  replacement container derives the same key from the same environment —
  which is what a 12-factor process wants. The password becomes the only
  secret and has to be treated as one.
- **One master key, not a list — and the gap is reported, not hidden.**
  Upstream carries a list with a per-entry `mkvno`, tries each in turn, and
  reloads from disk once on total failure, which is how a live KDC survives a
  rollover. None of that is implemented. A row whose `mkvno` is neither zero
  nor the loaded version is refused with a distinct error rather than
  reported as a bad password, so the missing feature is visible instead of
  baffling.
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

Modules are added as the code that needs them lands, never ahead of it: a
`require` for an unimported module is one `go mod tidy` away from deletion,
so listing it early would not survive.

**External Go modules, required now:**

- `gorm.io/gorm` + `gorm.io/driver/postgres` — the principal store. They
  bring `jackc/pgx/v5`, `jackc/pgpassfile`, `jackc/pgservicefile`,
  `jackc/puddle/v2`, `jinzhu/inflection`, `jinzhu/now`, `golang.org/x/sync`
  and `golang.org/x/text` with them, all indirect.

**Intended, not yet required:**

- `golang.org/x/crypto` — Argon2id, when §3.3's password work lands

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
- **`internal/wire`** — covered, and anchored the same way: every message the
  AS exchange touches is decoded from `tests/asn.1/reference_encode.out` and
  re-encoded to byte-identical octets. That file is output from upstream's own
  encoder, so it settles every tag number, optionality rule and string type at
  once, including three the C comments warn about and three they do not. Both
  the all-fields and the optionals-absent form of each message are used,
  because absence is most of what there is to get wrong.
  - **One deliberate gap.** `KDC-PROXY-MESSAGE` has no reference encoding —
    upstream's test program does not cover it — so it is round-tripped against
    itself and its shape asserted by hand. It is checked for real by the shim
    talking to a stock client.
- **`internal/store`** — covered against a real Postgres, not a mock. Schema
  isolation is asserted rather than assumed: `assertSchemaIsolated` checks the
  tables landed in the scratch schema and *not* in `public`, which is what
  catches the `SET search_path` failure mode §3.4 warns about. Beyond the
  round trips: that a stored key decrypts to exactly what string-to-key
  produces for the principal's own salt, that keys come back highest-kvno
  first and that an ascending list would fail, that saving replaces a key list
  rather than merging it, that tl-data types the code does not understand
  survive, and that a wrong master key version is its own error. The blob
  layout, the key search and principal-name escaping are unit-tested with no
  database at all, so `make test-short` still covers them.
- **Everything else** — not written, so not tested. The packages hold a
  doc comment and nothing else.
- **`internal/golden`** — the oracle half is covered by six tests against the
  real C KDC. They skip, rather than fail, when the image has not been built,
  so `make check` stays green on a machine that has not spent four minutes
  compiling Kerberos 5. `make golden` runs them for real.
- **End to end, with a real client.** `make golden` runs a stock `kinit` from
  the oracle image against the Go KDC through the shim, for a principal with
  no preauth requirement and for one with it, and checks `klist` lists the
  TGT. A wrong password is refused, and the refusal's *reason* is asserted —
  a non-zero exit alone would also be what a client that could not reach the
  KDC produced. Each case reads the client's own trace to confirm it dialled
  the shim and not the C KDC sharing its container.
- **What the end-to-end check does not cover.** The client-to-shim hop is
  cleartext, so the TLS leg is exercised by `kdiamond-proxy` and not by the
  client. A client built *with* a TLS module reaches the KDC's HTTPS listener
  directly; until one is available, that half is covered only by
  `internal/transport`'s own tests, which do use real TLS.
- **The TGS exchange** — covered in process. The service ticket is opened
  with the service's own key and compared against the reply the client can
  read, and the negative cases are the ones that matter: a tampered body, an
  authenticator under the wrong session key, one with no checksum at all, a
  mismatched client name, a stale clock, and a request asking for a flag its
  TGT does not carry. Each asserts the *specific* protocol error, because
  they are different codes and a client acts on them differently.
- **`internal/kdc` and `internal/transport`** — covered. The reply is opened
  with the key a client derives from the password and the ticket with the
  krbtgt's, then the two halves are compared against each other. The preauth
  handshake is driven as a real client would: the salt used in the second
  round trip is the one the KDC's hint named, not one the test assumed. The
  transport is exercised end to end through real TLS, including a second
  request on the same connection, because the preauth handshake is two.
- **The differential comparison is real, and it works.** `make golden` sends
  one encoded AS-REQ to both implementations and compares the decoded,
  normalised structures. It found four divergences on its first run, all of
  them this implementation's fault and all now fixed: a missing
  PA-ETYPE-INFO2 in the reply, a transited type of 0 instead of 1, and the
  two consequences of the Windows PAC. Reading the C and reasoning about it
  had already missed all four.
- **Every golden case asserts the exchange *succeeded*.** Two KDCs that both
  answer `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` agree perfectly while testing
  nothing, so `decodeReply` refuses a KRB-ERROR outright and
  `assertSucceeded` requires a session key, a server name, an end time after
  the authtime, and the initial flag. The one case that expects a refusal —
  the first half of the preauth handshake — says so, and compares the hint a
  client has to act on rather than merely agreeing on "no".
- **Time *relationships* are asserted before the comparison.** Rebasing
  every timestamp on the authtime is what makes the two sides comparable,
  and it would also let a clamping bug normalise into a passing test, so each
  side is checked on its own first.

The 70-column rule is checked over the whole tree, not just a diff, and CI
is not allowed to ignore it.
