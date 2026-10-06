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
- **`internal/crypto` covers four enctypes in two families**: RFC 3962's
  aes256- and aes128-cts-hmac-sha1-96 and RFC 8009's aes-sha2 pair. Every
  vector upstream publishes for all four is checked, and the default salt is
  cross-checked against what the C KDC actually computes.
- **A realm can be provisioned with `kdiamond` alone**, and a stock `kinit`
  then uses it. The administrative commands are exercised as a *binary* with
  arguments rather than by calling the functions behind them, so a flag that
  was never registered or a subcommand missing from the dispatch would fail
  the test. One case checks that `-maxlife 2h` beats a client's `-l 8h` —
  policy has to reach the KDC's decisions, not just the database.
- **Renewal works, and a stock `kinit -R` proves it.** A renewable TGT is
  renewed through the shim and the client's own `klist` shows the renew-until
  unmoved. The golden harness compares a renewal field for field as well,
  which matters more here than anywhere else: a renewal's times come from
  three places at once — the presented ticket's lifetime, its renew-till, and
  the clock — and its flags arrive already set and have to be partly cleared.
- **The TGS exchange works, and a stock `kvno` proves it.** An unmodified
  `kinit` gets a TGT and an unmodified `kvno` spends it for a service ticket,
  both against the Go KDC through `kdiamond-proxy`. The golden harness also
  presents *one* TGT to both implementations in the same encoded TGS-REQ —
  they share the fixture's krbtgt key, so the same ticket is valid at either —
  and compares the two replies field for field with both halves decrypted.
- **The TGS exchange issues everything it can now**: forwarding, proxying and
  user-to-user, where before each had only its refusal path. The golden
  harness compares all three against the C. User-to-user is the interesting
  one — it is the single case where the issued ticket is sealed with no
  long-term key at all, but with the session key out of a second ticket the
  client presents, so a principal with a password and no keytab can be
  reached. The realm fixture gained a `peer` principal with DISALLOW_SVR set
  for it, which makes the test prove something: an ordinary request for that
  principal is refused by both KDCs, and only the user-to-user request
  succeeds.
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

Everything the plan file listed is done, so this list is now the live one.
**Windows and Active Directory interop goes last, deliberately** — see §3.3.

1. ~~**The TGS cases nothing issues yet**~~ — forwarding, proxying and
   user-to-user. Done, and they found three divergences between them; see §6.
2. **Cross-realm.** The transited-path machinery is refused rather than
   evaluated, and a realm that cannot trust another is not much of a realm.
3. **FAST** (RFC 6113), which would also let the KDC stop declining to
   advertise it — currently the harness's one declared exemption.
4. **A `kadmin` protocol**, for provisioning from off-host. The `kdiamond`
   subcommands need a shell on the KDC's machine; something external
   eventually will not have one.
5. **A client built with a TLS module**, so the HTTPS leg is covered end to
   end without `kdiamond-proxy` in the way.
6. **The Windows PAC**, last but one.
7. **S4U2Self and S4U2Proxy**, last.

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
**Encryption types:**

- **Four, in two families, and the table really is a table.** RFC 3962's
  aes256- and aes128-cts-hmac-sha1-96 and RFC 8009's
  aes256-cts-hmac-sha384-192 and aes128-cts-hmac-sha256-128. The two
  families share almost nothing — one derives keys by n-folding a constant
  and encrypting it and MACs the *plaintext*; the other derives with a
  counter-mode HMAC and MACs the *ciphertext* — so the row carries those two
  steps as functions. A switch on the enctype would have put that difference
  in four places instead of one.
- **The aes-sha2 pair is preferred**, which `Supported()` reports and the KDC
  offers. A stock MIT *client* still asks for the sha1 pair first
  (`default_enctype_list`, `lib/krb5/krb/init_ctx.c:59-66`), and the client's
  order is what decides which of its long-term keys the reply is encrypted
  under. The KDC's order decides the session key and which key seals a
  ticket. Two orders, two jobs.
- **The oracle's realm is configured for all four.** MIT's default
  `supported_enctypes` is only the sha1 pair (`include/osconf.hin:109-111`),
  so a realm left at the default could never exercise the new family through
  the harness. The list is in the same order `Supported()` reports, because
  the KDC seals a ticket with the *first* key of a principal's highest key
  version whatever its enctype.

**The TGS exchange:**

- **Everything but S4U and cross-realm issues a ticket.** A client spends a
  TGT for a service ticket, renews a renewable ticket, validates a postdated
  one, asks for a postdated ticket, forwards and proxies, and reaches a
  principal with no keytab by user-to-user (`ENC-TKT-IN-SKEY`). What is left
  refused is S4U2Self, S4U2Proxy and cross-realm.
- **S4U2Proxy is refused, not ignored.** `KDC_OPT_CNAME_IN_ADDL_TKT` means the
  request is asking for a ticket on another principal's behalf; answering it
  as an ordinary request would issue a ticket naming the wrong client
  entirely, which is worse than saying no. It gets `KDC_ERR_BADOPTION`.
- **User-to-user is the one case with no long-term key in it.** The issued
  ticket is sealed with the session key out of the second ticket the client
  presents, and names no key version at all (`do_tgs_req.c:1056-1061`),
  because a session key has none. That is also why `DISALLOW_SVR` does not
  forbid it (`check_tgs_svc_deny_all`, `kdc/tgs_policy.c:152-156`): a
  principal that may not be a service may still be reached this way, and
  refusing it would refuse the only mechanism that works for a user.
- **A renewal or validation naming a different server than the ticket is
  refused**, which upstream does not do — though it *does* make exactly this
  check for forwarding and proxying, from the same function
  (`check_tgs_nontgt`, `kdc/tgs_policy.c:632-647`). It names the issued ticket
  after the *presented* ticket's server (`do_tgs_req.c:1012-1016`) while
  sealing it with the key of the server the *request* asked for, and nothing
  checks the two
  agree — so a mismatched request gets a ticket whose name and key belong to
  different principals, refused with `BAD_INTEGRITY` by whoever receives it.
  This answers `KDC_ERR_SERVER_NOMATCH` instead, whose name is exactly the
  condition. Issuing an unusable ticket is not behaviour worth preserving, and
  the normal case — a client renewing the ticket it holds — is unaffected.
- **No replay cache.** Upstream does not keep one for a TGS exchange either
  — "Don't use a replay cache" (`kdc/kdc_util.c:188`) — so the authenticator's
  clock skew is the whole of the replay window, as it is there. A KDC that
  added one here would diverge.
- **Addresses are carried but never read.** They travel as opaque DER: a
  forwarded or proxied ticket takes the request's addresses rather than the
  presented ticket's and the reply repeats them, which is upstream's behaviour
  (`do_tgs_req.c:1019-1027`), but nothing here parses one. Nor is the *source*
  address checked: upstream compares the request's against the ticket's list
  when it has one (`kdc_util.c:196-202`), and the realm fixture sets
  `noaddresses = true`, so there is nothing to compare and the check is not
  written.
- **Only an empty transited path is accepted.** Upstream runs
  `kdc_check_transited_list` and sets `TKT_FLG_TRANSIT_POLICY_CHECKED` when it
  passes, refusing the request when it does not — `reject_bad_transit`
  defaults to *true* (`kdc/main.c:305-309`). This implementation can evaluate
  only the empty path, which means the ticket never left this realm. A
  non-empty one is cross-realm and is refused rather than waved through:
  setting the flag on a path nothing examined would be a lie a service relies
  on, and `KDC_OPT_DISABLE_TRANSITED_CHECK` is refused for the same reason.

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
- **No FAST, and it is not advertised.** Upstream announces it twice: an
  empty `PA-FX-FAST` leads the preauth hint list (`kdc/kdc_preauth.c:380`),
  and another is added beside the RFC 6806 reply checksum unconditionally
  (`kdc/kdc_util.c:1800-1802`), which is how a client comes to write
  `fast_avail: yes` into its credential cache. This KDC does neither. A
  client told FAST were available and then refused it would be a broken
  deployment; one told it is unavailable simply does not use it, which is what
  every passing end-to-end case here does. It is the golden harness's one
  **declared exemption**, reported on every run rather than skipped.
- **No authorization data, and `last-req` is upstream's stub.**
  `fetch_last_req_info` returns one constant `{KRB5_LRQ_NONE, 0}` entry
  (`kdc/kdc_util.c:677-688`); matching the stub is deliberate, because
  implementing last-req properly would diverge from every C transcript
  immediately.

**Priorities:**

- **Windows and Active Directory interop goes last.** The MS-PAC, S4U2Self
  and S4U2Proxy are deprioritised behind every piece of standard-Kerberos
  work, because this realm's operator will not be using them. They sit near
  each other in upstream's code and it is easy to assume a cluster of related
  features; cross-realm, FAST, forwarding, proxying and user-to-user are not
  Windows features and come first even where they are larger. Deprioritised,
  not abandoned: if a Windows feature turns out to be the only way to finish
  something else, that is worth saying rather than quietly reordering.

**Crash-only and high availability:**

- **The KDC holds nothing a restart would have to rebuild**, and that is
  measured rather than asserted. Every principal and key is in Postgres, the
  master key is derived from the environment, and an exchange carries no state
  past its reply — no replay cache, no session table, nothing written. So
  several KDCs can serve one realm behind one address, and `make golden`
  issues a TGT at one and spends it at another sharing nothing but the
  database.
- **There is one stopping path and it is abrupt.** A signal calls
  `Server.Close`, not `Shutdown`: nothing needs draining, so a connection cut
  mid-flight costs a client one retry and costs the KDC nothing. Draining
  would be slower without being safer, and it would add a second stopping
  path that a crash never exercises.
- **`/healthz` is *readiness*, not liveness.** A KDC whose database is away
  reports 503 so a load balancer stops sending it traffic, and stays alive so
  nothing restarts it — restarting would not help, because the fault is
  elsewhere and the process recovers on its own. `make golden` proves that
  recovery: a dedicated Postgres is stopped under a running KDC, the KDC
  refuses cleanly with a KRB-ERROR and reports 503, the database comes back,
  and the *same process* answers again with no reconnection logic of its own.
- **A database it cannot reach is answered, not ignored.** The refusal is a
  KRB-ERROR with the generic code: a client that got nothing would retry
  forever, and "our database is down" is not something to tell a client.

**Administration:**

- **No kadmin protocol; `kdiamond` subcommands instead.** `addprinc`,
  `modprinc`, `cpw`, `delprinc`, `getprinc` and `listprincs`, with kadmin's
  own attribute specifiers. kadmin exists because a flat-file database can
  only be edited by a process on the same host; a relational one can be
  edited by anything that can reach it, so a second protocol earns its place
  only once something external needs to provision principals. The vocabulary
  is kadmin's deliberately — an operator should not have to learn a second
  set of words for the same job.
- **The attribute specifiers are mostly inverted, and that is upstream's
  doing.** The stored bits are nearly all `DISALLOW_` bits, so
  `+forwardable` *clears* `DISALLOW_FORWARDABLE`
  (`lib/kadm5/str_conv.c:50-94`). Eight of the fourteen attributes behave
  that way, which means reading `+` as "set the named bit" gets the opposite
  of what was asked. The table is ported with its aliases, and `getprinc`
  prints the *stored* names rather than the inverted spellings, as kadmin
  does.
- **Attributes are a repeatable `-attr` flag, not bare arguments.** kadmin
  takes them positionally; Go's flag package stops at the first non-flag
  argument, so a bare `+requires_preauth` before the principal name would
  swallow everything after it. Naming the flag is the honest fix.

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
- **Argon2id for the master key, and *only* the master key.** This is the
  place a memory-hard KDF can go without breaking anything, and the reason it
  cannot go further is worth stating plainly: Kerberos' string-to-key is part
  of the **protocol**. A client derives its long-term key from the password
  itself, using the function the enctype number fixes, over the salt and
  `s2kparams` the KDC advertises. Replacing that with Argon2id would mean no
  stock client could ever derive the same key — so a principal's long-term key
  stays PBKDF2, and the original intent of "Argon2id passwords" is not
  achievable while claiming to interoperate.
  The master key is different: no client ever sees it, it protects every
  stored key, and it is the single thing an attacker with a database dump
  needs. It is now Argon2id at RFC 9106's second recommended setting — 64 MiB,
  three passes, four lanes — paid once per process start, which a 12-factor
  KDC can afford and a password-checking path could not.
- **Upstream's derivation is still readable, never written.** `KD_MASTER_KDF`
  selects it (`string2key`), so a database created by MIT Kerberos can be
  opened and re-keyed. It is configuration rather than something stored
  because nothing persists that could carry it — the key is derived afresh at
  every start — and a wrong value corrupts nothing: a key simply does not
  decrypt, and the KDC says so.
- **The Argon2id parameters are fixed in code and changing one is a
  re-keying.** Nothing stores them, so raising a parameter changes the derived
  key and makes an existing database unreadable. That is the same operation as
  changing the master password, and should be treated as one.
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
- `golang.org/x/crypto` — Argon2id for the master key, which brings
  `golang.org/x/sys` for BLAKE2b's assembly paths.

Nothing else is intended. The standard library covers the rest.

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
  self-consistent. For RFC 3962: every n-fold vector from `t_nfold.c`, every
  appendix B string-to-key vector from `t_str2key.c`, all six Kc/Ke/Ki
  derivations from `t_derive.c`, and both keyed-checksum vectors from
  `t_cksums.c`. For RFC 8009: the six derivations, both string-to-key
  results, all eight published *ciphertexts* — decrypted, because a random
  confounder makes encrypt-and-compare impossible and a round trip would pass
  with the MAC over entirely the wrong bytes — and both checksums. Plus the
  negative cases a round trip cannot reach: tampering, a wrong key usage, a
  truncated ciphertext, and a weak iteration count.
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
- **Crash-only and HA** — covered by behaviour, not by inspection. A TGT
  issued at one KDC is spent at another sharing only the database; a
  dedicated Postgres is stopped and restarted under a running KDC and the same
  process recovers; readiness reports 503 while the database is away and 200
  when it returns; and the probe and the KKDCP path are separate routes, so a
  load balancer needs no Kerberos message and a client needs no probe path.
- **The master key's two derivations** — covered. Each is reproducible on its
  own, the two disagree with each other, the realm separates them, material
  sealed under one does not open under the other, and the legacy one is
  asserted against `crypto.StringToKey` over the K/M salt directly rather than
  against itself — because being byte-identical to upstream is the only thing
  that lets an MIT database be read.
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
- **The TGS exchange** — covered in process *and* differentially. The
  service ticket is opened
  with the service's own key and compared against the reply the client can
  read, and the negative cases are the ones that matter: a tampered body, an
  authenticator under the wrong session key, one with no checksum at all, a
  mismatched client name, a stale clock, and a request asking for a flag its
  TGT does not carry. Each asserts the *specific* protocol error, because
  they are different codes and a client acts on them differently.
- **Forwarding, proxying and user-to-user** — covered in process and
  differentially. The forwarded and proxied cases follow the addresses: the
  issued ticket takes the *request's* rather than the presented ticket's, the
  reply repeats them under its own `[11]` tag, and an ordinary request leaves
  the reply's field absent. Proxying is exercised against a real service
  ticket obtained the ordinary way first, because that is what it
  re-addresses. The user-to-user cases decrypt the issued ticket with the
  session key out of the second ticket — nothing short of that proves which
  key sealed it — and the refusals are each asserted by their own code: no
  second ticket, a second ticket that is not a TGT, and one whose client is
  not the principal asked for. S4U2Proxy is asserted to be *refused* rather
  than quietly answered, because answering it as an ordinary request would
  issue a ticket for the wrong client.
- **Renewal and validation** — covered in process, differentially, and with a
  stock `kinit -R`. The in-process cases pin the KDC's clock to move time
  forward, and the client's clock with it: an authenticator left behind is
  refused for skew before anything interesting is reached, which is how the
  first draft of those tests failed.
- **The harness has one declared exemption**, for the FAST advertisement
  above. An exemption is not a skipped field: `Compare` returns waived
  differences separately from real ones and the test logs every one on every
  run, so the output always states what was not compared and a reader can
  disagree with the reason.
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
- **It found three more when forwarding, proxying and user-to-user landed**,
  and this time none of them was a missing field. Upstream requires a
  forwarded or proxied request to name the same server its presented ticket
  does — `NON_TGT_OPTION` covers all four of forwarded, proxy, renew and
  validate (`kdc/kdc_util.h:455-456`), where this implementation had checked
  only the latter two, and the C refused with `SERVER_NOMATCH` while the Go
  side issued a ticket. Chasing that turned up a second gap in the same
  function's other branch: `check_tgs_tgt` (`kdc/tgs_policy.c:653-665`)
  refuses an ordinary request that presents anything but a ticket-granting
  ticket, and nothing here had refused it, so any service ticket would have
  served as a TGT. The third came out of the test written for the first:
  `krb5_principal_compare` never looks at a name's *type*
  (`lib/krb5/krb/princ_comp.c:70-136`), and `PrincipalName.Equal` did — so a
  client naming `krbtgt` as NT-SRV-HST rather than NT-SRV-INST was refused a
  ticket upstream would have issued.
- **The comparison now renders a raw DER field's context tag**, not only its
  length, because of where those addresses go: a KDC-REQ-BODY's addresses are
  `[9]` and an EncKDCRepPart's caddr is `[11]`, the bytes inside are
  identical, and a decoder meeting an unexpected tag treats it as the end of
  the sequence rather than complaining. Carrying the request's field across
  unchanged would have cost the client its addresses *and* the encrypted
  padata after them, with nothing saying so.
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
