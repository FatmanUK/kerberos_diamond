# Kerberos Diamond

A from-scratch Go reimplementation of Kerberos 5, behaviour-compatible with
the original — an unmodified `kinit` built from the MIT sources obtains a
ticket from it and does not know the difference — while deliberately
replacing six things that have aged worst in the C:

| Kerberos 5 (C) | Kerberos Diamond (Go) |
|---|---|
| Manual memory management | Go, memory-safe |
| Unencrypted connections | **TLS only** |
| Flat-file database | **Postgres** with GORM |
| autotools | Rootless **Podman** container |
| Complex save and restore routines | Crash-only architecture |
| High availability very hard | High availability almost effortless |

"Behaviour-compatible" is a claim this repository tries hard to keep
falsifiable. `make golden` drives the same encoded request through a real C
KDC built from the pinned upstream sources and through this one in process,
decrypts both replies, and compares the decoded messages field by field; and
a stock, unpatched `kinit`, `kvno` and `kinit -R` from that same build are
run against this KDC. See [the differential
harness](#the-differential-harness) below.

## What works

- **The AS exchange**, with and without pre-authentication.
- **The TGS exchange**, including renewal, validation, postdating,
  forwarding, proxying and user-to-user.
- **Cross-realm**, including a path through a middle realm, the transited
  field, configured paths (`KD_CAPATHS`) and the referral a KDC offers when
  the trust asked for does not exist.
- **Six enctypes** in three families: RFC 3962's `aes256-cts-hmac-sha1-96`
  and `aes128-cts-hmac-sha1-96`, RFC 8009's `aes256-cts-hmac-sha384-192`
  and `aes128-cts-hmac-sha256-128`, and RFC 6803's `camellia256-cts-cmac`
  and `camellia128-cts-cmac` — which between them are everything upstream
  has not deprecated.
- **S4U2Self and S4U2Proxy**, with the two constrained-delegation
  relations as Postgres tables — which is the one place the departure from
  a flat-file database pays off outright: upstream's own answer is LDAP,
  and its test suite needs a plugin to reach the cases this fixture reaches
  with a `kdiamond` verb.
- **A signed Windows PAC** in every ticket, unless the client declines one
  or the realm turns them off — the container, the CLIENT_INFO buffer and
  all four checksums, anchored against PACs three generations of Windows
  KDC produced.
- **A principal database in Postgres**, with upstream's stored-key blob
  layout, so an imported MIT database can be read.
- **Principal administration** as `kdiamond` subcommands, standing in for
  `kadmin`.
- **MS-KKDCP over HTTPS** as the only transport, with `kdiamond-proxy` for
  clients built without a TLS module.
- **FAST** (RFC 6113), both exchanges, with the encrypted-challenge factor —
  so pre-authentication here resists an offline dictionary attack, which
  plain `PA-ENC-TIMESTAMP` does not. A stock `kinit -T` proves it. One
  limitation is the protocol's rather than this implementation's: FAST cannot
  protect a client's *first* exchange, because armoring needs a ticket the
  client does not yet have.

## What does not

- **The Windows PAC**, **S4U2Self** and **S4U2Proxy**. A stock KDC puts a
  signed PAC in every ticket; this issues none.
- **A `kadmin` protocol.** Provisioning needs a shell on the KDC's machine.
- **The host-based referral**, which needs a `[domain_realm]` equivalent.
- **Anonymous PKINIT**, which is the only way to armor a client's first
  exchange with FAST — see the limitation above.
- **DES, 3DES, RC4 and Camellia.** Not planned.

`BOOTSTRAP.md` §2 is the live list of what comes next, and §3.3 records every
deliberate divergence from upstream with a file and line.

## The C reference is a submodule

This is the single most useful thing to know about the repository. It
contains only Go; the lines of Kerberos C that everything is ported from are
the upstream project, vendored as a read-only submodule at `kerberos/` and
pinned to a release tag.

```bash
git submodule update --init kerberos
```

Nothing in `kerberos/` is ever edited. Several behaviours in this codebase
look like bugs until you read the original.

## Requirements

- Go 1.26.5 or later
- Podman (rootless) — for Postgres, the container images, and the C oracle
- GNU Make
- `psql` is convenient but not required

Nothing else: the standard library covers the ASN.1, the crypto and the
transport, and the only external Go modules are GORM with its Postgres
driver and `golang.org/x/crypto` for Argon2id.

## Quick start

```bash
git clone --recurse-submodules \
    https://github.com/FatmanUK/kerberos_diamond.git
cd kerberos_diamond
make certs db-up
```

`make certs` writes a self-signed certificate into `deploy/tls/`; `make
db-up` starts Postgres in a container on port 55433 and waits for it to
answer.

Provision a realm and start the KDC. The master password is the only secret
the KDC holds, and there is no stash file — realm plus password determine
the database master key, so a replacement container derives the same one
from the same environment:

```bash
DB=postgres://kdiamond:kdiamond@localhost:55433/kdiamond
export KD_DATABASE_URL="$DB?sslmode=disable"
export KD_REALM=KDIAMOND.TEST
export KD_MASTER_PASSWORD=choose-something-better-than-this
make build
./kdiamond addprinc -pw tgtpassword krbtgt/KDIAMOND.TEST
./kdiamond addprinc -pw userpassword alice
make run
```

`make run` sets `KD_MASTER_PASSWORD` from the Makefile's own
`MASTER_PW`, which defaults to something useless on purpose; exporting
your own overrides it for the subcommands above. The administrative
subcommands ask only for what they use -- a database, a realm and the
master password -- and need no TLS material, because they open no
socket.

A client then needs the shim, because MS-KKDCP is the KDC's only transport
and most Kerberos clients are built without a TLS module:

```bash
./kdiamond-proxy -kdc https://localhost:8088/KdcProxy -realm KDIAMOND.TEST
```

and a `krb5.conf` naming it:

```ini
[libdefaults]
	default_realm = KDIAMOND.TEST
	udp_preference_limit = 1

[realms]
	KDIAMOND.TEST = {
		kdc = 127.0.0.1:8088
	}
```

Be clear about what that proves and what it does not: the client-to-shim hop
is loopback cleartext, so the shim carries the TLS and the client does not.
A client built *with* a TLS module reaches the KDC's HTTPS listener directly
from `kdc = https://host:8088/KdcProxy` and needs no shim.

## Configuration

Every setting is an environment variable. There is no configuration file, no
flag that persists anything, and nothing read from the database at startup —
a KDC derives its whole view of the world from its environment, which is
what makes a replacement container interchangeable with the one it replaced.
A bad environment reports *all* of its faults at once, because reporting the
first costs one restart per mistake.

| Variable | Default | Meaning |
|---|---|---|
| `KD_DATABASE_URL` | — | Postgres connection string |
| `KD_REALM` | — | the realm this KDC serves |
| `KD_MASTER_PASSWORD` | — | what the database master key is derived from |
| `KD_TLS_CERT_FILE` | — | PEM certificate |
| `KD_TLS_KEY_FILE` | — | PEM private key |
| `KD_LISTEN_ADDR` | `:8088` | host:port for the HTTPS listener |
| `KD_PROXY_PATH` | `KdcProxy` | URL path KKDCP requests arrive on |
| `KD_CLOCK_SKEW` | `5m` | how far a client's clock may be out |
| `KD_MASTER_KDF` | `argon2id` | or `string2key`, to read an MIT database |
| `KD_CAPATHS` | none | cross-realm paths; see below |

The five with no default are required and the KDC will not start without
them.

`KD_CAPATHS` is krb5.conf's `[capaths]` folded onto one line: entries
separated by semicolons, each `client>server=hop[,hop...]`, with a lone `.`
for a direct trust. Upstream's own documented example becomes

```
ANL.GOV>NERSC.GOV=ES.NET;ANL.GOV>ES.NET=.;ANL.GOV>HAL.COM=K5.MOON,K5.JUPITER
```

Unset means none, and then every path is decided by the realm-naming
hierarchy — which is the common case, because realms in one organisation are
usually named as a hierarchy on purpose.

## Administration

`kdiamond` doubles as its own `kadmin`. The subcommands read the same
environment the KDC does and talk to the database directly.

```bash
kdiamond addprinc -pw PW [-kvno N] [-maxlife D] [-maxrenewlife D] \
                  [-attr SPEC] PRINC
kdiamond modprinc [-maxlife D] [-maxrenewlife D] [-attr SPEC] PRINC
kdiamond cpw -pw PW PRINC     # change a password, bumping the kvno
kdiamond delprinc PRINC
kdiamond getprinc PRINC
kdiamond listprincs
```

An attribute `SPEC` is kadmin's, sign included: `+requires_preauth`,
`-allow_tix`, `+forwardable`. Most are inverted — `+forwardable` *clears*
`DISALLOW_FORWARDABLE` — so read them as what the principal is permitted,
not as which bit is set.

## Testing

```bash
make check         # vet, the formatting check, the 70-column check, the tests
make test-short    # only the tests that need no database
make width-check   # no Go line over 70 columns, counting a tab as 8
```

`make check` starts Postgres itself unless `KD_TEST_DATABASE_URL` is already
set. Tests that need a database skip rather than fail when there is none, so
`make test-short` stays useful on a machine without Podman.

### The differential harness

```bash
make golden-build      # builds Kerberos 5 from the submodule in a container
make golden-build-tls  # a second image, with a TLS-capable client
make golden            # drives both implementations and diffs
```

`golden-build` compiles the C and takes minutes, so none of these is part
of `make check` or CI. The oracle serves four realms from one `krb5kdc`, so
cross-realm and three-realm paths can be driven without a second container.

`golden-build-tls` builds a **second image and it is not an oracle**:
Kerberos 5 with the OpenSSL TLS module, serving no realm, used by one test
and never compared against. It is what lets a stock `kinit` reach this
KDC's HTTPS listener with no `kdiamond-proxy` in front of it. Two cases
need it and the second is the interesting one — a client *without* the
module, given the same configuration, reports "Cannot contact any KDC" and
never mentions TLS at all. Without that image the project could not tell
the two apart. The cases skip if it is not built.

Three things about the comparison are worth knowing before reading it,
because each is load-bearing and each is a conclusion rather than a choice:

- **Byte-exact diffing cannot work.** Every `krb5_c_encrypt` prepends a
  fresh random confounder, so every ciphertext differs run to run even with
  identical keys and plaintext. The comparison is of decoded structures with
  the volatile fields normalised.
- **A case where both implementations fail identically passes while testing
  nothing.** Two KDCs both answering `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` agree
  perfectly. Every case asserts the exchange *succeeded*; the ones that
  expect a refusal say so and compare the hint a client has to act on.
- **Agreement is not correctness.** The two sides can match perfectly on a
  message no real client accepts — which is exactly how the RFC 6806 reply
  checksum was missed. The stock-client cases exist for that reason and are
  not redundant with the diff.

It earns its keep. On its first run it found four divergences nobody had
spotted by reading the C, and the stock `kinit` found a fifth the
field-by-field diff could not see. It has kept finding them since; the most
recent came from *deleting* its last declared exemption, which had been
quietly waiving two fields in every comparison. `BOOTSTRAP.md` §6 lists them.

There are no exemptions now. Every field of every case is compared.

## Layout

| Path | What |
|---|---|
| `cmd/kdiamond` | the KDC daemon, and `kadmin`'s replacement |
| `cmd/kdiamond-proxy` | the client-side KKDCP shim |
| `internal/config` | the environment, and nothing else |
| `internal/crypto` | RFC 3961/3962, RFC 8009 and RFC 6803 enctypes |
| `internal/camellia` | the Camellia block cipher and CMAC |
| `internal/pac` | the Windows PAC container and its checksums |
| `internal/ndr` | the PAC's one NDR buffer, for delegation |
| `internal/wire` | ASN.1/DER for the message types |
| `internal/store` | the principal database |
| `internal/transit` | the transited-realm field and realm paths |
| `internal/kdc` | the exchanges |
| `internal/transport` | the HTTPS listener and the shim's client half |
| `internal/golden` | the differential harness |
| `deploy/` | containers, and the oracle's realm fixture |
| `tools/reflow` | rewraps comments to 70 columns, which `gofmt` will not |
| `kerberos/` | the C, read-only, pinned |

## Further reading

- `CLAUDE.md` — the working contract: the column limit, the signing rule,
  what the submodule is for.
- `BOOTSTRAP.md` — orientation. §1 is what the tree does, §2 what is next,
  §3.3 every deliberate divergence with a citation, §6 what the tests cover
  and what they found.

## Licence

Apache License 2.0 — see `LICENSE`, and `NOTICE` for the attribution that
travels with it.

Apache rather than a copyleft licence for two reasons. Kerberos is an
interoperability substrate and the rest of the ecosystem is permissive, so
anything stricter would stop exactly the people most likely to want a KDC
from embedding one. And this implements three Microsoft protocols — MS-PAC,
MS-SFU and MS-KKDCP — so the explicit patent grant in §3 is worth having,
which neither MIT nor BSD gives you.

**This is not MIT Kerberos 5.** It is an independent reimplementation,
derived by translation from the MIT Kerberos 5 source rather than by
patching it, and it is neither endorsed by nor supported by MIT. MIT's own
licence terms travel with code derived from theirs and are reproduced in
`NOTICE`; several of the files this work was ported from require derived
software to say plainly that it is modified and not to be confused with the
original, which is what that file and this paragraph do.

Kerberos is an MIT trademark, used here to name the protocol being
implemented. MIT's notice requires prior written permission for commercial
use of the mark.
