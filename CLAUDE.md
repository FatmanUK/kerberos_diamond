# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

A from-scratch Go reimplementation of Kerberos 5, aiming for behaviour compatibility —
with six deliberate departures: Go instead of C, TLS-only networking, Postgres/GORM
instead of a flat-file database, rootless Podman containers instead of autotools,
crash-only architecture and high-availability through the 12-factor manifesto.

**There must be exactly one plan file for this project**, and it is
`~/.claude/plans/ah-no-that-s-the-rustling-cat.md`. That directory is shared
across every project on this machine, so other plan files live there too:
they belong to unrelated work and are never read or edited from here.
`BOOTSTRAP.md` §2 is the narrative of what has landed, and the plan file is
what is next.

## The C reference is a submodule

This is the single most useful thing to know. The repository itself contains
only Go; the lines of Kerberos C that everything is ported from are the
upstream project, vendored as a submodule at `kerberos/` and pinned to a
release tag:

```bash
git submodule update --init kerberos       # if kerberos/ is empty
git -C kerberos/ describe --tags --always  # which upstream this is
```

It is read-only reference. Nothing in `kerberos/` is ever edited, and the
submodule is moved to a new upstream release deliberately, not incidentally —
bumping it can be catastrophic.

**Check the C before implementing anything that claims to match upstream.**
Several behaviours in this codebase look like bugs until you read the original,
and several plausible-looking assumptions turned out to be wrong when checked.

Constrain Go source to 70 columns wide, counting a tab as 8. Keep functions
short, 40 lines at most.

## Committing

**Commit when ready.** Be aware that all commits are signed. The GPG keychain
is locked and must be unlocked by the user. Therefore the commit might fail
if the user can't unlock the keychain in time. This is intended behaviour.
When a signature fails, report this and stop work. Leave the work staged. The next
prompt is likely to request a commit and then continue work.

**Every commit is signed. Never `--no-gpg-sign`** — not to get past a failure,
not "just this once", not for a doc-only change.

**A commit message says what was *found*, not only what was done.** Divergences
are valuable output, and the message is where they are recorded for whoever reads
the history. Where upstream's behaviour differs from what its source reads like,
say so and cite the file and line.

## The golden-output harness

`internal/golden` is the oracle, and it works. `make golden-build` builds
Kerberos 5 from the `kerberos` submodule into a container; `make golden` then
drives the same request through that C KDC over TCP and through this project
in process, decrypts both replies, and diffs the decoded messages. It also
runs a stock, unpatched `kinit` from that image against this KDC through
`cmd/kdiamond-proxy`.

**Check against it rather than reasoning, wherever it can answer.** Reading
the C is guesswork, and the harness has already proved the point: on its first
run it found four divergences nobody had spotted by reading, and the stock
`kinit` found a fifth that the field-by-field diff could not see, because the
harness's own request did not provoke it. `BOOTSTRAP.md` §6 lists them.

`make golden` needs Podman and a Postgres; it is deliberately not part of
`make check` or CI, because the C build takes minutes.

Two things about the diff, both from the C, both load-bearing:

- **Byte-exact comparison cannot work.** Every `krb5_c_encrypt` prepends a
  fresh random confounder (`lib/crypto/krb/enc_dk_hmac.c:144`), so every
  ciphertext differs run to run even with identical keys and plaintext. The
  comparison is of decoded structures with the volatile fields normalized.
- **A case where both implementations fail identically passes while testing
  nothing.** Two KDCs both answering `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` agree
  perfectly. Every case must assert the exchange *succeeded*, not merely that
  the two sides matched. `decodeReply` refuses a KRB-ERROR outright and
  `assertSucceeded` requires a session key, a server name, an end time after
  the authtime and the initial flag; the one case that expects a refusal says
  so and compares the hint a client has to act on.
- **Agreement is not the same as correctness.** The two sides can match
  perfectly on a message no real client accepts — that is exactly how the
  RFC 6806 reply checksum was missed. The end-to-end `kinit` cases exist for
  that reason and are not redundant with the diff.
