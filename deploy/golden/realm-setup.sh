#!/bin/sh
# Create the oracle's realms from nothing, then run whatever was asked.
#
# Everything here is fixed rather than generated: the realms, the
# passwords, the key version numbers. A master key is *derived* from its
# realm and master password -- string_to_key salted with K/M@REALM -- so
# a fixed password means a reproducible master key and therefore
# reproducible stored keys. A fixture that randomised any of this could
# not be diffed against anything.
#
# There are four realms and one krb5kdc serving all of them on one port,
# which is what -r does. They are:
#
#   KDIAMOND.TEST              the realm the Go KDC also serves
#   FOREIGN.TEST               a direct trust, for the one-hop case
#   OTHER.KDIAMOND.TEST        the middle of a three-realm path
#   SUB.OTHER.KDIAMOND.TEST    the far end of that path
#
# The last two are named *below* KDIAMOND.TEST deliberately. Without a
# [capaths] entry a client walks the realm hierarchy, which is a
# convention about names, so a path through three realms exists only if
# the names say it does. This implementation has no [capaths] yet, so
# the fixture has to be a hierarchy for the three-realm case to work at
# all -- and that limitation is the point of writing it down here.
set -eu

: "${KRB5_REALM:?}"
: "${KRB5_MASTER_PASSWORD:?}"
: "${KRB5_USER:?}"
: "${KRB5_USER_PASSWORD:?}"
: "${KRB5_TGT_PASSWORD:?}"
: "${KRB5_SERVICE:?}"
: "${KRB5_SERVICE_PASSWORD:?}"
: "${KRB5_PEER:?}"
: "${KRB5_PEER_PASSWORD:?}"
: "${KRB5_FOREIGN_REALM:?}"
: "${KRB5_FOREIGN_MASTER_PASSWORD:?}"
: "${KRB5_REMOTE:?}"
: "${KRB5_REMOTE_PASSWORD:?}"
: "${KRB5_FOREIGN_TGT_PASSWORD:?}"
: "${KRB5_INTERREALM_PASSWORD:?}"
: "${KRB5_MID_REALM:?}"
: "${KRB5_MID_MASTER_PASSWORD:?}"
: "${KRB5_MID_TGT_PASSWORD:?}"
: "${KRB5_MID_LOCAL_PASSWORD:?}"
: "${KRB5_FAR_REALM:?}"
: "${KRB5_FAR_MASTER_PASSWORD:?}"
: "${KRB5_FAR_TGT_PASSWORD:?}"
: "${KRB5_FAR_USER:?}"
: "${KRB5_FAR_PASSWORD:?}"
: "${KRB5_FAR_MID_PASSWORD:?}"
: "${KRB5_KDC_PORT:?}"
: "${KRB5_TESTDIR:?}"

# The image sets these too, so that `podman exec' inherits them; they
# are defaulted here as well so the script still works if it is run by
# hand.
export KRB5_CONFIG="${KRB5_CONFIG:-$KRB5_TESTDIR/krb5.conf}"
export KRB5_KDC_PROFILE="${KRB5_KDC_PROFILE:-$KRB5_TESTDIR/kdc.conf}"
export KRB5CCNAME="${KRB5CCNAME:-$KRB5_TESTDIR/ccache}"
export KRB5_KTNAME="${KRB5_KTNAME:-$KRB5_TESTDIR/keytab}"
export KRB5RCACHEDIR="${KRB5RCACHEDIR:-$KRB5_TESTDIR}"

# LC_ALL and TZ decide how klist renders a time: it formats through
# localtime_r with a %c format, so without both pinned the output
# depends on the host's locale and timezone.
export LC_ALL=C
export TZ=UTC

rm -rf "$KRB5_TESTDIR"
mkdir -p "$KRB5_TESTDIR"

# The realms, each with the short name used for its database module and
# stash file. The order is the order they are created in and nothing
# depends on it.
REALMS="$KRB5_REALM:db $KRB5_FOREIGN_REALM:fdb \
$KRB5_MID_REALM:mdb $KRB5_FAR_REALM:sdb"

# supported_enctypes is set explicitly, and the order matters.
#
# The default is only the two RFC 3962 types
# (KRB5_DEFAULT_SUPPORTED_ENCTYPES, include/osconf.hin:109-111), so a
# realm left at the default has no aes-sha2 keys and the differential
# comparison could never reach that family. Listing all four puts it in
# range.
#
# The order decides which key seals a ticket: the KDC takes the *first*
# key of a principal's highest key version, whatever its enctype
# (get_first_current_key, kdc/kdc_util.c:461-473). So this list has to
# match the order internal/crypto reports from Supported(), or the two
# implementations seal with different enctypes and the diff is about
# the fixture rather than the code.
ETYPES="aes256-cts-hmac-sha384-192:normal \
aes128-cts-hmac-sha256-128:normal \
aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal"

# client_realms writes a krb5.conf [realms] entry per realm. Every one
# of them is the same KDC, because one krb5kdc serves them all.
client_realms() {
	for pair in $REALMS; do
		printf '\t%s = {\n' "${pair%:*}"
		printf '\t\tkdc = 127.0.0.1:%s\n\t}\n\n' \
			"$KRB5_KDC_PORT"
	done
}

# kdc_realms writes a kdc.conf [realms] entry per realm, each with its
# own database and stash: four realms in one process still means four
# separate databases and four master keys.
#
# kdc_listen = "" disables UDP listening outright and kdc_tcp_listen
# keeps TCP. The older kdc_ports/kdc_tcp_ports names are only consulted
# when these are absent, so setting these is enough.
#
# Each master key is left at the default, aes256-cts-hmac-sha1-96
# (DEFAULT_KDC_ENCTYPE, osconf.hin:90), because it is derived from the
# master password and the Go side has to derive the same one.
kdc_realms() {
	for pair in $REALMS; do
		printf '\t%s = {\n' "${pair%:*}"
		printf '\t\tsupported_enctypes = %s\n' "$ETYPES"
		printf '\t\tdatabase_module = %s\n' "${pair#*:}"
		printf '\t\tkey_stash_file = %s/%s.stash\n' \
			"$KRB5_TESTDIR" "${pair#*:}"
		printf '\t\tacl_file = %s/acl\n' "$KRB5_TESTDIR"
		printf '\t\tdict_file = %s/dictfile\n' "$KRB5_TESTDIR"
		printf '\t\tkdc_listen = ""\n'
		printf '\t\tkdc_tcp_listen = %s\n\t}\n\n' \
			"$KRB5_KDC_PORT"
	done
}

# db_modules writes the [dbmodules] entries the stanzas above name.
db_modules() {
	for pair in $REALMS; do
		printf '\t%s = {\n' "${pair#*:}"
		printf '\t\tdb_library = db2\n'
		printf '\t\tdatabase_name = %s/%s\n\t}\n\n' \
			"$KRB5_TESTDIR" "${pair#*:}"
	done
}

# dns_lookup_kdc, dns_canonicalize_hostname, rdns and qualify_shortname
# are all off so that no name resolution reaches a transcript.
#
# udp_preference_limit = 1 puts TCP first. It is not sufficient on its
# own -- both protocols are tried if the first attempt fails -- which
# is why kdc_listen above removes UDP from the server as well.
#
# The [capaths] entry names the one path that is not hierarchical:
# KDIAMOND.TEST and FOREIGN.TEST share only the "TEST" suffix, so
# without it a client would look for krbtgt/TEST and fail. The three
# realms of the longer path need no entry and deliberately do not get
# one -- a capaths entry *replaces* the hierarchical walk, and the
# hierarchical walk is the only thing the Go side implements.
#
# preauth2.c:133 auto-registers pkinit as a *dynamic* clpreauth module
# whether or not it was built, so a build without it still tries to
# load the .so and writes "Error loading plugin module pkinit" into
# every trace. --disable-pkinit cannot prevent that; only disabling the
# module here can, and a clean trace is worth having in something whose
# whole purpose is diffing transcripts.
{
	cat <<EOF
[libdefaults]
	default_realm = $KRB5_REALM
	dns_lookup_kdc = false
	dns_lookup_realm = false
	dns_canonicalize_hostname = false
	rdns = false
	qualify_shortname = ""
	udp_preference_limit = 1
	noaddresses = true

[realms]
EOF
	client_realms
	cat <<EOF
[capaths]
	$KRB5_REALM = {
		$KRB5_FOREIGN_REALM = .
	}
	$KRB5_FOREIGN_REALM = {
		$KRB5_REALM = .
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
EOF
} >"$KRB5_CONFIG"

# The [domain_realm] stanza below is in kdc.conf and deliberately not
# in krb5.conf, and that choice is what decides whether the host-based
# referral is exercised at all. The KDC's profile is kdc.conf
# prepended to the usual file list (add_kdc_config_file,
# lib/krb5/os/init_os_ctx.c:339-366), so either file would reach the
# KDC -- but a mapping in krb5.conf would also let the *client*
# resolve the host's realm itself, and the client would then ask the
# right realm directly and never need a referral. Upstream's own
# referral test puts it in kdc_conf for that reason
# (tests/t_referral.py:5-11).
{
	cat <<EOF
[kdcdefaults]
	kdc_listen = ""
	kdc_tcp_listen = $KRB5_KDC_PORT

[domain_realm]
	.$KRB5_REFERRAL_DOMAIN = $KRB5_FOREIGN_REALM

[realms]
EOF
	kdc_realms
	printf '[dbmodules]\n'
	db_modules
	cat <<EOF
[logging]
	kdc = FILE:$KRB5_TESTDIR/kdc.log
	default = FILE:$KRB5_TESTDIR/others.log
EOF
} >"$KRB5_KDC_PROFILE"

printf '%s/admin@%s *e\n' "$KRB5_USER" "$KRB5_REALM" >"$KRB5_TESTDIR/acl"
printf 'weak_password\n' >"$KRB5_TESTDIR/dictfile"

# kadm runs one kadmin.local command against a named realm's database.
kadm() {
	realm="$1"
	shift
	kadmin.local -r "$realm" -q "$*" >/dev/null
}

# make_realm creates a realm's database and resets its own krbtgt key
# from a password.
#
# The krbtgt key kdb5_util create writes is a *random* key
# (tgt_keysalt_iterate, kadmin/dbutil/kdb5_create.c:441-460) -- seeded
# from the master password, but still the output of the PRNG, so it is
# not something an independent implementation can reproduce. Setting it
# from a password makes it string_to_key over the krbtgt's own default
# salt, which is derivable from the realm alone. That is what lets the
# harness decrypt the C KDC's *ticket* and compare the EncTicketPart,
# where most of what an exchange decides actually lives.
#
# cpw bumps the key version, so every krbtgt ends up at kvno 2 while the
# user principals stay at 1. That is deterministic and left visible
# rather than papered over.
make_realm() {
	kdb5_util -r "$1" create -s -P "$2" >/dev/null
	kadm "$1" "cpw -pw $3 krbtgt/$1@$1"
}

# trust adds an inter-realm principal to one database.
#
# The principal is krbtgt/<granting realm>@<holding realm>, and both
# ends of a trust hold the same one with the same key: the holder so it
# can *issue* a cross-realm ticket-granting ticket, the grantor so it
# can verify one. Its default salt is its realm plus its name
# components, which both sides spell identically, so one password gives
# one key.
trust() {
	kadm "$1" "addprinc -pw $4 -kvno 1 krbtgt/$3@$2"
}

# The realm the Go KDC also serves, and everything in it.
make_realm "$KRB5_REALM" "$KRB5_MASTER_PASSWORD" \
	"$KRB5_TGT_PASSWORD"

# -kvno 1 pins the key version number, which would otherwise be a
# moving part in every reply that carries one. The principal is created
# without +requires_preauth: that is the single-round-trip, padata-free
# exchange, which is both the easiest case to get right and the most
# deterministic one to compare.
kadm "$KRB5_REALM" "addprinc -pw $KRB5_USER_PASSWORD -kvno 1 \
	$KRB5_USER@$KRB5_REALM"

# A second principal that does demand pre-authentication, so the
# PA-ENC-TIMESTAMP path has something to exercise without disturbing
# the simple case above.
kadm "$KRB5_REALM" "addprinc -pw $KRB5_USER_PASSWORD -kvno 1 \
	+requires_preauth preauth@$KRB5_REALM"

# A service for the TGS exchange to ask for a ticket to. It is created
# from a password rather than with a random key for the same reason
# every krbtgt is reset: the harness has to decrypt the ticket the KDC
# issues, and a key derived from a password is one it can compute.
#
# -kvno 1 pins the version, and no +requires_preauth: a service ticket
# inherits PRE-AUTHENT from the TGT rather than establishing it, so
# requiring it here would only test the refusal path.
kadm "$KRB5_REALM" "addprinc -pw $KRB5_SERVICE_PASSWORD -kvno 1 \
	$KRB5_SERVICE@$KRB5_REALM"

# A user-to-user peer: someone with a password and no keytab, which is
# the whole reason the mechanism exists. -allow_svr sets DISALLOW_SVR,
# so an ordinary TGS-REQ naming this principal is refused with
# KRB5KDC_ERR_MUST_USE_USER2USER and only a request carrying this
# principal's own TGT as its second ticket can reach it
# (check_tgs_svc_deny_all, kdc/tgs_policy.c:152-156).
#
# The password is fixed like every other, so the harness can derive the
# key and obtain a TGT for this principal the way its owner would.
kadm "$KRB5_REALM" "addprinc -pw $KRB5_PEER_PASSWORD -kvno 1 \
	-allow_svr $KRB5_PEER@$KRB5_REALM"

# The one-hop trust, FOREIGN.TEST to here. Each master password differs
# from every other: sharing one would make a bug that confused two
# realms' master keys invisible.
make_realm "$KRB5_FOREIGN_REALM" \
	"$KRB5_FOREIGN_MASTER_PASSWORD" "$KRB5_FOREIGN_TGT_PASSWORD"
kadm "$KRB5_FOREIGN_REALM" \
	"addprinc -pw $KRB5_REMOTE_PASSWORD -kvno 1 \
	$KRB5_REMOTE@$KRB5_FOREIGN_REALM"
trust "$KRB5_FOREIGN_REALM" "$KRB5_FOREIGN_REALM" "$KRB5_REALM" \
	"$KRB5_INTERREALM_PASSWORD"
trust "$KRB5_REALM" "$KRB5_FOREIGN_REALM" "$KRB5_REALM" \
	"$KRB5_INTERREALM_PASSWORD"

# The *other* direction of the same trust, which the host-based
# referral needs and nothing before it did. A cross-realm
# ticket-granting ticket that takes a client from here to there is
# krbtgt/FOREIGN.TEST@KDIAMOND.TEST, held at both ends -- a separate
# principal from the krbtgt/KDIAMOND.TEST@FOREIGN.TEST above, which
# is the trust in the direction every earlier case used. Its own
# password again, so that a bug confusing the two directions cannot
# hide.
trust "$KRB5_REALM" "$KRB5_REALM" "$KRB5_FOREIGN_REALM" \
	"$KRB5_LOCAL_FOREIGN_PASSWORD"
trust "$KRB5_FOREIGN_REALM" "$KRB5_REALM" "$KRB5_FOREIGN_REALM" \
	"$KRB5_LOCAL_FOREIGN_PASSWORD"

# A host-based service that exists *only* in the foreign realm, in a
# domain [domain_realm] maps there. Asked for it, this realm has
# nothing and must say which realm to ask instead; the client then
# finds it over there. It mirrors upstream's own referral fixture,
# which creates a/x.d in REFREALM alone (tests/t_referral.py:11).
kadm "$KRB5_FOREIGN_REALM" \
	"addprinc -pw $KRB5_REFERRAL_SVC_PASSWORD -kvno 1 \
	$KRB5_REFERRAL_SERVICE@$KRB5_FOREIGN_REALM"

# The three-realm path: a client in the far realm reaches a service here
# through the middle one, and the middle one is what has to appear in
# the issued ticket's transited field. With a single boundary the field
# stays empty and nothing about it is exercised.
make_realm "$KRB5_MID_REALM" "$KRB5_MID_MASTER_PASSWORD" \
	"$KRB5_MID_TGT_PASSWORD"
make_realm "$KRB5_FAR_REALM" "$KRB5_FAR_MASTER_PASSWORD" \
	"$KRB5_FAR_TGT_PASSWORD"
kadm "$KRB5_FAR_REALM" "addprinc -pw $KRB5_FAR_PASSWORD -kvno 1 \
	$KRB5_FAR_USER@$KRB5_FAR_REALM"

# Far trusts middle, and middle trusts here. Each trust is held at both
# ends, which is four entries for two trusts.
trust "$KRB5_FAR_REALM" "$KRB5_FAR_REALM" "$KRB5_MID_REALM" \
	"$KRB5_FAR_MID_PASSWORD"
trust "$KRB5_MID_REALM" "$KRB5_FAR_REALM" "$KRB5_MID_REALM" \
	"$KRB5_FAR_MID_PASSWORD"
trust "$KRB5_MID_REALM" "$KRB5_MID_REALM" "$KRB5_REALM" \
	"$KRB5_MID_LOCAL_PASSWORD"
trust "$KRB5_REALM" "$KRB5_MID_REALM" "$KRB5_REALM" \
	"$KRB5_MID_LOCAL_PASSWORD"

exec "$@"
