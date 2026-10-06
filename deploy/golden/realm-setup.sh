#!/bin/sh
# Create the oracle's realm from nothing, then run whatever was asked.
#
# Everything here is fixed rather than generated: the realm, the
# passwords, the key version numbers. The master key is *derived* from
# the realm and the master password -- string_to_key salted with
# K/M@REALM -- so a fixed password means a reproducible master key and
# therefore reproducible stored keys. A fixture that randomised any of
# this could not be diffed against anything.
set -eu

: "${KRB5_REALM:?}"
: "${KRB5_MASTER_PASSWORD:?}"
: "${KRB5_USER:?}"
: "${KRB5_USER_PASSWORD:?}"
: "${KRB5_TGT_PASSWORD:?}"
: "${KRB5_SERVICE:?}"
: "${KRB5_SERVICE_PASSWORD:?}"
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

# dns_lookup_kdc, dns_canonicalize_hostname, rdns and qualify_shortname
# are all off so that no name resolution reaches a transcript.
#
# udp_preference_limit = 1 puts TCP first. It is not sufficient on its
# own -- both protocols are tried if the first attempt fails -- which
# is why kdc_listen below removes UDP from the server as well.
cat >"$KRB5_CONFIG" <<EOF
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
	$KRB5_REALM = {
		kdc = 127.0.0.1:$KRB5_KDC_PORT
	}

# preauth2.c:133 auto-registers pkinit as a *dynamic* clpreauth module
# whether or not it was built, so a build without it still tries to
# load the .so and writes "Error loading plugin module pkinit" into
# every trace. --disable-pkinit cannot prevent that; only disabling the
# module here can, and a clean trace is worth having in something whose
# whole purpose is diffing transcripts.
[plugins]
	clpreauth = {
		disable = pkinit
	}
EOF

# kdc_listen = "" disables UDP listening outright; kdc_tcp_listen keeps
# TCP. The older kdc_ports/kdc_tcp_ports names are only consulted when
# these are absent, so setting these is enough.
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
#
# The master key is left at the default, aes256-cts-hmac-sha1-96
# (DEFAULT_KDC_ENCTYPE, osconf.hin:90), because it is derived from the
# master password and the Go side has to derive the same one.
cat >"$KRB5_KDC_PROFILE" <<EOF
[kdcdefaults]
	kdc_listen = ""
	kdc_tcp_listen = $KRB5_KDC_PORT

[realms]
	$KRB5_REALM = {
		supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
		database_module = db
		key_stash_file = $KRB5_TESTDIR/stash
		acl_file = $KRB5_TESTDIR/acl
		dict_file = $KRB5_TESTDIR/dictfile
		kdc_listen = ""
		kdc_tcp_listen = $KRB5_KDC_PORT
	}

[dbmodules]
	db = {
		db_library = db2
		database_name = $KRB5_TESTDIR/db
	}

[logging]
	kdc = FILE:$KRB5_TESTDIR/kdc.log
	default = FILE:$KRB5_TESTDIR/others.log
EOF

printf '%s/admin@%s *e\n' "$KRB5_USER" "$KRB5_REALM" >"$KRB5_TESTDIR/acl"
printf 'weak_password\n' >"$KRB5_TESTDIR/dictfile"

kdb5_util create -s -P "$KRB5_MASTER_PASSWORD" >/dev/null

# -kvno 1 pins the key version number, which would otherwise be a
# moving part in every reply that carries one. The principal is created
# without +requires_preauth: that is the single-round-trip, padata-free
# exchange, which is both the easiest case to get right and the most
# deterministic one to compare.
kadmin.local -q "addprinc -pw $KRB5_USER_PASSWORD -kvno 1 \
	$KRB5_USER@$KRB5_REALM" >/dev/null

# A second principal that does demand pre-authentication, so the
# PA-ENC-TIMESTAMP path has something to exercise without disturbing
# the simple case above.
kadmin.local -q "addprinc -pw $KRB5_USER_PASSWORD -kvno 1 \
	+requires_preauth preauth@$KRB5_REALM" >/dev/null

# A service for the TGS exchange to ask for a ticket to. It is created
# from a password rather than with a random key for the same reason
# krbtgt is reset below: the harness has to decrypt the ticket the KDC
# issues, and a key derived from a password is one it can compute.
#
# -kvno 1 pins the version, and no +requires_preauth: a service ticket
# inherits PRE-AUTHENT from the TGT rather than establishing it, so
# requiring it here would only test the refusal path.
kadmin.local -q "addprinc -pw $KRB5_SERVICE_PASSWORD -kvno 1 \
	$KRB5_SERVICE@$KRB5_REALM" >/dev/null

# The krbtgt key kdb5_util create writes is a *random* key
# (tgt_keysalt_iterate, kadmin/dbutil/kdb5_create.c:441-460) -- seeded
# from the master password, but still the output of the PRNG, so it is
# not something an independent implementation can reproduce. Setting it
# from a password makes it string_to_key over the krbtgt's own default
# salt, which is derivable from the realm alone. That is what lets the
# harness decrypt the C KDC's *ticket* and compare the EncTicketPart,
# where most of what the AS exchange decides actually lives.
#
# cpw bumps the key version, so krbtgt ends up at kvno 2 while the user
# principals stay at 1. That is deterministic and left visible rather
# than papered over.
kadmin.local -q "cpw -pw $KRB5_TGT_PASSWORD \
	krbtgt/$KRB5_REALM@$KRB5_REALM" >/dev/null

exec "$@"
