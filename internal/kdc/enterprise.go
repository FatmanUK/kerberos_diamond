package kdc

import (
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// enterpriseName splits an NT-ENTERPRISE client name into the
// principal and realm it carries.
//
// An enterprise name is a user principal name -- `user@REALM' -- in
// **one component**, with the whole string including the at sign
// inside it, and the message's own realm field saying something else
// entirely. So it is not a Kerberos name that happens to look like
// one; it is a different naming scheme carried in the same field,
// which is why upstream treats the type as a flag rather than a hint
// (do_as_req.c:574-576).
//
// The split is at the **last** at sign, because a realm cannot
// contain one and a user name can. Upstream reaches the same place
// through krb5_parse_name on the unparsed component
// (upn_to_principal, princ_comp.c:60-80).
func enterpriseName(n wire.PrincipalName) (string, string, bool) {
	if n.Type != wire.NTEnterprise ||
		len(n.Components) != 1 {
		return "", "", false
	}
	at := strings.LastIndexByte(n.Components[0], '@')
	if at <= 0 || at == len(n.Components[0])-1 {
		return "", "", false
	}
	c := n.Components[0]
	return c[:at], c[at+1:], true
}

// enterpriseClient resolves an NT-ENTERPRISE client name, and is
// where this KDC's AS exchange learns to refer a client to another
// realm.
//
// Three outcomes:
//
//   - not an enterprise name: nothing happens and the ordinary
//     lookup follows.
//   - an enterprise name in **this** realm: the embedded name is
//     looked up as though it had been sent as an ordinary
//     NT-PRINCIPAL, so `kinit -E user@THIS.REALM' logs in.
//   - an enterprise name in **another** realm: KDC_ERR_WRONG_REALM,
//     carrying a cname whose realm is the one named. That is the
//     referral, and the realm is the part that matters -- a client
//     checks it differs from its own before believing the error
//     (is_referral, get_in_tkt.c:1659-1667) and then restarts there
//     (:1745-1759).
//
// **Where this sits relative to upstream is worth being exact
// about.** The KDC proper does not resolve an enterprise name at all:
// it sets KRB5_KDB_FLAG_REFERRAL_OK and hands the whole name to the
// database (do_as_req.c:573-578), and whether anything comes back is
// the database module's business. Of the modules upstream ships,
// **only the test one honours that flag** (kdb_test.c:411-419 is the
// sole reader of it); db2 and ldap ignore it, so a stock krb5kdc over
// db2 answers C_PRINCIPAL_UNKNOWN for every enterprise name and there
// is no oracle for any of this.
//
// This project *is* the database module, so the choice lands here.
// Resolving the embedded realm is what a Windows KDC does and what
// [MS-SFU] 3.1.5.1.1.1 describes, and it is the only answer that
// makes the name type mean anything.
func (k *KDC) enterpriseClient(
	s *asState,
) (int32, string) {
	name, realm, ok := enterpriseName(s.cname)
	if !ok {
		return 0, ""
	}
	if realm == k.Realm {
		// Rewritten to the ordinary form so that every later
		// step -- the lookup, the salt, the reply -- sees a
		// name it understands. The *reply* still carries the
		// enterprise name unless canonicalisation was asked
		// for, which canonNames handles.
		s.cname = wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{name},
		}
		return 0, ""
	}
	s.referral = &wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: []string{name},
	}
	s.referralRealm = realm
	return wire.ErrCodeWrongRealm, "REFERRAL"
}
