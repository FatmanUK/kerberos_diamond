package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// anonymousName is the well-known client name an anonymous request
// must use (KRB5_ANONYMOUS_PRINCSTR and KRB5_WELLKNOWN_NAMESTR,
// krb5.hin).
var anonymousName = []string{"WELLKNOWN", "ANONYMOUS"}

// refuseAnonymous answers KDC_OPT_REQUEST_ANONYMOUS, and the answer
// is a refusal.
//
// **This replaces a silent downgrade, which is the part worth
// recording.** The option was in optsCommonFlagsMask, so it reached
// the ticket's flags, and TKT_FLG_ANONYMOUS was then cleared
// unconditionally -- so a client that asked for an anonymous ticket
// got an ordinary one naming it, and was told nothing. That is
// precisely the failure mode BOOTSTRAP.md section 3.3 already refuses
// three times over, for S4U2Proxy, for DISABLE_TRANSITED_CHECK and
// for hide-client-names: a request this KDC cannot honour is refused
// rather than quietly answered with something else.
//
// Upstream's own handling is two conditions and both are copied
// (do_as_req.c:716-735):
//
//   - the client must be WELLKNOWN/ANONYMOUS, in any realm, or the
//     answer is KDC_ERR_BADOPTION with status
//     VALIDATE_ANONYMOUS_PRINCIPAL. A client asking for anonymity
//     under its own name has asked for a contradiction.
//   - and the request is then forced to require
//     pre-authentication, which in practice means **anonymous
//     PKINIT**: there is no other pre-authentication mechanism a
//     client with no key can complete.
//
// PKINIT is a declared non-goal, and the reason is not reluctance:
// upstream's only backend is OpenSSL, so under section 3.3's rule
// there is no oracle to compare against at all and PKINIT would be
// the one feature in this project anchored by nothing but a round
// trip. So an anonymous request cannot be honoured here, and saying
// so is the whole of this function.
func (k *KDC) refuseAnonymous(s *asState) (int32, string) {
	if s.req.Body.Options&wire.OptRequestAnon == 0 {
		return 0, ""
	}
	// The well-known name is checked first, and in upstream's
	// order: a request that is malformed in this way is told so
	// rather than being told the feature is unavailable, because
	// the two are different problems and only one of them is this
	// KDC's choice.
	if !isAnonymousName(s.cname) {
		return wire.ErrCodeBadOption,
			"VALIDATE_ANONYMOUS_PRINCIPAL"
	}
	return wire.ErrCodeBadOption, "ANONYMOUS NOT SUPPORTED"
}

// isAnonymousName is krb5_principal_compare_any_realm against the
// anonymous principal: the components must match and the realm is not
// looked at, because an anonymous client's realm is whatever it came
// from.
func isAnonymousName(n wire.PrincipalName) bool {
	if len(n.Components) != len(anonymousName) {
		return false
	}
	for i := range anonymousName {
		if n.Components[i] != anonymousName[i] {
			return false
		}
	}
	return true
}
