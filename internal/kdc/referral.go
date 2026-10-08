package kdc

import (
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// referralTGSName names the cross-realm ticket-granting service
// through which a host-based service's own realm is reached
// (find_referral_tgs, kdc/do_tgs_req.c:482-523).
//
// A client asks this realm for host/www.elsewhere.test; this realm
// has never heard of it; and rather than refusing, the KDC looks the
// host up in its host-to-realm map and answers with
// krbtgt/ELSEWHERE.TEST@<here> so the client can ask again over
// there. It is the only referral that answers a request for an
// ordinary service rather than for a trust, which is why it needs a
// map at all: the alternate-TGS search can read the realm it is
// heading for out of the name it was given, and this cannot.
//
// The name is built with the *request's* realm, and the mapped realm
// as the instance (krb5_build_principal, :517-519). That makes it an
// ordinary inter-realm krbtgt, so the key that seals it is the trust
// and nothing else about the issuing path changes.
func (k *KDC) referralTGSName(
	s *tgsState,
) (wire.PrincipalName, bool) {
	none := wire.PrincipalName{}
	if !k.wantsHostReferral(s) {
		return none, false
	}
	// A name with no dot in it is not a fully qualified domain
	// name, and upstream refuses to refer on one (:502-504).
	host := s.req.Body.SName.Components[1]
	if !strings.Contains(host, ".") {
		return none, false
	}
	realm := k.Hosts.Realm(host)
	// No match is the empty realm. And a map pointing back at the
	// realm the request named is no answer either: that one is
	// upstream's own fix for its bug #7483 (:511-515), and
	// without it a client would be told to go and ask the realm
	// it had just asked.
	if realm == "" || realm == s.req.Body.Realm {
		return none, false
	}
	return wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{tgsName, realm},
	}, true
}

// wantsHostReferral is the gate on all of it (is_referral_req,
// do_tgs_req.c:436-481), in upstream's own order.
func (k *KDC) wantsHostReferral(s *tgsState) bool {
	opts := s.req.Body.Options
	// The referral is opt-in by the client. Without canonicalize
	// it is told the service is unknown, which is the truth
	// (:446) -- and this is the first thing in this project to
	// read the option at all.
	if opts&wire.OptCanonicalize == 0 {
		return false
	}
	// User-to-user names a ticket the client already holds, so
	// answering with a different server would answer a different
	// question (:449).
	if opts&wire.OptEncTktInSKey != 0 {
		return false
	}
	// Exactly two components: a service, and the host it runs on
	// (:452).
	name := s.req.Body.SName
	if len(name.Components) != 2 {
		return false
	}
	return k.referrableService(*name)
}

// referrableService reports whether a server name's type and service
// leave it eligible (do_tgs_req.c:455-473).
//
// NT-SRV-HST and NT-SRV-INST always are. NT-UNKNOWN is only when
// host_based_services names the service, because an unknown type says
// nothing about whether the second component is a host. Every other
// type -- NT-PRINCIPAL included -- never is, which is why a request
// for an ordinary two-part principal that does not exist stays simply
// unknown.
//
// no_host_referral then excludes a service whatever its type, and it
// *overrides* host_based_services rather than being weighed against
// it (:468-470).
func (k *KDC) referrableService(name wire.PrincipalName) bool {
	service := name.Components[0]
	switch name.Type {
	case wire.NTSrvHst, wire.NTSrvInst:
	case wire.NTUnknown:
		if !k.HostBasedServices.Matches(service) {
			return false
		}
	default:
		return false
	}
	return !k.NoHostReferral.Matches(service)
}
