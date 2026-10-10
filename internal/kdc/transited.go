package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/transit"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// buildTransited computes the path the issued ticket will carry,
// which upstream does while reading the request rather than while
// answering it (gather_tgs_req_info, do_tgs_req.c:786-802).
//
// The condition for *reusing* the presented ticket's path reads oddly
// until a two-realm hop is worked through. The path is carried across
// unchanged when the realm that issued the presented ticket is the
// client's own: that ticket came from the client's own KDC, so no
// realm has been passed through that the client and server realms do
// not already name between them. Anything else means a third realm is
// in the path and has to be written down, or a service could not tell
// a one-hop ticket from one that crossed somewhere it does not trust.
//
// Note which realm is added: the one that issued the presented
// ticket, because that is the realm the request has just come
// *through*. The two end realms are passed in as well and matter
// without appearing in the output -- a realm that is already one of
// the ends is not recorded, since both ends know it.
func (k *KDC) buildTransited(s *tgsState) (int32, string) {
	s.transited = s.header.Transited
	if !s.isCrossRealm(k.Realm) ||
		s.headerRealm == s.header.CRealm {
		return 0, ""
	}
	if s.header.Transited.Type !=
		wire.TransitedDomainX500Compress {
		return wire.ErrCodeTrTypeNoSupp,
			"VALIDATE_TRANSIT_TYPE"
	}
	out, err := transit.Add(string(s.header.Transited.Contents),
		s.headerRealm, s.header.CRealm, s.req.Body.Realm)
	if err != nil {
		return wire.ErrCodePolicy, "ADD_TO_TRANSITED_LIST"
	}
	s.transited = wire.TransitedEncoding{
		Type:     wire.TransitedDomainX500Compress,
		Contents: []byte(out),
	}
	return 0, ""
}
