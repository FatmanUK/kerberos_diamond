package kdc

import (
	"encoding/asn1"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// The addresses a TGS-issued ticket carries, from
// do_tgs_req.c:1012-1027.
//
// Three cases, and only the middle one does anything. A renewal or a
// validation copies the presented ticket's enc-part wholesale, so its
// addresses come along with it. An ordinary request takes the
// presented ticket's addresses too, and says nothing about them in
// the reply, because the client already knows what it asked for.
//
// A forwarded or proxied ticket is the exception, and it is the whole
// point of those two options: the ticket is being issued for use from
// somewhere else, so the addresses come from the *request* rather
// than from the ticket being presented -- and the reply repeats them,
// so the client can see which addresses it actually got.

// ticketAddresses is the caddr field of the ticket being issued.
func ticketAddresses(s *tgsState) asn1.RawValue {
	if forwardedOrProxy(s) {
		return s.req.Body.Addresses
	}
	return s.header.CAddr
}

// replyAddresses is the caddr field of the reply's sealed half, which
// is absent except for a forwarded or proxied ticket.
func replyAddresses(s *tgsState) asn1.RawValue {
	if !forwardedOrProxy(s) {
		return asn1.RawValue{}
	}
	return wire.ReplyAddresses(s.req.Body.Addresses)
}

// forwardedOrProxy reports whether this request is the address-moving
// kind. Validation and renewal are excluded because upstream tests
// them first and never reaches the forwarded branch for them, so a
// request combining the two gets the reissue behaviour.
func forwardedOrProxy(s *tgsState) bool {
	opts := s.req.Body.Options
	if opts&(wire.OptValidate|wire.OptRenew) != 0 {
		return false
	}
	return opts&(wire.OptForwarded|wire.OptProxy) != 0
}
