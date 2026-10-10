package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// tgsAssemble builds the TGS-REP, from do_tgs_req.c:1050-1120.
//
// The order is forced by FAST and would otherwise be arbitrary. The
// ticket comes first because the tunnel's finished field checksums
// it; the tunnel comes next because it both moves the reply's padata
// inside and decides the key the enc-part is sealed with; the
// enc-part comes last for that reason.
func (k *KDC) tgsAssemble(s *tgsState) (*wire.TGSRep, error) {
	tkt, err := k.tgsTicket(s)
	if err != nil {
		return nil, err
	}
	// A TGS-REP carries almost no cleartext padata of its own.
	// return_padata's etype-info is an AS-only thing -- it
	// describes the client's long-term key, which a TGS exchange
	// never touches -- so what appears here is the FAST container
	// and, for an S4U2Self request, the PA-S4U-X509-USER echo.
	//
	// That echo really is cleartext and not encrypted padata:
	// kdc_make_s4u2self_rep adds it to reply->padata
	// (kdc_util.c:1489-1491). See s4uSelfRep for why.
	pa, err := k.s4uSelfRep(s)
	if err != nil {
		return nil, err
	}
	rep := &wire.TGSRep{
		CRealm:  s.ticketCRealm(),
		CName:   s.ticketCName(),
		Ticket:  *tkt,
		EncPart: wire.EncryptedData{},
	}
	if pa != nil {
		rep.PAData = append(rep.PAData, *pa)
	}
	if err := k.wrapTGSReply(s, rep); err != nil {
		return nil, err
	}
	enc, err := k.tgsEncPart(s)
	if err != nil {
		return nil, err
	}
	rep.EncPart = *enc
	return rep, nil
}

// wrapTGSReply puts the reply in its tunnel, if the request came
// through one, and replaces the reply key with the strengthened one.
//
// It is a no-op for an unarmored request, which is the shape of
// upstream's `if (!state->armor_key) return 0;` at fast_util.c:291.
func (k *KDC) wrapTGSReply(
	s *tgsState,
	rep *wire.TGSRep,
) error {
	if s.fast == nil {
		return nil
	}
	der, err := wire.MarshalTicket(rep.Ticket)
	if err != nil {
		return err
	}
	key, err := k.fastReply(s.fast, rep, der, s.req.Body.Nonce,
		s.replyKey, s.replyEType)
	if err != nil {
		return err
	}
	s.replyKey = key
	return nil
}

// tgsTicket seals the new ticket under the service's key.
//
// The client named in it is the one from the presented ticket, not
// anything in the request: a TGS-REQ has no cname field, because the
// ticket is what says who the client is. For a renewal or a
// validation the *server* comes from the presented ticket as well
// (do_tgs_req.c:1012-1016).
func (k *KDC) tgsTicket(s *tgsState) (*wire.Ticket, error) {
	part := s.encTicketPart()
	// The PAC goes on before the encoding, because attaching one
	// *encodes the ticket* to checksum it -- and it goes on here
	// rather than in setAuthData because it is prepended to
	// whatever that decided.
	if err := k.tgsPAC(s, &part); err != nil {
		return nil, err
	}
	plain, err := wire.MarshalEncTicketPart(part)
	if err != nil {
		return nil, err
	}
	key, etype, kvno := s.sealingKey()
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(key, plain, crypto.UsageKDCRepTicket)
	if err != nil {
		return nil, err
	}
	return &wire.Ticket{
		Realm: k.Realm,
		SName: s.issuedFor(),
		EncPart: wire.EncryptedData{
			EType:  int32(etype),
			KVNO:   kvno,
			Cipher: ct,
		},
	}, nil
}

// sealingKey is the key the new ticket is sealed with, and the
// enctype and key version that name it on the wire
// (do_tgs_req.c:996-1010,1056-1061).
//
// Ordinarily that is the service's first current long-term key.
// User-to-user replaces it entirely, for the reason u2u.go gives.
//
// **The test is on the option and not on the second ticket being
// present**, which it used to be and could not stay: S4U2Proxy also
// brings a second ticket, and sealing its reply with that ticket's
// session key would produce a ticket the target service cannot open
// at all. Nothing caught it until S4U2Proxy landed, because
// user-to-user was the only thing that set s.stkt.
func (s *tgsState) sealingKey() ([]byte, crypto.EncType, int32) {
	if s.req.Body.Options&wire.OptEncTktInSKey != 0 &&
		s.stkt != nil {
		return u2uSealingKey(s)
	}
	return s.serverKey, s.serverEType, s.serverKVNO
}

// encTicketPart is what goes inside the new ticket.
func (s *tgsState) encTicketPart() wire.EncTicketPart {
	return wire.EncTicketPart{
		Flags:  s.flags,
		Key:    s.session,
		CRealm: s.ticketCRealm(),
		CName:  s.ticketCName(),
		// buildTransited decided this: the presented ticket's
		// path, with this realm's predecessor added when the
		// request crossed a second boundary.
		Transited: s.transited,
		// The addresses pass through as opaque DER because
		// nothing here reads them; which ticket's they are is
		// ticketAddresses' business.
		CAddr:     ticketAddresses(s),
		AuthTime:  unstamp(s.authTime),
		StartTime: optStamp(s.start),
		EndTime:   unstamp(s.end),
		RenewTill: optStamp(s.renew),

		// The request's own authorization data and the
		// presented ticket's, filtered and in that order.
		// Decided by ticketAuthData before the reply is
		// built, because an AD-MANDATORY-FOR-KDC element
		// refuses the request rather than changing the
		// ticket.
		AuthorizationData: s.authData,
	}
}

// issuedFor is the server the new ticket names.
//
// For a renewal or a validation it is the presented ticket's server;
// checkNonTGT has already refused the case where that disagrees with
// the request, so the two are the same name by the time this runs and
// the distinction is documentation rather than logic.
func (s *tgsState) issuedFor() wire.PrincipalName {
	opts := s.req.Body.Options
	if opts&(wire.OptValidate|wire.OptRenew) != 0 {
		return s.headerSrv
	}
	// A referral names what was *found* rather than what was
	// asked for, and only a referral does. Upstream uses the
	// request's name otherwise even though it has the database
	// entry's in hand (do_tgs_req.c:1029), which matters because
	// the two can differ in their name type and the client
	// compares what it sent.
	if s.referral {
		return s.serverName
	}
	return *s.req.Body.SName
}

// tgsEncPart seals the reply's half under the reply key.
//
// key-expiration is *always* absent here. do_tgs_req.c:1081 sets
// reply_encpart.key_exp to 0 unconditionally, where the AS path
// computes it from the client's expiry -- the field describes a
// password, and a TGS exchange never saw one.
func (k *KDC) tgsEncPart(s *tgsState) (*wire.EncryptedData, error) {
	encPA, err := k.tgsEncPAData(s)
	if err != nil {
		return nil, err
	}
	plain, err := wire.MarshalEncTGSRepPart(wire.EncKDCRepPart{
		Key:       s.session,
		EncPAData: encPA,
		LastReq:   []wire.LastReqEntry{{Type: 0}},
		Nonce:     s.req.Body.Nonce,
		Flags:     s.flags,
		AuthTime:  unstamp(s.authTime),
		StartTime: optStamp(s.start),
		EndTime:   unstamp(s.end),
		RenewTill: optStamp(s.renew),
		SRealm:    k.Realm,
		SName:     s.issuedFor(),
		CAddr:     replyAddresses(s),
	})
	if err != nil {
		return nil, err
	}
	p, err := crypto.Profile(s.replyEType)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(s.replyKey, plain, s.replyUsage)
	if err != nil {
		return nil, err
	}
	return &wire.EncryptedData{
		EType:  int32(s.replyEType),
		Cipher: ct,
	}, nil
}

// tgsEncPAData is the RFC 6806 reply checksum, which applies to a
// TGS-REP exactly as to an AS-REP: return_enc_padata is called from
// both paths (do_tgs_req.c:1099) and the client's check keys off the
// ticket's ENC-PA-REP flag, which a TGS ticket carries too.
func (k *KDC) tgsEncPAData(s *tgsState) ([]wire.PAData, error) {
	out, err := k.tgsNegotiationPAData(s)
	if err != nil {
		return nil, err
	}
	// And the PA-PAC-OPTIONS echo, which is not conditional on
	// the checksum having been asked for -- see encPAData. It
	// matters more here than on the AS path: RBCD is a TGS
	// feature, so a client announcing it is announcing it on a
	// TGS request.
	if echo := pacOptionsEcho(s.req.PAData); echo != nil {
		out = append(out, *echo)
	}
	return out, nil
}

// tgsNegotiationPAData is the reply checksum and the FAST
// advertisement, both gated on the client having asked for the
// checksum.
func (k *KDC) tgsNegotiationPAData(
	s *tgsState,
) ([]wire.PAData, error) {
	if findPAData(s.req.PAData, wire.PAReqEncPARep) == nil {
		return nil, nil
	}
	p, err := crypto.Profile(s.replyEType)
	if err != nil {
		return nil, err
	}
	sum, err := p.Checksum(s.replyKey, s.raw, crypto.UsageASReq)
	if err != nil {
		return nil, err
	}
	der, err := wire.MarshalChecksum(wire.Checksum{
		Type:     int32(p.RequiredCksum),
		Checksum: sum,
	})
	if err != nil {
		return nil, err
	}
	// The empty PA-FX-FAST goes here too, after the checksum.
	// return_enc_padata is one function called from both
	// exchanges (do_tgs_req.c:1098, do_as_req.c:315), so a TGS
	// reply advertises FAST exactly as an AS reply does -- see
	// encPAData for what a client does with it.
	return []wire.PAData{
		{Type: wire.PAReqEncPARep, Value: der},
		{Type: wire.PAFXFast},
	}, nil
}

// ticketCName and ticketCRealm are the client the issued ticket
// names, which is the presented ticket's client for an ordinary
// request and the **impersonated** principal for a final S4U request
// (do_tgs_req.c:757-759).
//
// "Final" is the distinction: an S4U request that this realm answers
// with a referral names the impersonator, because the ticket it
// issues is a cross-realm TGT for the server to spend elsewhere, not
// the service ticket the server asked for.
func (s *tgsState) ticketCName() wire.PrincipalName {
	if s.referral {
		return s.header.CName
	}
	if s.s4u != nil {
		return *s.s4u.UserID.UserName
	}
	// For S4U2Proxy the impersonated client is the **evidence
	// ticket's** client: the user who really did authenticate to
	// the service presenting it (do_tgs_req.c:747-751).
	if s.isProxy() && s.stkt != nil {
		return s.stkt.CName
	}
	return s.header.CName
}

func (s *tgsState) ticketCRealm() string {
	if s.referral {
		return s.header.CRealm
	}
	if s.s4u != nil {
		return s.s4u.UserID.UserRealm
	}
	if s.isProxy() && s.stkt != nil {
		return s.stkt.CRealm
	}
	return s.header.CRealm
}

// isProxy reports a constrained-delegation request.
func (s *tgsState) isProxy() bool {
	return s.req.Body.Options&wire.OptCNameInAddlTkt != 0
}
