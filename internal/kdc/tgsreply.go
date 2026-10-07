package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
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
	// A TGS-REP carries no cleartext padata of its own.
	// return_padata's etype-info is an AS-only thing -- it
	// describes the client's long-term key, which a TGS exchange
	// never touches -- so the only thing that ever appears here
	// is the FAST container.
	rep := &wire.TGSRep{
		CRealm:  s.header.CRealm,
		CName:   s.header.CName,
		Ticket:  *tkt,
		EncPart: wire.EncryptedData{},
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
	plain, err := wire.MarshalEncTicketPart(s.encTicketPart())
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
func (s *tgsState) sealingKey() ([]byte, crypto.EncType, int32) {
	if s.stkt != nil {
		return u2uSealingKey(s)
	}
	return s.serverKey, s.serverEType, s.serverKVNO
}

// encTicketPart is what goes inside the new ticket.
func (s *tgsState) encTicketPart() wire.EncTicketPart {
	return wire.EncTicketPart{
		Flags:  s.flags,
		Key:    s.session,
		CRealm: s.header.CRealm,
		CName:  s.header.CName,
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
