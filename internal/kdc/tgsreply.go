package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// tgsAssemble builds the TGS-REP, from do_tgs_req.c:1050-1120.
func (k *KDC) tgsAssemble(s *tgsState) (*wire.TGSRep, error) {
	tkt, err := k.tgsTicket(s)
	if err != nil {
		return nil, err
	}
	enc, err := k.tgsEncPart(s)
	if err != nil {
		return nil, err
	}
	// A TGS-REP carries no cleartext padata. return_padata's
	// etype-info is an AS-only thing -- it describes the client's
	// long-term key, which a TGS exchange never touches.
	return &wire.TGSRep{
		CRealm:  s.header.CRealm,
		CName:   s.header.CName,
		Ticket:  *tkt,
		EncPart: *enc,
	}, nil
}

// tgsTicket seals the new ticket under the service's key.
//
// The client named in it is the one from the presented ticket, not
// anything in the request: a TGS-REQ has no cname field, because the
// ticket is what says who the client is.
func (k *KDC) tgsTicket(s *tgsState) (*wire.Ticket, error) {
	plain, err := wire.MarshalEncTicketPart(wire.EncTicketPart{
		Flags:  s.flags,
		Key:    s.session,
		CRealm: s.header.CRealm,
		CName:  s.header.CName,
		Transited: wire.TransitedEncoding{
			Type: wire.TransitedDomainX500Compress,
		},
		AuthTime:  unstamp(s.authTime),
		StartTime: optStamp(s.start),
		EndTime:   unstamp(s.end),
		RenewTill: optStamp(s.renew),
	})
	if err != nil {
		return nil, err
	}
	p, err := crypto.Profile(s.serverEType)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(s.serverKey, plain,
		crypto.UsageKDCRepTicket)
	if err != nil {
		return nil, err
	}
	return &wire.Ticket{
		Realm: k.Realm,
		SName: *s.req.Body.SName,
		EncPart: wire.EncryptedData{
			EType:  int32(s.serverEType),
			KVNO:   s.serverKVNO,
			Cipher: ct,
		},
	}, nil
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
		SName:     *s.req.Body.SName,
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
	return []wire.PAData{
		{Type: wire.PAReqEncPARep, Value: der},
	}, nil
}
