package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// assemble builds the AS-REP: the ticket sealed under the server's
// key and a copy of its contents sealed under the client's.
//
// This is the tail of finish_process_as_req (do_as_req.c:231-328)
// with the FAST, authdata and audit paths left out.
func (k *KDC) assemble(s *asState) (*wire.ASRep, error) {
	tkt, err := k.ticket(s)
	if err != nil {
		return nil, err
	}
	enc, err := k.encPart(s)
	if err != nil {
		return nil, err
	}
	return &wire.ASRep{
		CRealm:  k.Realm,
		CName:   s.cname,
		Ticket:  *tkt,
		EncPart: *enc,
	}, nil
}

// ticket seals the EncTicketPart under the server's key with key
// usage 2, and records the server's current key version on it.
func (k *KDC) ticket(s *asState) (*wire.Ticket, error) {
	plain, err := wire.MarshalEncTicketPart(wire.EncTicketPart{
		Flags:    s.flags,
		Key:      s.session,
		CRealm:   k.Realm,
		CName:    s.cname,
		AuthTime: unstamp(s.authTime),
		// The ticket's own starttime is absent when zero and
		// gets no authtime default on decode, unlike the
		// reply's -- see wire.EncTicketPart.
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

// encPart seals the EncKDCRepPart under the client's long-term key
// with key usage 3.
//
// The reply's enc-part carries *no* kvno, and that is not an
// omission. finish_process_as_req assigns state->reply.enc_part.kvno
// only after krb5_encode_kdc_rep has already run
// (do_as_req.c:326-330), so the value never reaches the wire -- the
// comment there calls the leftover fields "a courtesy". A Go KDC that
// filled the field in would differ from every MIT reply in existence.
func (k *KDC) encPart(s *asState) (*wire.EncryptedData, error) {
	plain, err := wire.MarshalEncASRepPart(wire.EncKDCRepPart{
		Key: s.session,
		// last-req is a stub upstream: one constant
		// {KRB5_LRQ_NONE, 0} entry (kdc/kdc_util.c:677-688).
		// Implementing it properly would diverge immediately.
		LastReq:       []wire.LastReqEntry{{Type: 0}},
		Nonce:         s.req.Body.Nonce,
		KeyExpiration: optStamp(keyExpiry(s)),
		Flags:         s.flags,
		AuthTime:      unstamp(s.authTime),
		StartTime:     optStamp(s.start),
		EndTime:       unstamp(s.end),
		RenewTill:     optStamp(s.renew),
		SRealm:        k.Realm,
		SName:         *s.req.Body.SName,
	})
	if err != nil {
		return nil, err
	}
	p, err := crypto.Profile(s.clientEType)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(s.clientKey, plain,
		crypto.UsageASRepEncPart)
	if err != nil {
		return nil, err
	}
	return &wire.EncryptedData{
		EType:  int32(s.clientEType),
		Cipher: ct,
	}, nil
}

// keyExpiry is get_key_exp (do_as_req.c:160-167): the earlier of the
// two expiries, with zero on either meaning "use the other".
func keyExpiry(s *asState) uint32 {
	exp := stamp(s.client.Expiration)
	pw := stamp(s.client.PWExpiration)
	if exp == 0 {
		return pw
	}
	if pw == 0 {
		return exp
	}
	return tsMin(exp, pw)
}
