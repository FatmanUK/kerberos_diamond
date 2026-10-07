package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// assemble builds the AS-REP: the ticket sealed under the server's
// key and a copy of its contents sealed under the client's.
//
// This is the tail of finish_process_as_req (do_as_req.c:231-328)
// with the FAST, authdata and audit paths left out. The order is
// forced by FAST and would otherwise be arbitrary: the ticket first
// because the tunnel's finished field checksums it, the tunnel next
// because it both moves the reply's padata inside and decides the key
// the enc-part is sealed with, and the enc-part last for that reason.
func (k *KDC) assemble(s *asState) (*wire.ASRep, error) {
	tkt, err := k.ticket(s)
	if err != nil {
		return nil, err
	}
	pa, err := k.replyPAData(s)
	if err != nil {
		return nil, err
	}
	rep := &wire.ASRep{
		PAData: pa,
		CRealm: k.Realm,
		CName:  s.cname,
		Ticket: *tkt,
	}
	if err := k.wrapASReply(s, rep); err != nil {
		return nil, err
	}
	enc, err := k.encPart(s)
	if err != nil {
		return nil, err
	}
	rep.EncPart = *enc
	return rep, nil
}

// wrapASReply puts the reply in its tunnel, if the request came
// through one, and replaces the reply key with the strengthened one.
func (k *KDC) wrapASReply(
	s *asState,
	rep *wire.ASRep,
) error {
	if s.fast == nil {
		return nil
	}
	der, err := wire.MarshalTicket(rep.Ticket)
	if err != nil {
		return err
	}
	key, err := k.fastReply(s.fast, rep, der, s.req.Body.Nonce,
		s.replyKey, s.clientEType)
	if err != nil {
		return err
	}
	s.replyKey = key
	return nil
}

// replyPAData is the padata every successful AS-REP carries.
//
// PA-ETYPE-INFO2 goes in *every* reply, not only a preauth refusal:
// return_padata adds it unconditionally unless a preauth mechanism
// replaced the reply key (kdc/kdc_preauth.c:1486-1492). The comment
// there explains the exception -- RFC 4120 section 5.2.7.5 forbids
// describing a reply key of a different enctype -- and no mechanism
// here replaces the key, so the exception never applies.
//
// PA-PW-SALT is *not* included. add_pw_salt sends it only to "old
// clients", meaning a request that asked for no enctype requiring
// etype-info2 (:805-824); the AES types all require it, so a request
// this KDC can answer never qualifies.
func (k *KDC) replyPAData(s *asState) ([]wire.PAData, error) {
	info, err := k.etypeInfo2(s)
	if err != nil {
		return nil, err
	}
	out := []wire.PAData{
		{Type: wire.PAETypeInfo2, Value: info},
	}
	// An encrypted challenge is answered in kind, which is the
	// KDC authenticating itself: only something holding the
	// client's long-term key could have produced it (ec_return,
	// kdc/kdc_preauth_ec.c:154-205). Under FAST this travels
	// inside the tunnel, because the tunnel takes the reply's
	// padata with it.
	ch, err := k.answerChallenge(s)
	if err != nil {
		return nil, err
	}
	if ch != nil {
		out = append(out, *ch)
	}
	return out, nil
}

// ticket seals the EncTicketPart under the server's key with key
// usage 2, and records the server's current key version on it.
func (k *KDC) ticket(s *asState) (*wire.Ticket, error) {
	plain, err := k.encTicketPart(s)
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

// encTicketPart encodes what goes inside the ticket.
func (k *KDC) encTicketPart(s *asState) ([]byte, error) {
	return wire.MarshalEncTicketPart(wire.EncTicketPart{
		Flags:  s.flags,
		Key:    s.session,
		CRealm: k.Realm,
		CName:  s.cname,
		// The transited encoding is empty but its *type* is
		// 1, DOMAIN-X500-COMPRESS, not 0: the KDC sets it
		// unconditionally (do_as_req.c:689). A zero there is
		// a one-byte difference that no round-trip test sees.
		Transited: wire.TransitedEncoding{
			Type: wire.TransitedDomainX500Compress,
		},
		AuthTime: unstamp(s.authTime),
		// The ticket's own starttime is absent when zero and
		// gets no authtime default on decode, unlike the
		// reply's -- see wire.EncTicketPart.
		StartTime: optStamp(s.start),
		EndTime:   unstamp(s.end),
		RenewTill: optStamp(s.renew),
	})
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
	encPA, err := k.encPAData(s)
	if err != nil {
		return nil, err
	}
	plain, err := wire.MarshalEncASRepPart(wire.EncKDCRepPart{
		Key:       s.session,
		EncPAData: encPA,
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
	ct, err := p.Encrypt(s.replyKey, plain,
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

// encPAData is the reply's *encrypted* padata.
//
// It carries the RFC 6806 reply checksum, and only when the client
// asked for one by sending an empty PA-REQ-ENC-PA-REP
// (kdc_handle_protected_negotiation, kdc/kdc_util.c:1768-1807). The
// checksum is over the request bytes as received, keyed with the
// reply key under key usage 56.
//
// This is not optional in practice. get_ticket_flags sets
// TKT_FLG_ENC_PA_REP on every ticket, and a client that sees that
// flag *demands* the checksum and rejects the reply with
// KRB5_KDCREP_MODIFIED if it is missing (krb5int_fast_verify_nego,
// lib/krb5/krb/fast.c:635-673). A KDC that set the flag and sent no
// checksum would be refused by every MIT client while looking
// entirely correct in a field-by-field diff against a request that
// did not ask for one.
//
// Upstream also adds an empty PA-FX-FAST here, which is what makes a
// client report "FAST negotiation: available". This does not: FAST is
// not implemented, and advertising it would have the client record
// availability it cannot use.
func (k *KDC) encPAData(s *asState) ([]wire.PAData, error) {
	if findPAData(s.req.PAData, wire.PAReqEncPARep) == nil {
		return nil, nil
	}
	p, err := crypto.Profile(s.clientEType)
	if err != nil {
		return nil, err
	}
	// Keyed with the *strengthened* key, because upstream
	// computes this after kdc_fast_handle_reply_key has run
	// (do_as_req.c:312-318). A client verifies it with the key it
	// decrypted the reply with, so the unstrengthened one would
	// fail there and look like a tampered reply.
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
