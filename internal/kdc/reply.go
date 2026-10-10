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
		CName:  s.ticketCName,
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
//
// The authorization data is filled in before the encoding rather than
// inside encTicketPart, because attaching a PAC *encodes the ticket
// itself* to checksum it -- so the structure has to exist as a value
// for a moment, which is also the shape upstream's
// krb5_kdc_sign_ticket needs.
func (k *KDC) ticket(s *asState) (*wire.Ticket, error) {
	part := k.encTicketPart(s)
	if err := k.asAuthData(s, &part); err != nil {
		return nil, err
	}
	plain, err := wire.MarshalEncTicketPart(part)
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
		SName: s.ticketSName,
		EncPart: wire.EncryptedData{
			EType:  int32(s.serverEType),
			KVNO:   s.serverKVNO,
			Cipher: ct,
		},
	}, nil
}

// encTicketPart is what goes inside the ticket.
func (k *KDC) encTicketPart(s *asState) wire.EncTicketPart {
	return wire.EncTicketPart{
		Flags:  s.flags,
		Key:    s.session,
		CRealm: k.Realm,
		CName:  s.ticketCName,
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
	}
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
		SName:         s.ticketSName,
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

// encPAData is the *encrypted* padata, distinct from the AS-REP's
// cleartext padata: it travels inside the enc-part, sealed with the
// reply key, where a client can trust it came from something holding
// that key.
//
// Two things go in it and both are advertisements of a sort.
//
// RFC 6806's reply checksum goes in when the client asked for one
// with PA-REQ-ENC-PA-REP, and a client that asked and does not get
// one refuses the reply (krb5int_fast_verify_nego,
// lib/krb5/krb/fast.c:635-673). It is keyed with the *strengthened*
// reply key, because upstream computes it after the strengthening
// (do_as_req.c:312-318) and a client verifies it with the key it
// decrypted the reply with.
//
// Then an empty PA-FX-FAST, which is how a client learns FAST is
// available here: it writes "fast_avail: yes" against this ticket in
// its credential cache (get_in_tkt.c:1635-1640), and a later kinit -T
// armed from that cache then goes straight to FAST with no probe
// round trip. The order is upstream's -- checksum first
// (kdc_handle_protected_negotiation, kdc/kdc_util.c:1784-1797) -- and
// it matters, because a client reads the list and the harness
// compares it element by element.
//
// Both are conditional on the client having asked for the checksum.
// That looks odd for the advertisement but it is upstream's
// structure: kdc_handle_protected_negotiation returns early without a
// PA-REQ-ENC-PA-REP in the request (:1779-1782), so a client that
// does not ask for a checksum is not told about FAST either. It will
// find out by trying.
//
// **A third thing goes in it and is not conditional on that**, which
// is why this is two functions now. return_enc_padata calls the
// negotiation handler and then kdc_add_pa_pac_options
// (kdc_preauth.c:1648-1657), and the second does not care whether the
// first produced anything -- so a request carrying PA-PAC-OPTIONS and
// no PA-REQ-ENC-PA-REP gets an enc-padata list holding only the PAC
// options echo. The order is upstream's: the checksum, the FAST
// advertisement, then the echo.
func (k *KDC) encPAData(s *asState) ([]wire.PAData, error) {
	out, err := k.negotiationPAData(s)
	if err != nil {
		return nil, err
	}
	if echo := pacOptionsEcho(s.req.PAData); echo != nil {
		out = append(out, *echo)
	}
	return out, nil
}

// negotiationPAData is the reply checksum and the FAST advertisement,
// both gated on the client having asked for the checksum.
func (k *KDC) negotiationPAData(
	s *asState,
) ([]wire.PAData, error) {
	if findPAData(s.req.PAData, wire.PAReqEncPARep) == nil {
		return nil, nil
	}
	p, err := crypto.Profile(s.clientEType)
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
		{Type: wire.PAFXFast},
	}, nil
}
