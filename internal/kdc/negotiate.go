package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/spnego"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Negotiated is the outcome of accepting a GSS context-establishment
// token: who the client is, and the token to answer with.
type Negotiated struct {
	// Identity is the authenticated client.
	*Identity

	// Reply is the token to send back, which is empty when the
	// initiator did not ask for mutual authentication. An HTTP
	// acceptor sends it in a WWW-Authenticate header on the
	// successful response.
	Reply []byte

	// Flags is the context flags this acceptor honoured, which is
	// the initiator's request masked (spnego.InitiatorFlags).
	Flags uint32

	// Subkey is the acceptor subkey sent in the AP-REP, which
	// becomes the key for anything that follows and is therefore
	// the one piece of this a per-message layer would need. There
	// is no such layer here; it is returned so that its absence
	// is a decision rather than an omission.
	Subkey *wire.EncryptionKey
}

// AcceptNegotiate accepts an RFC 4559 Negotiate token.
//
// Two kinds arrive and both are handled, because a client chooses
// which and an acceptor does not: a bare RFC 4121 mechanism token
// framed directly under the Kerberos OID, and the same token wrapped
// in a SPNEGO NegTokenInit. Upstream reaches both through the same
// gss_accept_sec_context by dispatching on the OID in the framing,
// and so does this.
func (k *KDC) AcceptNegotiate(
	token []byte,
) (*Negotiated, *wire.KRBError) {
	oid, _, err := spnego.ParseFramed(token)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeModified,
			"GSS TOKEN FRAMING", nil)
	}
	if oid.Equal(spnego.MechSPNEGO) {
		return k.acceptSPNEGO(token)
	}
	return k.acceptMechToken(token, nil)
}

// acceptSPNEGO unwraps a NegTokenInit and answers with a
// NegTokenResp.
func (k *KDC) acceptSPNEGO(
	token []byte,
) (*Negotiated, *wire.KRBError) {
	init, err := spnego.UnmarshalNegTokenInit(token)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeModified,
			"SPNEGO NEG-TOKEN-INIT", nil)
	}
	mech, state := init.Negotiate()
	if state != spnego.AcceptIncomplete {
		return nil, k.negRefusal(state)
	}
	// An initiator may settle the mechanism before sending a
	// ticket, and then there is nothing to authenticate yet.
	// Refusing says so rather than reporting a client this
	// acceptor never saw.
	if len(init.MechToken) == 0 {
		return nil, k.krbError(wire.ErrCodePreauthRequired,
			"SPNEGO NO MECH TOKEN", nil)
	}
	n, kerr := k.acceptMechToken(init.MechToken, mech)
	if kerr != nil {
		return nil, kerr
	}
	n.Reply = spnego.NegTokenResp{
		State:         spnego.AcceptComplete,
		SupportedMech: mech,
		ResponseToken: n.Reply,
	}.Marshal()
	return n, nil
}

// negRefusal turns a negotiation that did not choose Kerberos into an
// error, and the two reasons are worth distinguishing.
//
// Reject means no mechanism in the initiator's list was Kerberos,
// which is a client this realm cannot serve.
//
// RequestMIC means Kerberos was offered but not first, and RFC 4178
// then requires a mechListMIC exchange before the context is
// established -- a GSS per-message MIC, which this project has no
// per-message layer to produce. Answering AcceptComplete anyway would
// establish the context while discarding the negotiation's only
// protection against an attacker having stripped the initiator's
// preferred mechanism out of the list, so it is refused instead. The
// cost is a client whose first choice is something else -- NegoEx,
// most likely, which Windows offers ahead of Kerberos -- and that is
// recorded as a limitation rather than papered over.
func (k *KDC) negRefusal(s spnego.NegState) *wire.KRBError {
	if s == spnego.RequestMIC {
		return k.krbError(wire.ErrCodePolicy,
			"SPNEGO MECH NOT PREFERRED", nil)
	}
	return k.krbError(wire.ErrCodeETypeNoSupp,
		"SPNEGO NO KERBEROS MECH", nil)
}

// acceptMechToken accepts an RFC 4121 initiator token. mech is the
// OID the SPNEGO negotiation settled on, or nil when the token was
// framed directly and the OID in the framing is the answer.
func (k *KDC) acceptMechToken(
	token []byte,
	mech spnego.OID,
) (*Negotiated, *wire.KRBError) {
	der, framed, err := spnego.APReqToken(token)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeModified,
			"GSS MECH TOKEN", nil)
	}
	if mech == nil {
		mech = framed
	}
	id, kerr := k.AcceptAPReq(der)
	if kerr != nil {
		return nil, kerr
	}
	flags, kerr := k.contextFlags(id)
	if kerr != nil {
		return nil, kerr
	}
	n := &Negotiated{Identity: id, Flags: flags}
	if flags&spnego.FlagMutual == 0 {
		return n, nil
	}
	if kerr := k.negAPRep(n, mech); kerr != nil {
		return nil, kerr
	}
	return n, nil
}
