package kdc

import (
	"context"
	"errors"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/spnego"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
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
// and so does this. A context is taken rather than made because this
// one has a caller that has one -- an HTTP request -- where the KDC's
// own exchanges are driven by Handle and make their own. The replay
// check reaches the database, so a cancelled request should stop
// there too.
func (k *KDC) AcceptNegotiate(
	ctx context.Context,
	token []byte,
) (*Negotiated, *wire.KRBError) {
	oid, _, err := spnego.ParseFramed(token)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeModified,
			"GSS TOKEN FRAMING", nil)
	}
	if oid.Equal(spnego.MechSPNEGO) {
		return k.acceptSPNEGO(ctx, token)
	}
	return k.acceptMechToken(ctx, token, nil)
}

// acceptSPNEGO unwraps a NegTokenInit and answers with a
// NegTokenResp.
func (k *KDC) acceptSPNEGO(
	ctx context.Context,
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
	n, kerr := k.acceptMechToken(ctx, init.MechToken, mech)
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
	ctx context.Context,
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
	if kerr := k.refuseReplay(ctx, der); kerr != nil {
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

// refuseReplay records this AP-REQ's authenticator and refuses one
// already seen.
//
// **Upstream's two administrative surfaces differ here, and the
// difference is deliberate on both sides.** The GSS acceptor keeps a
// replay cache: `krb5_get_server_rcache` opens one when the
// credential is acquired (`acquire_cred.c:218`), it goes on the auth
// context at `accept_sec_context.c:808-811`, and `k5_rc_store` runs
// inside `krb5_rd_req` (`rd_req_dec.c:620-625`). The password-change
// service turns it off: `schpw.c:110-111` sets the auth context's
// flags to `DO_SEQUENCE` alone, which *clears* `DO_TIME`, and
// `rd_req_dec.c:543-548` then creates no cache and stores nothing.
//
// So the line is drawn by what a replay would do. Replaying a
// password change sets the same password again; replaying an
// administrative request re-runs it, and `cpw -randkey` or `delprinc`
// re-run is not harmless. This is the GSS path, so it gets the cache,
// and internal/kdc/chpw.go does not -- which is upstream's split
// exactly.
//
// TLS is not the answer to this and it is worth saying why: it
// protects a live connection and says nothing about a POST recorded
// at one end and sent again later.
func (k *KDC) refuseReplay(
	ctx context.Context,
	der []byte,
) *wire.KRBError {
	tag, err := replayTag(der)
	if err != nil {
		return k.krbError(wire.ErrCodeModified,
			"GSS REPLAY TAG", nil)
	}
	err = k.Store.RecordAuthenticator(ctx, tag, k.now(),
		k.skew())
	switch {
	case errors.Is(err, store.ErrReplay):
		return k.krbError(wire.ErrCodeRepeat,
			"GSS AUTHENTICATOR REPLAYED", nil)
	case err != nil:
		return k.krbError(wire.ErrCodeGeneric,
			"RECORD GSS AUTHENTICATOR", nil)
	}
	return nil
}

// replayTag is k5_rc_tag_from_ciphertext
// (lib/krb5/rcache/rc_base.c:109-126): the last octets of the
// authenticator's ciphertext, as many as that enctype's checksum is
// long.
//
// It is the integrity tag, which is the one part of the message a
// sender could not have produced without the key -- so it is unique
// per authenticator without this code having to decrypt anything or
// hash anything, and two authenticators collide only if their tags
// do. Deriving it from the client name and timestamp instead would
// collide for a client that legitimately sent two requests in the
// same microsecond.
func replayTag(der []byte) ([]byte, error) {
	ap, err := wire.UnmarshalAPReq(der)
	if err != nil {
		return nil, err
	}
	p, err := crypto.Profile(
		crypto.EncType(ap.Authenticator.EType))
	if err != nil {
		return nil, err
	}
	ct := ap.Authenticator.Cipher
	if len(ct) < p.TrailerLength || p.TrailerLength == 0 {
		return nil, errors.New("kdc: short authenticator")
	}
	return ct[len(ct)-p.TrailerLength:], nil
}
