package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/spnego"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// negAPRep builds the AP-REP a GSS initiator that asked for mutual
// authentication expects, and fills in the reply token.
//
// **The AP-REP's subkey field means two different things**, and which
// one is a single line of C: k5_mk_rep puts a *fresh* acceptor-chosen
// key there when KRB5_AUTH_CONTEXT_USE_SUBKEY is set, and otherwise
// echoes the client's own subkey straight back (mk_rep.c:48-57). GSS
// always sets the flag for a modern enctype (CFX_ACCEPTOR_SUBKEY,
// accept_sec_context.c:1020-1023), and the password-change service
// never does.
//
// So this project needs both behaviours out of the same field, and
// they are not interchangeable: B3's finding -- that a stock kpasswd
// cannot read the reply unless its subkey comes back -- is the
// non-USE_SUBKEY half of this line, and sending a fresh key there
// would break it exactly as echoing one here would break a GSS
// client. internal/kdc/chpw.go does the echo and this does not.
func (k *KDC) negAPRep(
	n *Negotiated,
	mech spnego.OID,
) *wire.KRBError {
	id := n.Identity
	p, err := crypto.Profile(crypto.EncType(id.Session.KeyType))
	if err != nil {
		return k.krbError(wire.ErrCodeETypeNoSupp,
			"GSS SESSION ENCTYPE", nil)
	}
	sub, kerr := k.acceptorSubkey(id)
	if kerr != nil {
		return kerr
	}
	seq, err := chpwSeqNumber()
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"GSS SEQUENCE NUMBER", nil)
	}
	der, err := k.sealAPRep(id, p, sub, seq)
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"SEAL GSS AP-REP", nil)
	}
	n.Subkey, n.Reply = sub, spnego.APRepToken(mech, der)
	return nil
}

// sealAPRep encodes and encrypts the AP-REP.
//
// Encrypted with the *ticket session key* and not with the subkey the
// client sent, which is not obvious from upstream's code either:
// k5_encrypt_keyhelper is given auth_context->key (mk_rep.c:92-94),
// and rd_req sets that to the session key while keeping the
// authenticator's subkey elsewhere (rd_req_dec.c:747-749). The ctime
// and cusec are echoed exactly, because that echo is what mutual
// authentication consists of (rd_rep.c:106-110).
func (k *KDC) sealAPRep(
	id *Identity,
	p *crypto.EncProfile,
	sub *wire.EncryptionKey,
	seq uint32,
) ([]byte, error) {
	part, err := wire.MarshalEncAPRepPart(wire.EncAPRepPart{
		CTime:     id.CTime,
		CUsec:     id.CUsec,
		SubKey:    sub,
		SeqNumber: seq,
	})
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(id.Session.KeyValue, part,
		crypto.UsageAPRepEncPart)
	if err != nil {
		return nil, err
	}
	return wire.MarshalAPRep(wire.APRep{
		EncPart: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
}

// acceptorSubkey makes the key the AP-REP carries.
//
// Its enctype is the authenticator subkey's when the client sent one
// and the ticket session key's otherwise, which is negotiate_etype's
// preference order with the RFC 4537 EtypeList left out
// (rd_req_dec.c:697-701). The EtypeList travels as authorization data
// in the authenticator and this project reads no authorization data
// at all yet, so there is nothing to prefer ahead of the subkey -- a
// client that sent a list gets the next choice down, which is a legal
// outcome of the negotiation rather than a divergence. RFC 4537 says
// as much: a client cannot tell a server that ignored its list from
// one that chose the same enctype anyway.
func (k *KDC) acceptorSubkey(
	id *Identity,
) (*wire.EncryptionKey, *wire.KRBError) {
	e := crypto.EncType(id.Session.KeyType)
	if id.SubKey != nil {
		e = crypto.EncType(id.SubKey.KeyType)
	}
	if _, err := crypto.Profile(e); err != nil {
		return nil, k.krbError(wire.ErrCodeETypeNoSupp,
			"GSS SUBKEY ENCTYPE", nil)
	}
	raw, err := randomKey(e)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeGeneric,
			"GSS ACCEPTOR SUBKEY", nil)
	}
	return &wire.EncryptionKey{
		KeyType:  int32(e),
		KeyValue: raw,
	}, nil
}
