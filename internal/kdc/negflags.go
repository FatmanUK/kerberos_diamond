package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/spnego"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// contextFlags works out the GSS context flags from the
// authenticator's checksum field (process_checksum,
// accept_sec_context.c:466-625).
//
// Three shapes arrive and upstream tolerates all three, which is the
// surprise in this function: the field is specified to hold an 0x8003
// structure and two widely deployed implementations put something
// else there. Refusing either would make this surface unreachable
// from software that works against a stock KDC, so the tolerance is
// copied along with the behaviour.
func (k *KDC) contextFlags(
	id *Identity,
) (uint32, *wire.KRBError) {
	switch {
	case id.Cksum == nil:
		// Handcrafted SMB clients send no checksum at all,
		// and MS-KILE says a server should accept that and
		// assume every flag unset (:487-493). No flags means
		// no mutual authentication, so such a client gets no
		// AP-REP -- which is what it expects.
		return 0, nil
	case id.Cksum.Type != spnego.CksumTypeGSSCB:
		return k.sambaFlags(id)
	}
	c, err := spnego.ParseChecksum(id.Cksum.Checksum)
	if err != nil {
		return 0, k.krbError(wire.ErrCodeModified,
			"GSS AUTHENTICATOR CHECKSUM", nil)
	}
	// The channel bindings are read and then ignored, because
	// this acceptor passes none of its own: upstream compares
	// them only when the application supplied bindings to compare
	// against (:533-545). An initiator's bindings are therefore
	// not a refusal here, and a realm that wanted them enforced
	// would have to decide what it was binding to first.
	return c.Accepted(), nil
}

// sambaFlags handles an authenticator carrying a real checksum where
// an 0x8003 structure belongs.
//
// Samba sends one, over no data at all, and upstream verifies it
// rather than ignoring it -- and says why in a comment worth
// repeating: verifying proves the authenticator was not replayed from
// one whose checksum covered actual data (:504-506). An unverified
// empty checksum would make any authenticator usable here.
//
// The key is the *ticket session key*, which upstream's own code
// obscures: it reads the key into a variable called subkey
// (:496-500), but krb5_auth_con_getkey_k returns auth_context->key
// (auth_con.c:398-404), and rd_req sets that to the session key and
// keeps the authenticator's subkey in a separate field
// (rd_req_dec.c:747-749). A reimplementation that followed the
// variable name would verify with the wrong key whenever a client
// sent a subkey, which every GSS client does.
func (k *KDC) sambaFlags(
	id *Identity,
) (uint32, *wire.KRBError) {
	p, err := crypto.Profile(crypto.EncType(id.Session.KeyType))
	if err != nil {
		return 0, k.krbError(wire.ErrCodeETypeNoSupp,
			"GSS SESSION ENCTYPE", nil)
	}
	ok := p.VerifyChecksum(id.Session.KeyValue, nil,
		id.Cksum.Checksum, crypto.UsageAPReqAuthCksum)
	if ok != nil {
		return 0, k.krbError(wire.ErrCodeBadIntegrity,
			"GSS PLAIN AUTHENTICATOR CHECKSUM", nil)
	}
	// Mutual authentication is guessed from the AP-REQ's own
	// options, because a client that sent no flags word still
	// told us this much (:514-517).
	flags := spnego.FlagReplay | spnego.FlagSequence
	if id.MutualRequired {
		flags |= spnego.FlagMutual
	}
	return flags, nil
}
