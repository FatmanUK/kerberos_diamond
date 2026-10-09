package kdc

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/spnego"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// gssAPReq builds the AP-REQ a GSS initiator sends: mutual
// authentication in the options, a subkey in the authenticator, and
// an 0x8003 structure in the checksum field where a checksum belongs.
func gssAPReq(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	cksum *wire.Checksum,
	opts wire.Flags,
) []byte {
	t.Helper()
	p := aes256(t)
	sub := &wire.EncryptionKey{
		KeyType:  int32(crypto.AES256CTSHMACSHA196),
		KeyValue: make([]byte, 32),
	}
	plain, err := wire.MarshalAuthenticator(
		adminAuthenticator(func(a *wire.Authenticator) {
			a.SubKey = sub
			a.SeqNumber = 42
			a.Cksum = cksum
		}))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(session, plain, crypto.UsageAPReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	der, err := wire.MarshalAPReq(wire.APReq{
		Options: opts,
		Ticket:  tkt,
		Authenticator: wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// gssCksum is the 0x8003 field for a given flags word.
func gssCksum(flags uint32) *wire.Checksum {
	c := &spnego.Checksum{Flags: flags}
	return &wire.Checksum{
		Type:     spnego.CksumTypeGSSCB,
		Checksum: c.Marshal(),
	}
}

// negTokenInit wraps a mechanism token the way a SPNEGO initiator
// does, with a chosen preference order.
func negTokenInit(
	mechs []spnego.OID,
	apReq []byte,
) []byte {
	return spnego.NegTokenInit{
		MechTypes: mechs,
		MechToken: spnego.MechToken{
			Mech:  spnego.MechKrb5,
			TokID: spnego.TokIDAPReq,
			Body:  apReq,
		}.Marshal(),
	}.Marshal()
}

// A SPNEGO token whose first mechanism is Kerberos authenticates and
// gets an AP-REP back, and the reply is a bare NegTokenResp naming
// the mechanism that was chosen.
func TestAcceptNegotiateSPNEGO(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")
	der := gssAPReq(t, tkt, session,
		gssCksum(spnego.FlagMutual|spnego.FlagInteg),
		wire.APOptMutualRequired)
	n, kerr := k.AcceptNegotiate(negTokenInit(
		[]spnego.OID{spnego.MechKrb5}, der))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr.ErrorCode)
	}
	if got := n.Name(); got != "user@"+testRealm {
		t.Errorf("authenticated %q", got)
	}
	if n.Flags&spnego.FlagMutual == 0 ||
		n.Flags&spnego.FlagInteg == 0 {
		t.Errorf("flags are %#x", n.Flags)
	}
	if n.Subkey == nil {
		t.Fatal("no acceptor subkey")
	}
	assertNegTokenResp(t, n.Reply, spnego.MechKrb5)
}

// assertNegTokenResp checks the reply token's shape.
func assertNegTokenResp(
	t *testing.T,
	reply []byte,
	mech spnego.OID,
) {
	t.Helper()
	r, err := spnego.UnmarshalNegTokenResp(reply)
	if err != nil {
		t.Fatalf("the reply does not decode: %v", err)
	}
	if r.State != spnego.AcceptComplete {
		t.Errorf("negState is %d", r.State)
	}
	if !r.SupportedMech.Equal(mech) {
		t.Errorf("supportedMech is %x", r.SupportedMech)
	}
	// APPLICATION 15 is KRB-AP-REP (asn1_k_encode.c:762).
	tok, err := spnego.ParseMechToken(r.ResponseToken)
	if err != nil {
		t.Fatalf("the responseToken: %v", err)
	}
	if tok.TokID != spnego.TokIDAPRep {
		t.Errorf("token id %#x", tok.TokID)
	}
	if len(tok.Body) == 0 || tok.Body[0] != 0x6f {
		t.Error("the responseToken is not an AP-REP")
	}
	if r.MechListMIC != nil {
		t.Error("a mechListMIC was sent")
	}
}

// The acceptor subkey is **a fresh key and not the client's**, which
// is the half of mk_rep.c:48-57 that GSS takes. Sending the client's
// own subkey back would be the password-change service's behaviour in
// the wrong protocol.
func TestTheAcceptorSubkeyIsNotTheClients(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")
	der := gssAPReq(t, tkt, session,
		gssCksum(spnego.FlagMutual), wire.APOptMutualRequired)
	n, kerr := k.AcceptNegotiate(negTokenInit(
		[]spnego.OID{spnego.MechKrb5}, der))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr.ErrorCode)
	}
	if n.SubKey == nil || n.Subkey == nil {
		t.Fatal("a key is missing")
	}
	if string(n.Subkey.KeyValue) == string(n.SubKey.KeyValue) {
		t.Error("the client's own subkey was echoed back")
	}
	// gssAPReq's client subkey is all zeroes, so a key of the
	// right length that is not zero is a key this side chose.
	if len(n.Subkey.KeyValue) != 32 {
		t.Errorf("subkey is %d octets",
			len(n.Subkey.KeyValue))
	}
}

// A bare mechanism token works too, because an HTTP client may send
// either and the acceptor dispatches on the OID in the framing.
func TestAcceptNegotiateBareMechToken(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")
	der := gssAPReq(t, tkt, session,
		gssCksum(spnego.FlagMutual), wire.APOptMutualRequired)
	tok := spnego.MechToken{
		Mech:  spnego.MechKrb5,
		TokID: spnego.TokIDAPReq,
		Body:  der,
	}.Marshal()
	n, kerr := k.AcceptNegotiate(tok)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr.ErrorCode)
	}
	// No SPNEGO wrapper went in, so none comes back: the reply is
	// the AP-REP token itself.
	back, err := spnego.ParseMechToken(n.Reply)
	if err != nil {
		t.Fatalf("the reply: %v", err)
	}
	if back.TokID != spnego.TokIDAPRep {
		t.Errorf("token id %#x", back.TokID)
	}
}

// The three shapes the authenticator's checksum field arrives in, all
// three of which upstream tolerates (process_checksum,
// accept_sec_context.c:485-520). The surprise is that two of them are
// not 0x8003 at all, and refusing either would make this surface
// unreachable from software that works against a stock KDC.
// checksumShape is one way the authenticator's checksum field
// arrives, and what the acceptor should make of it.
type checksumShape struct {
	why    string
	cksum  func(*testing.T, []byte) *wire.Checksum
	mutual bool
	flags  uint32
}

// checksumShapes is the three shapes upstream tolerates
// (process_checksum, accept_sec_context.c:485-520). The surprise is
// that two of them are not 0x8003 at all, and refusing either would
// make this surface unreachable from software that works against a
// stock KDC.
func checksumShapes() []checksumShape {
	return []checksumShape{
		{"an 0x8003 structure", func(
			*testing.T, []byte) *wire.Checksum {
			return gssCksum(spnego.FlagMutual |
				spnego.FlagConf)
		}, true, spnego.FlagMutual | spnego.FlagConf},
		{"no checksum at all", func(
			*testing.T, []byte) *wire.Checksum {
			return nil
		}, false, 0},
		{"a real checksum over no data", emptyCksum, true,
			spnego.FlagReplay | spnego.FlagSequence |
				spnego.FlagMutual},
	}
}

// All three authenticate, and the flags each yields are different.
func TestTheThreeChecksumShapes(t *testing.T) {
	k := testKDC(t)
	for _, c := range checksumShapes() {
		t.Run(c.why, func(t *testing.T) {
			n := acceptShape(t, k, c)
			if n.Flags != c.flags {
				t.Errorf("flags %#x, want %#x",
					n.Flags, c.flags)
			}
		})
	}
}

// acceptShape runs one shape through the acceptor.
func acceptShape(
	t *testing.T,
	k *KDC,
	c checksumShape,
) *Negotiated {
	t.Helper()
	tkt, session := adminTicketFromTGT(t, k, "admin")
	var opts wire.Flags
	if c.mutual {
		opts = wire.APOptMutualRequired
	}
	der := gssAPReq(t, tkt, session, c.cksum(t, session),
		opts)
	n, kerr := k.AcceptNegotiate(negTokenInit(
		[]spnego.OID{spnego.MechKrb5}, der))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr.ErrorCode)
	}
	return n
}

// emptyCksum is what Samba sends: a real keyed checksum over no data
// at all, under key usage 10 and the **ticket session key** -- which
// upstream's own code obscures by calling it a subkey
// (accept_sec_context.c:496-500 reads auth_context->key, which
// rd_req_dec.c:747-749 set to the session key).
func emptyCksum(t *testing.T, session []byte) *wire.Checksum {
	t.Helper()
	sum, err := aes256(t).Checksum(session, nil,
		crypto.UsageAPReqAuthCksum)
	if err != nil {
		t.Fatal(err)
	}
	return &wire.Checksum{
		Type:     int32(crypto.HMACSHA196AES256),
		Checksum: sum,
	}
}

// Every way the negotiation is refused, each with its own error,
// because an HTTP acceptor answers differently for each. negRefusal
// is one way the negotiation is turned away.
type negRefusalCase struct {
	why   string
	token func(*testing.T, *KDC) []byte
	want  int32
}

// goodGSSAPReq is the AP-REQ the refusal cases wrap in something
// wrong, so that only the wrapping is under test.
func goodGSSAPReq(t *testing.T, k *KDC) []byte {
	t.Helper()
	tkt, session := adminTicketFromTGT(t, k, "admin")
	return gssAPReq(t, tkt, session,
		gssCksum(spnego.FlagMutual),
		wire.APOptMutualRequired)
}

// ntlmOID is Microsoft's NTLMSSP mechanism, used here only as
// something that is not Kerberos.
var ntlmOID = spnego.OID(
	"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")

// negRefusals is every way the negotiation is refused, each with its
// own error, because an HTTP acceptor answers differently for each.
func negRefusals() []negRefusalCase {
	return []negRefusalCase{
		{"not a token at all",
			func(*testing.T, *KDC) []byte {
				return []byte{0x30, 0x00}
			}, wire.ErrCodeModified},
		{"a mechanism nobody here speaks",
			func(t *testing.T, k *KDC) []byte {
				return negTokenInit(
					[]spnego.OID{ntlmOID},
					goodGSSAPReq(t, k))
			}, wire.ErrCodeETypeNoSupp},
		{"Kerberos offered second",
			func(t *testing.T, k *KDC) []byte {
				return negTokenInit([]spnego.OID{
					ntlmOID, spnego.MechKrb5},
					goodGSSAPReq(t, k))
			}, wire.ErrCodePolicy},
		{"no mechanism token",
			func(*testing.T, *KDC) []byte {
				return spnego.NegTokenInit{
					MechTypes: []spnego.OID{
						spnego.MechKrb5},
				}.Marshal()
			}, wire.ErrCodePreauthRequired},
		{"an AP-REP where an AP-REQ belongs",
			func(t *testing.T, k *KDC) []byte {
				return spnego.APRepToken(
					spnego.MechKrb5,
					goodGSSAPReq(t, k))
			}, wire.ErrCodeModified},
	}
}

func TestAcceptNegotiateRefusals(t *testing.T) {
	k := testKDC(t)
	for _, c := range negRefusals() {
		t.Run(c.why, func(t *testing.T) {
			_, kerr := k.AcceptNegotiate(c.token(t, k))
			if kerr == nil {
				t.Fatal("accepted")
			}
			if kerr.ErrorCode != c.want {
				t.Errorf("code %d, want %d",
					kerr.ErrorCode, c.want)
			}
		})
	}
}
