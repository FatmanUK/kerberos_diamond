package spnego

// NegState is RFC 4178's negResult (gssapiP_spnego.h:25-28).
type NegState int

const (
	// AcceptComplete ends the negotiation successfully.
	AcceptComplete NegState = 0

	// AcceptIncomplete asks for another round.
	AcceptIncomplete NegState = 1

	// Reject ends it unsuccessfully.
	Reject NegState = 2

	// RequestMIC is what an acceptor answers when the mechanism
	// it chose was *not* the initiator's first preference, and it
	// obliges both sides to exchange a mechListMIC before the
	// context is established. See Negotiate for why this acceptor
	// answers Reject instead.
	RequestMIC NegState = 3
)

// NegTokenInit is RFC 4178's first token.
type NegTokenInit struct {
	// MechTypes is the initiator's preference order, most
	// preferred first. It is required and may not be empty.
	MechTypes []OID

	// DERMechTypes is the encoded MechTypeList exactly as it
	// arrived. A mechListMIC is computed over these octets and
	// not over a re-encoding, which is why the bytes are kept
	// (spnego_mech.c:3443-3450) -- the same rule the TGS body
	// checksum follows.
	DERMechTypes []byte

	// ReqFlags is the optional ContextFlags, which nothing in MIT
	// reads and which is carried for completeness.
	ReqFlags uint32

	// MechToken is the optimistic first mechanism token, which
	// for an HTTP client is the Kerberos AP-REQ. Absent means the
	// initiator wants the mechanism settled first.
	MechToken []byte

	// MechListMIC is the optional MIC over DERMechTypes.
	MechListMIC []byte
}

// UnmarshalNegTokenInit decodes a NegTokenInit, framing and all
// (get_negTokenInit, spnego_mech.c:3406-3476).
func UnmarshalNegTokenInit(b []byte) (*NegTokenInit, error) {
	oid, rest, err := ParseFramed(b)
	if err != nil {
		return nil, err
	}
	if !oid.Equal(MechSPNEGO) {
		return nil, ErrWrongMech
	}
	return parseNegTokenInit(rest)
}

// parseNegTokenInit decodes the NegotiationToken CHOICE and the
// negTokenInit inside it.
//
// Every field but mechTypes is optional and an absent one is not an
// error, which is why this reads as a run of conditionals rather than
// a decode. mechTypes itself must be present *and* non-empty:
// upstream rejects an empty field explicitly (:3440-3442), and an
// initiator offering no mechanisms has asked for nothing.
func parseNegTokenInit(b []byte) (*NegTokenInit, error) {
	outer := &reader{b: b}
	choice, ok := outer.value(tagContext | 0x00)
	if !ok || !outer.done() {
		return nil, ErrBadToken
	}
	seqs := &reader{b: choice}
	seq, ok := seqs.value(tagSeq)
	if !ok || !seqs.done() {
		return nil, ErrBadToken
	}
	r := &reader{b: seq}
	mechs, ok := r.value(tagContext | 0x00)
	if !ok || len(mechs) == 0 {
		return nil, ErrBadToken
	}
	t := &NegTokenInit{DERMechTypes: mechs}
	if t.MechTypes, ok = parseMechList(mechs); !ok {
		return nil, ErrBadToken
	}
	if f, ok := r.value(tagContext | 0x01); ok {
		if t.ReqFlags, ok = parseReqFlags(f); !ok {
			return nil, ErrBadToken
		}
	}
	if v, ok := r.value(tagContext | 0x02); ok {
		if t.MechToken, ok = octetString(v); !ok {
			return nil, ErrBadToken
		}
	}
	if v, ok := r.value(tagContext | 0x03); ok {
		if t.MechListMIC, ok = octetString(v); !ok {
			return nil, ErrBadToken
		}
	}
	if !r.done() {
		return nil, ErrBadToken
	}
	return t, nil
}

// parseMechList decodes a MechTypeList, which is a SEQUENCE OF OBJECT
// IDENTIFIER.
func parseMechList(b []byte) ([]OID, bool) {
	outer := &reader{b: b}
	seq, ok := outer.value(tagSeq)
	if !ok || !outer.done() {
		return nil, false
	}
	var out []OID
	r := &reader{b: seq}
	for !r.done() {
		oid, ok := r.value(tagOID)
		if !ok {
			return nil, false
		}
		out = append(out, OID(oid))
	}
	if r.err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// octetString unwraps an OCTET STRING.
func octetString(b []byte) ([]byte, bool) {
	r := &reader{b: b}
	v, ok := r.value(tagOctetStr)
	if !ok || !r.done() {
		return nil, false
	}
	return v, true
}

// parseReqFlags decodes ContextFlags, and it is transcribed rather
// than generalised because upstream's own decoder is startlingly
// rigid: get_req_flags (spnego_mech.c:3392-3404) demands exactly four
// octets reading 03 02 01 <flags> -- a BIT STRING with two content
// octets and one padding bit -- and then takes the flags as the last
// octet shifted right by one.
//
// A DER encoder that trimmed the padding to its minimum, which DER
// actually requires for a BIT STRING, would produce a different
// length and upstream would refuse it. So the only encoding that
// interoperates is the one upstream emits, and matching the decoder
// exactly is the behaviour-compatible choice even though it is not
// the standards-compliant one. Nothing in MIT reads the result.
func parseReqFlags(b []byte) (uint32, bool) {
	if len(b) != 4 || b[0] != tagBitStr || b[1] != 0x02 ||
		b[2] != 0x01 {
		return 0, false
	}
	return uint32(b[3]) >> 1, true
}

// Negotiate picks a mechanism out of the initiator's list and says
// what the negotiation's state then is (negotiate_mech,
// spnego_mech.c:3222-3259).
//
// The rule that matters is the one about *order*. A mechanism found
// at the head of the list is accepted outright; the same mechanism
// found anywhere else answers RequestMIC, which obliges both sides to
// exchange a mechListMIC before the context is established. That is
// RFC 4178's downgrade protection: if an attacker stripped the
// initiator's preferred mechanism out of the list, the MIC over the
// list it actually sent will not verify.
//
// So the returned state is not advisory. An acceptor that answered
// AcceptComplete where upstream answers RequestMIC would be
// discarding the only protection the negotiation has, which is why
// this reports the state and leaves refusing to the caller rather
// than quietly flattening the two cases together.
//
// Microsoft's broken OID is matched as though it were the correct one
// and then returned *as it arrived*, which is upstream's behaviour
// and is what lets a client that sent it recognise the answer
// (:3234-3237 and :3251-3254).
func (t *NegTokenInit) Negotiate() (OID, NegState) {
	for i, m := range t.MechTypes {
		if !IsKerberos(m) {
			continue
		}
		if i == 0 {
			return m, AcceptIncomplete
		}
		return m, RequestMIC
	}
	return nil, Reject
}

// NegTokenResp is RFC 4178's reply token.
type NegTokenResp struct {
	// State is the negotiation's state after this token.
	State NegState

	// SupportedMech names the chosen mechanism and is sent only
	// on the acceptor's *first* reply (make_spnego_tokenTarg_msg,
	// spnego_mech.c:3736-3742). Repeating it afterwards is not an
	// error but no implementation does it.
	SupportedMech OID

	// ResponseToken carries the mechanism's own reply, which for
	// Kerberos with mutual authentication is a framed AP-REP.
	ResponseToken []byte

	// MechListMIC is the MIC over the initiator's MechTypeList.
	// This acceptor never sends one -- see Negotiate.
	MechListMIC []byte
}

// Marshal encodes a NegTokenResp.
//
// There is no RFC 2743 framing here and that is not an omission: the
// 0x60 wrapper and the SPNEGO OID appear on the *first* token of a
// conversation only, and every token after it is a bare
// NegotiationToken. Upstream's emitter writes the [1] choice tag
// directly (:3761) and a client that received a framed reply would
// refuse it.
func (r NegTokenResp) Marshal() []byte {
	var fields []byte
	fields = append(fields, derValue(tagContext|0x00,
		derValue(tagEnum, []byte{byte(r.State)}))...)
	if r.SupportedMech != nil {
		fields = append(fields, derValue(tagContext|0x01,
			derValue(tagOID, r.SupportedMech))...)
	}
	if len(r.ResponseToken) > 0 {
		fields = append(fields, derValue(tagContext|0x02,
			derValue(tagOctetStr, r.ResponseToken))...)
	}
	if r.MechListMIC != nil {
		fields = append(fields, derValue(tagContext|0x03,
			derValue(tagOctetStr, r.MechListMIC))...)
	}
	seq := derValue(tagSeq, fields)
	return derValue(tagContext|0x01, seq)
}

// Marshal encodes a NegTokenInit, framing and all
// (make_spnego_tokenInit_msg, spnego_mech.c:3620-3700).
//
// This is the initiator's side of the conversation, which nothing in
// this project sends: an acceptor only ever decodes one. It is here
// because a decoder tested against nothing but captured bytes cannot
// reach the cases a capture does not contain -- a second mechanism in
// the list, a reqFlags field, a mechListMIC -- and because the remote
// administrative client will need it.
//
// MechTypes is encoded from the OIDs and DERMechTypes is ignored,
// which is the opposite of the decoder's priority and is right for
// the same reason: an initiator knows what it means to offer, and an
// acceptor has to keep what it was actually sent.
func (t NegTokenInit) Marshal() []byte {
	var list []byte
	for _, m := range t.MechTypes {
		list = append(list, derValue(tagOID, m)...)
	}
	fields := derValue(tagContext|0x00,
		derValue(tagSeq, list))
	if t.ReqFlags != 0 {
		fields = append(fields, derValue(tagContext|0x01,
			reqFlagsDER(t.ReqFlags))...)
	}
	if len(t.MechToken) > 0 {
		fields = append(fields, derValue(tagContext|0x02,
			derValue(tagOctetStr, t.MechToken))...)
	}
	if t.MechListMIC != nil {
		fields = append(fields, derValue(tagContext|0x03,
			derValue(tagOctetStr, t.MechListMIC))...)
	}
	choice := derValue(tagContext|0x00,
		derValue(tagSeq, fields))
	body := append(derValue(tagOID, MechSPNEGO), choice...)
	return derValue(tagAppConstr, body)
}

// reqFlagsDER writes ContextFlags in the only encoding upstream's
// decoder accepts: two content octets with one padding bit, which is
// what parseReqFlags refuses to deviate from.
func reqFlagsDER(flags uint32) []byte {
	return []byte{tagBitStr, 0x02, 0x01, byte(flags << 1)}
}

// UnmarshalNegTokenResp decodes a NegTokenResp (get_negTokenResp,
// spnego_mech.c:3480-3520).
//
// Every field is optional here, negState included, and upstream
// tolerates all of them being absent. That is not laxity: a
// conversation's last token can be nothing but a MIC, and one that is
// rejecting can be nothing but a state.
func UnmarshalNegTokenResp(b []byte) (*NegTokenResp, error) {
	outer := &reader{b: b}
	choice, ok := outer.value(tagContext | 0x01)
	if !ok || !outer.done() {
		return nil, ErrBadToken
	}
	seqs := &reader{b: choice}
	seq, ok := seqs.value(tagSeq)
	if !ok || !seqs.done() {
		return nil, ErrBadToken
	}
	r := &NegTokenResp{State: -1}
	in := &reader{b: seq}
	if v, ok := in.value(tagContext | 0x00); ok {
		n, ok := enumerated(v)
		if !ok {
			return nil, ErrBadToken
		}
		r.State = NegState(n)
	}
	if v, ok := in.value(tagContext | 0x01); ok {
		m := &reader{b: v}
		oid, ok := m.value(tagOID)
		if !ok || !m.done() {
			return nil, ErrBadToken
		}
		r.SupportedMech = OID(oid)
	}
	return respTail(in, r)
}

// respTail reads the two octet-string fields and checks nothing is
// left over.
func respTail(
	in *reader,
	r *NegTokenResp,
) (*NegTokenResp, error) {
	if v, ok := in.value(tagContext | 0x02); ok {
		s, ok := octetString(v)
		if !ok {
			return nil, ErrBadToken
		}
		r.ResponseToken = s
	}
	if v, ok := in.value(tagContext | 0x03); ok {
		s, ok := octetString(v)
		if !ok {
			return nil, ErrBadToken
		}
		r.MechListMIC = s
	}
	if !in.done() {
		return nil, ErrBadToken
	}
	return r, nil
}

// enumerated reads a single-octet ENUMERATED, which is the only width
// a negState takes.
func enumerated(b []byte) (int, bool) {
	r := &reader{b: b}
	v, ok := r.value(tagEnum)
	if !ok || !r.done() || len(v) != 1 {
		return 0, false
	}
	return int(v[0]), true
}
