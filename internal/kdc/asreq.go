package kdc

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// asState is what one AS exchange needs to carry between steps, and
// it stands in for upstream's struct as_req_state
// (do_as_req.c:140-192) -- minus everything the callback continuation
// needed, which a straight-line Go function does not.
type asState struct {
	req wire.ASReq

	// raw is the request exactly as it arrived. RFC 6806's reply
	// checksum is computed over those bytes, so re-encoding req
	// would not do: DER is canonical, but a peer that encoded
	// something a shade differently would still have its own
	// bytes checksummed by the C and would reject ours.
	raw []byte

	now uint32

	cname  wire.PrincipalName
	client *store.Principal
	server *store.Principal

	// ticketCName and ticketSName are the names the reply
	// actually carries, which are the requested ones unless
	// KDC_OPT_CANONICALIZE asked for the database's. They differ
	// from cname and req.Body.SName only when an alias was named
	// -- see canonNames.
	ticketCName wire.PrincipalName
	ticketSName wire.PrincipalName

	// clientKey is the long-term key the reply is encrypted
	// under, and clientEType is the enctype the *request* asked
	// for. Those are two things: select_client_key overrides the
	// keyblock's enctype with the requested one
	// (do_as_req.c:117-121), a DES-era wart that is load-bearing
	// because the reply's enc-part advertises the requested
	// enctype.
	clientKey   []byte
	clientEType crypto.EncType
	clientKVNO  int32

	// clientSaltType and clientSalt are that key's stored salt.
	// They matter for one reason: a renamed principal's keys
	// carry an explicit salt, because the default one is derived
	// from the name and the name has changed. Advertising the
	// default instead would tell every client the wrong salt and
	// fail as "password incorrect" with nothing to say why.
	clientSaltType int32
	clientSalt     []byte

	// replyKey is what the reply's enc-part is actually sealed
	// with. It is the client's long-term key unless FAST
	// strengthened it, and the two are kept apart because the
	// reply still *advertises* the client key's enctype and key
	// version either way (do_as_req.c:310,330) -- the
	// strengthened key is derived from it and so shares its
	// enctype.
	replyKey []byte

	// fast is the FAST tunnel this request arrived through, or
	// nil if it arrived in the open.
	fast *fastState

	// challengeKey is the client long-term key an encrypted
	// challenge was proved with, kept so the reply can answer in
	// kind. It is not necessarily the key the reply is encrypted
	// under: a client may prove with one kvno and expect the
	// reply under the current one.
	challengeKey []byte

	// challengeEType is that key's enctype, which the reply's
	// answering challenge needs and which is not necessarily
	// clientEType: a client may prove with one enctype and ask
	// for the reply under another.
	challengeEType crypto.EncType

	serverKey   []byte
	serverKVNO  int32
	serverEType crypto.EncType

	// preAuthenticated records that the client proved knowledge
	// of its key, which becomes TKT_FLG_PRE_AUTH on the ticket
	// (kdc/kdc_preauth_encts.c:101).
	preAuthenticated bool

	session  wire.EncryptionKey
	flags    wire.Flags
	authTime uint32
	start    uint32
	end      uint32
	renew    uint32
}

// AS answers an AS-REQ. The second result is a refusal to encode as a
// KRB-ERROR; exactly one of the two is non-nil.
//
// msg is the request as it arrived on the wire, which the reply
// checksum needs and which req cannot supply -- see asState.raw.
func (k *KDC) AS(
	msg []byte,
	req wire.ASReq,
) (*wire.ASRep, *wire.KRBError) {
	s := &asState{req: req, raw: msg, now: stamp(k.now())}
	if code, status := k.findFastAS(s); code != 0 {
		return nil, k.fastErrorAS(s, code, status)
	}
	if code, status := k.principals(s); code != 0 {
		return nil, k.fastErrorAS(s, code, status)
	}
	code, status := k.validateASRequest(
		req, s.client, s.server, s.now)
	if code != 0 {
		return nil, k.fastErrorAS(s, code, status)
	}
	if code, status := k.lockedOut(s); code != 0 {
		return nil, k.fastErrorAS(s, code, status)
	}
	if code, status := k.keys(s); code != 0 {
		return nil, k.fastErrorAS(s, code, status)
	}
	if e := k.preauth(s); e != nil {
		k.audit(s, store.FailedPreauth)
		return nil, k.wrapErr(s.fast, e, s.req.Body.Nonce)
	}
	k.audit(s, store.Succeeded)
	k.times(s)
	if err := k.sessionKey(s); err != nil {
		return nil, k.fastErrorAS(s, wire.ErrCodeGeneric,
			"MAKE_SESSION_KEY")
	}
	rep, err := k.assemble(s)
	if err != nil {
		return nil, k.fastErrorAS(s, wire.ErrCodeGeneric,
			"ENCODE_REPLY")
	}
	return rep, nil
}

// fastErrorAS is krbError, wrapped in the tunnel when there is one.
func (k *KDC) fastErrorAS(
	s *asState,
	code int32,
	status string,
) *wire.KRBError {
	e := k.krbError(code, status, s.nameOrNil())
	return k.wrapErr(s.fast, e, s.req.Body.Nonce)
}

func (s *asState) nameOrNil() *wire.PrincipalName {
	if len(s.cname.Components) == 0 {
		return nil
	}
	return &s.cname
}

// principals loads the client and the requested server.
//
// ourRealm insists the request names this realm, exactly, and the
// exactness is load-bearing beyond the obvious.
//
// Upstream canonicalises the issued ticket's client realm from the
// *database entry* rather than from the request, and does it whether
// or not KDC_OPT_CANONICALIZE was asked for -- "The realm is always
// canonicalized" (do_as_req.c:680-686) -- because its KDB layer can
// hand back an entry whose realm differs from the one asked for.
//
// This KDC satisfies that rule by construction instead: a request
// naming any other realm is refused here, the lookup that follows is
// made with k.Realm, and the reply carries k.Realm, so the three can
// never disagree.
//
// Which means relaxing this check -- matching the realm
// case-insensitively, say, which looks like a kindness -- would
// *introduce* the divergence rather than remove a restriction: the
// ticket would then have to carry the database's spelling and not the
// request's, and nothing downstream does that.
func (k *KDC) ourRealm(s *asState) (int32, string) {
	if s.req.Body.Realm != k.Realm {
		return wire.ErrCodeCPrincipalUnknown, "WRONG REALM"
	}
	return 0, ""
}

// A missing client and a missing server get different protocol codes,
// which is why store.ErrNotFound is one error and the distinction is
// made here.
func (k *KDC) principals(s *asState) (int32, string) {
	ctx := context.Background()
	if s.req.Body.CName == nil {
		return wire.ErrCodeCPrincipalUnknown, "NO CLIENT NAME"
	}
	s.cname = *s.req.Body.CName
	if s.req.Body.SName == nil {
		return wire.ErrCodeSPrincipalUnknown, "NO SERVER NAME"
	}
	if code, status := k.ourRealm(s); code != 0 {
		return code, status
	}
	var err error
	s.client, err = k.Store.LookupWire(
		ctx, k.Realm, s.cname.Components)
	if errors.Is(err, store.ErrNotFound) {
		return wire.ErrCodeCPrincipalUnknown,
			"CLIENT NOT FOUND"
	}
	if err != nil {
		return wire.ErrCodeGeneric, "LOOKUP_CLIENT"
	}
	s.server, err = k.Store.LookupWire(
		ctx, k.Realm, s.req.Body.SName.Components)
	if errors.Is(err, store.ErrNotFound) {
		return wire.ErrCodeSPrincipalUnknown,
			"SERVER NOT FOUND"
	}
	if err != nil {
		return wire.ErrCodeGeneric, "LOOKUP_SERVER"
	}
	k.canonNames(s)
	return 0, ""
}

// keys picks the client key the reply will be encrypted under and the
// server key the ticket will be sealed with.
//
// The client key is chosen by walking the request's enctype list in
// the *client's* order of preference and taking the first one the
// client has a key for -- select_client_key (do_as_req.c:102-130).
// The KDC does not re-sort that list: which enctype gets used is the
// client's decision, not the KDC's.
func (k *KDC) keys(s *asState) (int32, string) {
	for _, e := range s.req.Body.EType {
		start := 0
		row, key, err := k.Store.Key(s.client, &start,
			e, store.AnySaltType, store.HighestKVNO)
		if err != nil {
			continue
		}
		s.clientKey, s.clientKVNO = key, row.KVNO
		s.clientEType = crypto.EncType(e)
		s.clientSaltType = row.SaltType
		s.clientSalt = row.Salt
		// The reply key starts as the client key and stays so
		// unless FAST strengthens it.
		s.replyKey = key
		break
	}
	if s.clientKey == nil {
		return wire.ErrCodeETypeNoSupp, "CANT_FIND_CLIENT_KEY"
	}
	// The server's key is its first key at the highest kvno, with
	// no enctype preference at all -- get_first_current_key
	// (kdc/kdc_util.c:461-473) passes -1, -1, 0.
	start := 0
	row, key, err := k.Store.Key(s.server, &start,
		store.AnyEType, store.AnySaltType, store.HighestKVNO)
	if err != nil {
		return wire.ErrCodeSPrincipalUnknown,
			"FINDING_SERVER_KEY"
	}
	s.serverKey, s.serverKVNO = key, row.KVNO
	s.serverEType = crypto.EncType(row.EType)
	return 0, ""
}

// times fills in the ticket's four timestamps and the renewable flag.
func (k *KDC) times(s *asState) {
	s.flags = ticketFlags(s.req.Body.Options, s.client, s.server)
	if s.preAuthenticated {
		s.flags |= wire.FlagPreAuthent
	}
	s.authTime = s.now
	if s.req.Body.Options&wire.OptPostdated != 0 {
		s.start = stamp(s.req.Body.From)
	} else {
		s.start = s.now
	}
	s.end = k.endTime(s)
	s.renew = k.renewTime(s)
	if s.renew != 0 {
		s.flags |= wire.FlagRenewable
	}
	// starttime is optional and means authtime when absent, so
	// the KDC drops it when they match (do_as_req.c:706-711).
	// This is the KDC's rule, not the codec's: internal/wire
	// writes the field whenever it is non-zero, exactly as the C
	// encoder does.
	if s.start == s.authTime {
		s.start = 0
	}
}

// endTime is kdc_get_ticket_endtime (kdc/kdc_util.c:1676-1704).
//
// Three things in four lines of C: a till of 0 means infinity; a
// max_life of 0 means *unlimited* rather than zero; and the wrap
// guard catches an interval so long that the signed difference comes
// back negative, which is the 2038 boundary showing through the
// unsigned comparison.
func (k *KDC) endTime(s *asState) uint32 {
	till := stamp(s.req.Body.Till)
	if till == 0 {
		till = kdcInfinity
	}
	until := tsMin(till, kdcInfinity)
	life := tsDelta(until, s.start)
	if tsAfter(until, s.start) && life < 0 {
		life = 0x7FFFFFFF
	}
	life = capLife(life, s.client.MaxLife)
	life = capLife(life, s.server.MaxLife)
	life = capLife(life, k.realmMaxLife())
	return tsIncr(s.start, life)
}

// capLife applies one maximum, where zero means no maximum.
func capLife(life, max int32) int32 {
	if max != 0 && max < life {
		return max
	}
	return life
}

// renewTime is kdc_get_ticket_renewtime (kdc/kdc_util.c:1712-1757).
//
// The renewable-ok case is the subtle one: it declines to issue a
// renewable ticket at all unless the truncated renew time exceeds the
// end time, so asking politely can get you nothing rather than
// something short. Returning 0 means not renewable, and the caller
// sets the flag and the field together -- which is what puts the
// field on the wire at all, since EncKDCRepPart gates renew-till on
// the flag.
func (k *KDC) renewTime(s *asState) uint32 {
	disallow := s.client.Attributes | s.server.Attributes
	if disallow&store.AttrDisallowRenewable != 0 {
		return 0
	}
	opts := s.req.Body.Options
	var rtime uint32
	switch {
	case opts&wire.OptRenewable != 0:
		rtime = stamp(s.req.Body.RTime)
		if rtime == 0 {
			rtime = kdcInfinity
		}
	case opts&wire.OptRenewableOK != 0 &&
		tsAfter(stamp(s.req.Body.Till), s.end):
		rtime = stamp(s.req.Body.Till)
	default:
		return 0
	}
	maxLife := minLife(s.server.MaxRenewableLife,
		k.realmMaxRenewableLife())
	maxLife = minLife(maxLife, s.client.MaxRenewableLife)
	rtime = tsMin(rtime, tsIncr(s.start, maxLife))
	if opts&wire.OptRenewable == 0 && !tsAfter(rtime, s.end) {
		return 0
	}
	return rtime
}

// minLife is upstream's min() over the renewable-life caps.
//
// Unlike capLife, zero is *not* special here:
// kdc_get_ticket_renewtime uses a plain min, so a max_renewable_life
// of zero really does mean zero and no renewable ticket is issued.
// The asymmetry with endtime's caps is upstream's and is easy to
// normalise away by accident.
func minLife(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

// sessionKey makes the ticket's session key.
func (k *KDC) sessionKey(s *asState) error {
	key, e, err := k.makeSessionKey(
		s.req.Body.EType, s.server, s.clientEType)
	if err != nil {
		return err
	}
	s.session = wire.EncryptionKey{
		KeyType:  int32(e),
		KeyValue: key,
	}
	return nil
}

// makeSessionKey is select_session_keytype (kdc/kdc_util.c:1085-1111)
// followed by a fresh random key of that enctype.
//
// The enctype is the first entry of the *request's* list that the
// server has a key for, in the client's order. Two things it is not:
// the enctype the client's own long-term key uses, and the enctype of
// the server's first key. Those three coincide in a realm with one
// enctype and diverge immediately in one with four.
//
// fallback is used when the request names nothing the server can
// satisfy, which upstream answers with 0 and its caller then refuses;
// here the caller has already established a usable key, so falling
// back to it issues a ticket rather than refusing one the client
// could read.
func (k *KDC) makeSessionKey(
	requested []int32,
	server *store.Principal,
	fallback crypto.EncType,
) ([]byte, crypto.EncType, error) {
	e := fallback
	for _, want := range requested {
		start := 0
		_, _, err := k.Store.Key(server, &start, want,
			store.AnySaltType, store.HighestKVNO)
		if err == nil {
			e = crypto.EncType(want)
			break
		}
	}
	key, err := randomKey(e)
	return key, e, err
}

// randomKey makes a fresh key of an enctype's length.
func randomKey(e crypto.EncType) ([]byte, error) {
	p, err := crypto.Profile(e)
	if err != nil {
		return nil, err
	}
	key := make([]byte, p.KeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// lockedOut refuses a principal whose failure count has reached its
// policy's maximum (krb5_db2_lockout_check_policy,
// plugins/kdb/db2/lockout.c:116-139).
//
// The code is KDC_ERR_CLIENT_REVOKED, which is what a locked-out
// account gets and is the same code DISALLOW_ALL_TIX gets: from the
// client's side being locked out and being disabled look alike, and
// upstream makes no attempt to distinguish them.
func (k *KDC) lockedOut(s *asState) (int32, string) {
	out, err := k.Store.LockoutFor(context.Background(),
		s.client, k.now())
	if err != nil {
		return wire.ErrCodeGeneric, "LOCKOUT_POLICY"
	}
	if out.Locked {
		return wire.ErrCodeClientRevoked, "CLIENT LOCKED OUT"
	}
	return 0, ""
}

// audit records what an exchange said about the client, which is what
// the lockout counters are made of.
//
// A failure to *write* the counter is deliberately not a failure of
// the exchange. Refusing a correct authentication because a counter
// could not be incremented would turn a database hiccup into an
// outage, and refusing to report a failed one changes nothing the
// client sees. Upstream's audit hook returns a code its caller
// ignores for the same reason.
func (k *KDC) audit(s *asState, outcome store.Outcome) {
	if s.client == nil {
		return
	}
	_ = k.Store.RecordOutcome(context.Background(), s.client,
		outcome, k.now())
}
