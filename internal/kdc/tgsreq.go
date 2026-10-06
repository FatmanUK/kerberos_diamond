package kdc

import (
	"context"
	"errors"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// tgsState is one TGS exchange, standing in for upstream's struct
// tgs_req_info (kdc/do_tgs_req.c).
//
// The naming follows upstream's: the *header* ticket is the one the
// client presented, and the ticket being issued has no name because
// it does not exist yet.
type tgsState struct {
	req wire.TGSReq
	raw []byte
	now uint32

	header    wire.EncTicketPart
	headerSrv wire.PrincipalName
	auth      wire.Authenticator

	// replyKey is the authenticator's subkey when it sent one and
	// the header ticket's session key otherwise, and replyUsage
	// follows it. Getting the pair out of step produces a reply
	// the client cannot read while looking correct from here.
	replyKey   []byte
	replyEType crypto.EncType
	replyUsage crypto.Usage

	server      *store.Principal
	serverKey   []byte
	serverKVNO  int32
	serverEType crypto.EncType

	session wire.EncryptionKey
	flags   wire.Flags

	authTime uint32
	start    uint32
	end      uint32
	renew    uint32
}

// TGS answers a TGS-REQ. The second result is a refusal to encode as
// a KRB-ERROR; exactly one of the two is non-nil.
//
// msg is the request as it arrived, and here it is not merely useful
// but required: the authenticator's checksum is over the req-body
// bytes as sent -- see wire.ReqBodyBytes.
func (k *KDC) TGS(
	msg []byte,
	req wire.TGSReq,
) (*wire.TGSRep, *wire.KRBError) {
	s := &tgsState{req: req, raw: msg, now: stamp(k.now())}
	if code, status := k.readAPReq(s); code != 0 {
		return nil, k.krbError(code, status, nil)
	}
	cname := s.header.CName
	if code, status := k.tgsServer(s); code != 0 {
		return nil, k.krbError(code, status, &cname)
	}
	if code, status := k.tgsPolicy(s); code != 0 {
		return nil, k.krbError(code, status, &cname)
	}
	k.tgsTimes(s)
	if err := k.tgsSessionKey(s); err != nil {
		return nil, k.krbError(wire.ErrCodeGeneric,
			"MAKE_SESSION_KEY", &cname)
	}
	rep, err := k.tgsAssemble(s)
	if err != nil {
		return nil, k.krbError(wire.ErrCodeGeneric,
			"ENCODE_REPLY", &cname)
	}
	return rep, nil
}

// readAPReq validates the ticket and authenticator the client
// presented.
//
// This is kdc_process_tgs_req (kdc/kdc_util.c:143-290) with the
// replay cache and the address checks left out, as upstream also
// leaves the replay cache out here: "Don't use a replay cache"
// (:188).
func (k *KDC) readAPReq(s *tgsState) (int32, string) {
	pa := findPAData(s.req.PAData, wire.PATGSReq)
	if pa == nil {
		return wire.ErrCodePADataTypeNoSupp, "NO AP-REQ"
	}
	ap, err := wire.UnmarshalAPReq(pa.Value)
	if err != nil {
		return wire.ErrCodeModified, "DECODE AP-REQ"
	}
	// Both options are refused outright, not ignored: a TGS-REQ
	// has no use for a session-key ticket or for mutual
	// authentication, and upstream logs and rejects them
	// (kdc_util.c:177-182).
	if ap.Options&(wire.APOptUseSessionKey|
		wire.APOptMutualRequired) != 0 {
		return wire.ErrCodePolicy, "SESSION KEY OR MUTUAL"
	}
	if code, status := k.openHeader(s, ap); code != 0 {
		return code, status
	}
	return k.openAuthenticator(s, ap)
}

// openHeader decrypts the presented ticket with its server's key.
func (k *KDC) openHeader(
	s *tgsState,
	ap wire.APReq,
) (int32, string) {
	if ap.Ticket.Realm != k.Realm {
		return wire.ErrCodeNotUs, "FOREIGN TICKET"
	}
	key, code, status := k.ticketKey(ap.Ticket)
	if code != 0 {
		return code, status
	}
	tkt, code, status := openTicket(ap.Ticket, key)
	if code != 0 {
		return code, status
	}
	s.header, s.headerSrv = tkt, ap.Ticket.SName
	if tsAfter(s.now, stamp(tkt.EndTime)) {
		return wire.ErrCodeTktExpired, "TICKET EXPIRED"
	}
	return 0, ""
}

// ticketKey finds the key a presented ticket was sealed with.
//
// The kvno from the ticket selects it and the enctype is *not*
// matched: for a local krbtgt upstream sets search_enctype to -1
// (kdc_rd_ap_req, kdc_util.c:369-375), so the first key of that kvno
// is used whatever its enctype. Matching on enctype instead would
// refuse a TGT that this same KDC had issued under an older key.
func (k *KDC) ticketKey(
	tkt wire.Ticket,
) ([]byte, int32, string) {
	name := store.UnparseName(k.Realm, tkt.SName.Components)
	srv, err := k.Store.Lookup(context.Background(), name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, wire.ErrCodeSPrincipalUnknown,
			"TICKET SERVER"
	}
	if err != nil {
		return nil, wire.ErrCodeGeneric,
			"LOOKUP_TICKET_SERVER"
	}
	start := 0
	_, key, err := k.Store.Key(srv, &start, store.AnyEType,
		store.AnySaltType, tkt.EncPart.KVNO)
	if err != nil {
		return nil, wire.ErrCodeBadKeyVer, "TICKET KEY"
	}
	return key, 0, ""
}

// openTicket decrypts and decodes a ticket's sealed half.
func openTicket(
	tkt wire.Ticket,
	key []byte,
) (wire.EncTicketPart, int32, string) {
	var zero wire.EncTicketPart
	p, err := crypto.Profile(crypto.EncType(tkt.EncPart.EType))
	if err != nil {
		return zero, wire.ErrCodeETypeNoSupp, "TICKET ENCTYPE"
	}
	plain, err := p.Decrypt(key, tkt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		return zero, wire.ErrCodeBadIntegrity,
			"DECRYPT TICKET"
	}
	out, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		return zero, wire.ErrCodeModified, "DECODE TICKET"
	}
	return out, 0, ""
}

// openAuthenticator decrypts and checks the authenticator.
//
// Three things have to hold, and each is a different error: it
// decrypts under the ticket's session key, it names the same client
// as the ticket, and its clock is within skew. The first is the proof
// of possession -- a stolen ticket without the session key stops
// here.
func (k *KDC) openAuthenticator(
	s *tgsState,
	ap wire.APReq,
) (int32, string) {
	p, err := crypto.Profile(
		crypto.EncType(s.header.Key.KeyType))
	if err != nil {
		return wire.ErrCodeETypeNoSupp, "SESSION ENCTYPE"
	}
	plain, err := p.Decrypt(s.header.Key.KeyValue,
		ap.Authenticator.Cipher, crypto.UsageTGSReqAuth)
	if err != nil {
		return wire.ErrCodeBadIntegrity,
			"DECRYPT AUTHENTICATOR"
	}
	a, err := wire.UnmarshalAuthenticator(plain)
	if err != nil {
		return wire.ErrCodeModified,
			"DECODE AUTHENTICATOR"
	}
	s.auth = a
	if a.CRealm != s.header.CRealm ||
		!a.CName.Equal(s.header.CName) {
		return wire.ErrCodeBadMatch, "AUTHENTICATOR CLIENT"
	}
	if !withinSkew(stamp(a.CTime), s.now, k.skew()) {
		return wire.ErrCodeSkew, "CLOCK SKEW"
	}
	if code, status := k.checkBodyCksum(s, p); code != 0 {
		return code, status
	}
	s.replyKeyFrom(p)
	return 0, ""
}

// checkBodyCksum verifies the authenticator's checksum over the
// req-body.
//
// The checksum is mandatory here, which it is not in an application
// AP-REQ: upstream answers an authenticator without one with
// KRB5KRB_AP_ERR_INAPP_CKSUM (kdc_util.c:242-245). Without it the
// body could be rewritten in flight by anyone who could relay the
// message.
func (k *KDC) checkBodyCksum(
	s *tgsState,
	p *crypto.EncProfile,
) (int32, string) {
	if s.auth.Cksum == nil {
		return wire.ErrCodeInappCksum, "NO CHECKSUM"
	}
	body, err := wire.ReqBodyBytes(s.raw)
	if err != nil {
		return wire.ErrCodeModified, "NO REQ-BODY"
	}
	if int32(p.RequiredCksum) != s.auth.Cksum.Type {
		return wire.ErrCodeSumTypeNoSupp, "CHECKSUM TYPE"
	}
	err = p.VerifyChecksum(s.header.Key.KeyValue, body,
		s.auth.Cksum.Checksum, crypto.UsageTGSReqAuthCksum)
	if err != nil {
		return wire.ErrCodeModified, "BODY CHECKSUM"
	}
	return 0, ""
}

// replyKeyFrom picks the key the reply's enc-part is sealed with.
//
// A subkey in the authenticator replaces the ticket's session key,
// and the key usage changes with it -- 9 instead of 8. The two move
// together because upstream passes one boolean for both
// (krb5_encode_kdc_rep's use_subkey, called from
// do_tgs_req.c:1113-1114).
func (s *tgsState) replyKeyFrom(p *crypto.EncProfile) {
	if s.auth.SubKey != nil {
		s.replyKey = s.auth.SubKey.KeyValue
		s.replyEType = crypto.EncType(s.auth.SubKey.KeyType)
		s.replyUsage = crypto.UsageTGSRepEncPartSubKey
		return
	}
	s.replyKey = s.header.Key.KeyValue
	s.replyEType = p.EncType
	s.replyUsage = crypto.UsageTGSRepEncPartSessKey
}

// tgsServer loads the principal the client is asking for a ticket to.
func (k *KDC) tgsServer(s *tgsState) (int32, string) {
	if s.req.Body.SName == nil {
		return wire.ErrCodeSPrincipalUnknown, "NO SERVER NAME"
	}
	if s.req.Body.Realm != k.Realm {
		return wire.ErrCodeSPrincipalUnknown, "WRONG REALM"
	}
	srv, err := k.Store.LookupWire(context.Background(),
		k.Realm, s.req.Body.SName.Components)
	if errors.Is(err, store.ErrNotFound) {
		return wire.ErrCodeSPrincipalUnknown,
			"SERVER NOT FOUND"
	}
	if err != nil {
		return wire.ErrCodeGeneric, "LOOKUP_SERVER"
	}
	s.server = srv
	start := 0
	row, key, err := k.Store.Key(srv, &start, store.AnyEType,
		store.AnySaltType, store.HighestKVNO)
	if err != nil {
		return wire.ErrCodeSPrincipalUnknown,
			"FINDING_SERVER_KEY"
	}
	s.serverKey, s.serverKVNO = key, row.KVNO
	s.serverEType = crypto.EncType(row.EType)
	return 0, ""
}

// tgsPolicy runs the three policy gates in upstream's order.
func (k *KDC) tgsPolicy(s *tgsState) (int32, string) {
	opts := s.req.Body.Options
	if opts&wire.ASInvalidOptions == wire.OptEncTktInSKey {
		return wire.ErrCodeBadOption, "USER2USER UNSUPPORTED"
	}
	if code, status := checkTGSOpts(opts, s.header); code != 0 {
		return code, status
	}
	code, status := checkTGSService(
		opts, s.server, s.header, s.now)
	if code != 0 {
		return code, status
	}
	return checkTGSTimes(opts, s.header, s.now)
}

// tgsTimes fills in the issued ticket's times, from
// do_tgs_req.c:813-852.
func (k *KDC) tgsTimes(s *tgsState) {
	s.flags = tgsTicketFlags(s.req.Body.Options, s.server,
		s.header)
	// The authtime is *preserved from the presented ticket*, not
	// set to now: it records when the client last authenticated
	// with a password, which a derived ticket does not change.
	s.authTime = stamp(s.header.AuthTime)
	if s.req.Body.Options&wire.OptPostdated != 0 {
		s.start = stamp(s.req.Body.From)
	} else {
		s.start = s.now
	}
	s.end = k.tgsEndTime(s)
	s.renew = k.tgsRenewTime(s)
	if s.renew != 0 {
		s.flags |= wire.FlagRenewable
	}
	if s.start == s.authTime {
		s.start = 0
	}
}

// tgsEndTime caps the new ticket by the presented ticket's end time.
//
// That cap is what stops a TGT being spent for a service ticket that
// outlives it. The client principal is nil here, as it is upstream
// for anything but S4U2Self, so only the service's and the realm's
// maximum lifetimes apply.
func (k *KDC) tgsEndTime(s *tgsState) uint32 {
	till := stamp(s.req.Body.Till)
	if till == 0 {
		till = kdcInfinity
	}
	until := tsMin(till, stamp(s.header.EndTime))
	life := tsDelta(until, s.start)
	if tsAfter(until, s.start) && life < 0 {
		life = 0x7FFFFFFF
	}
	life = capLife(life, s.server.MaxLife)
	life = capLife(life, k.realmMaxLife())
	return tsIncr(s.start, life)
}

// tgsRenewTime is kdc_get_ticket_renewtime with the presented ticket
// as the TGT, which adds two caps to the AS case: a non-renewable TGT
// cannot yield a renewable ticket, and the new renew time cannot
// exceed the TGT's.
func (k *KDC) tgsRenewTime(s *tgsState) uint32 {
	if !s.header.Flags.Has(wire.FlagRenewable) {
		return 0
	}
	if s.server.Attributes&store.AttrDisallowRenewable != 0 {
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
	rtime = tsMin(rtime, stamp(s.header.RenewTill))
	maxLife := minLife(s.server.MaxRenewableLife,
		k.realmMaxRenewableLife())
	rtime = tsMin(rtime, tsIncr(s.start, maxLife))
	if opts&wire.OptRenewable == 0 && !tsAfter(rtime, s.end) {
		return 0
	}
	return rtime
}

// tgsSessionKey makes the new ticket's session key.
func (k *KDC) tgsSessionKey(s *tgsState) error {
	e := s.serverEType
	for _, want := range s.req.Body.EType {
		if want == int32(s.serverEType) {
			e = s.serverEType
			break
		}
	}
	key, err := randomKey(e)
	if err != nil {
		return err
	}
	s.session = wire.EncryptionKey{
		KeyType:  int32(e),
		KeyValue: key,
	}
	return nil
}

func (k *KDC) skew() time.Duration {
	if k.ClockSkew <= 0 {
		return 5 * time.Minute
	}
	return k.ClockSkew
}

// withinSkew is upstream's ts_within, which does its comparisons
// unsigned like everything else at the protocol boundary
// (include/k5-int.h:2357-2361).
func withinSkew(a, b uint32, d time.Duration) bool {
	secs := int32(d / time.Second)
	return !tsAfter(a, tsIncr(b, secs)) &&
		!tsAfter(b, tsIncr(a, secs))
}
