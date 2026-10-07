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

	// headerRealm is the realm the presented ticket was issued
	// in, which is not this realm for a cross-realm request.
	headerRealm string

	auth wire.Authenticator

	// replyKey is the authenticator's subkey when it sent one and
	// the header ticket's session key otherwise, and replyUsage
	// follows it. Getting the pair out of step produces a reply
	// the client cannot read while looking correct from here.
	replyKey   []byte
	replyEType crypto.EncType
	replyUsage crypto.Usage

	// fast is the FAST tunnel this request arrived through, or
	// nil if it arrived in the open.
	fast *fastState

	// stkt is the request's second ticket, decrypted, and stktSrv
	// the principal it names. Both are nil unless the options
	// asked for user-to-user.
	stkt    *wire.EncTicketPart
	stktSrv wire.PrincipalName

	// serverName is the name the issued ticket will carry, which
	// is the one asked for unless referral is set -- a referral
	// names an intermediate realm's krbtgt instead.
	serverName wire.PrincipalName
	referral   bool

	server      *store.Principal
	serverKey   []byte
	serverKVNO  int32
	serverEType crypto.EncType

	// transited is the path the issued ticket will carry, which
	// is the presented ticket's unless this request added a realm
	// to it. transitChecked records that the path was evaluated
	// and accepted, which becomes TKT_FLG_TRANSIT_POLICY_CHECKED
	// on the issued ticket.
	transited      wire.TransitedEncoding
	transitChecked bool

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
	if code, status := k.findFastTGS(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	if code, status := k.tgsServer(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	if code, status := k.readSecondTicket(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	if code, status := k.buildTransited(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	if code, status := k.tgsPolicy(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	k.tgsTimes(s)
	if code, status := k.tgsSessionKey(s); code != 0 {
		return nil, k.fastError(s, code, status, &cname)
	}
	rep, err := k.tgsAssemble(s)
	if err != nil {
		return nil, k.fastError(s, wire.ErrCodeGeneric,
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
	// A foreign realm is not refused here. The ticket's server is
	// looked up under the ticket's own realm, so a cross-realm
	// TGT resolves to krbtgt/<here>@<there> -- a principal this
	// KDC holds only if it has agreed to trust that realm. The
	// lookup succeeding is the trust check, and checkTGT then
	// insists the name really is a krbtgt for the realm being
	// asked about.
	key, code, status := k.ticketKey(ap.Ticket)
	if code != 0 {
		return code, status
	}
	tkt, code, status := openTicket(ap.Ticket, key)
	if code != 0 {
		return code, status
	}
	s.header = tkt
	s.headerSrv, s.headerRealm = ap.Ticket.SName, ap.Ticket.Realm
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
	// The ticket's own realm, not this KDC's: a cross-realm TGT
	// names krbtgt/<here> but belongs to the realm that issued
	// it, and that is the principal whose key sealed it.
	name := store.UnparseName(
		tkt.Realm, tkt.SName.Components)
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

// tgsServer loads the principal the client is asking for a ticket to
// (search_sprinc, do_tgs_req.c:541-581).
//
// A lookup that comes up empty is not always the end: when the name
// is a cross-realm ticket-granting service this realm does not hold,
// the KDC knows a path the client does not and hands back an
// intermediate instead. The issued ticket then names something other
// than what was asked for, which is what a referral is.
func (k *KDC) tgsServer(s *tgsState) (int32, string) {
	if s.req.Body.SName == nil {
		return wire.ErrCodeSPrincipalUnknown, "NO SERVER NAME"
	}
	if s.req.Body.Realm != k.Realm {
		return wire.ErrCodeSPrincipalUnknown, "WRONG REALM"
	}
	s.serverName = *s.req.Body.SName
	srv, err := k.Store.LookupWire(context.Background(),
		k.Realm, s.req.Body.SName.Components)
	if errors.Is(err, store.ErrNotFound) {
		if code, status := k.alternate(s); code != 0 {
			return code, status
		}
	} else if err != nil {
		return wire.ErrCodeGeneric, "LOOKUP_SERVER"
	} else {
		s.server = srv
	}
	return k.serverKeyFor(s)
}

// alternate fills in a referral server, or reports the refusal that
// stands when there is none.
func (k *KDC) alternate(s *tgsState) (int32, string) {
	if !k.wantsAlternateTGS(s) {
		return wire.ErrCodeSPrincipalUnknown,
			"SERVER NOT FOUND"
	}
	srv, name, ok := k.findAlternateTGS(s)
	if !ok {
		return wire.ErrCodeSPrincipalUnknown, "UNKNOWN_SERVER"
	}
	s.server, s.serverName, s.referral = srv, name, true
	return 0, ""
}

// serverKeyFor finds the key the issued ticket will be sealed with:
// the first key of the server's highest key version, whatever its
// enctype (get_first_current_key, kdc/kdc_util.c:461-473).
func (k *KDC) serverKeyFor(s *tgsState) (int32, string) {
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

// tgsPolicy runs the policy gates in upstream's order.
//
// The order is itself behaviour: a request that fails more than one
// gate gets the error of the first, and that error is what a client
// acts on. check_tgs_constraints runs the option checks, then the
// times, then the server-name checks, then user-to-user
// (tgs_policy.c:682-714); check_tgs_policy's service checks come
// after all of them (:746).
func (k *KDC) tgsPolicy(s *tgsState) (int32, string) {
	opts := s.req.Body.Options
	// S4U2Proxy is not implemented and is refused rather than
	// ignored: cname-in-addl-tkt means the request is asking for
	// a ticket on another principal's behalf, and answering it as
	// an ordinary request would issue a ticket for the wrong
	// client.
	if opts&wire.OptCNameInAddlTkt != 0 {
		return wire.ErrCodeBadOption, "S4U2PROXY UNSUPPORTED"
	}
	if code, status := checkTGSOpts(opts, s.header); code != 0 {
		return code, status
	}
	if code, status := checkTGSTimes(
		opts, s.header, s.now); code != 0 {
		return code, status
	}
	if code, status := k.checkHeaderServer(s); code != 0 {
		return code, status
	}
	if code, status := k.checkLineage(s); code != 0 {
		return code, status
	}
	if code, status := k.checkU2U(s); code != 0 {
		return code, status
	}
	code, status := checkTGSService(
		opts, s.server, s.header, s.now)
	if code != 0 {
		return code, status
	}
	return k.checkTransited(s)
}

// nonTGTOptions are the options under which the presented ticket's
// server may be something other than a ticket-granting service
// (NON_TGT_OPTION, kdc/kdc_util.h:455-456).
const nonTGTOptions = wire.OptForwarded | wire.OptProxy |
	wire.OptRenew | wire.OptValidate

// checkHeaderServer checks the presented ticket's server against the
// request's, which upstream does one of two ways depending on the
// options (tgs_policy.c:692-695).
func (k *KDC) checkHeaderServer(s *tgsState) (int32, string) {
	if s.req.Body.Options&nonTGTOptions != 0 {
		return k.checkNonTGT(s)
	}
	return k.checkTGT(s)
}

// checkTGT is check_tgs_tgt (tgs_policy.c:653-665): an ordinary
// request must present a ticket-granting ticket.
//
// Without it any service ticket would do -- one the client obtained
// earlier for some unrelated service -- and the KDC would derive a
// ticket to somewhere else from it. The error is
// KRB5KRB_AP_ERR_NOT_US rather than a policy refusal, because the
// complaint is that the ticket was not addressed to this KDC at all.
func (k *KDC) checkTGT(s *tgsState) (int32, string) {
	if !isTGSName(s.headerSrv) {
		return wire.ErrCodeNotUs, "BAD TGS SERVER NAME"
	}
	// The krbtgt's instance names the realm it grants tickets
	// for, which has to be the realm the request asks about.
	if s.headerSrv.Components[1] != s.req.Body.Realm {
		return wire.ErrCodeNotUs, "BAD TGS SERVER INSTANCE"
	}
	return 0, ""
}

// checkNonTGT is check_tgs_nontgt (tgs_policy.c:632-647): the four
// options under which the presented ticket is not a TGT.
//
// All four hand back the ticket presented -- renewed, validated, or
// re-addressed -- so the request has to name the same server it does.
// Upstream applies this to forwarded and proxied requests as well as
// to renewal and validation (NON_TGT_OPTION, kdc_util.h:455-456), and
// this implementation at first applied it only to the latter two. The
// differential harness found that the moment forwarding was put to
// both KDCs: the C refused with SERVER_NOMATCH and the Go side issued
// a ticket.
//
// Upstream itself does not make the equivalent check for renewal and
// validation, where it names the issued ticket after the *header*
// ticket's server (do_tgs_req.c:1012-1016) while sealing it with the
// key of the server the *request* asked for. A mismatched request
// therefore gets a ticket whose name and key belong to different
// principals -- undecryptable by the principal it names, and refused
// with BAD_INTEGRITY by whoever receives it. This refuses the
// mismatch instead, with the error whose name is exactly this
// condition: KDC_ERR_SERVER_NOMATCH, "Requested server and ticket
// don't match". That divergence is recorded in BOOTSTRAP.md §3.3, on
// the grounds that issuing an unusable ticket is not behaviour worth
// preserving. The normal case -- a client renewing the ticket it
// holds -- is unaffected.
func (k *KDC) checkNonTGT(s *tgsState) (int32, string) {
	if !s.req.Body.SName.Equal(s.headerSrv) {
		return wire.ErrCodeServerNoMatch, "SERVER NOMATCH"
	}
	// A ticket-granting ticket cannot be proxied. A proxy ticket
	// is one service's ticket for use from somewhere else, and a
	// TGT is not a service ticket: proxying one would hand out
	// the right to obtain tickets, not the right to use one.
	if s.req.Body.Options&wire.OptProxy != 0 &&
		isTGSName(*s.req.Body.SName) {
		return wire.ErrCodeBadOption, "CAN'T PROXY TGT"
	}
	return 0, ""
}

// checkTransited evaluates the path the issued ticket will carry and
// decides whether it may claim the path was checked
// (do_tgs_req.c:924-948).
//
// Two things happen here and upstream keeps them apart on purpose.
// The check itself only *sets a flag*: a path it cannot verify is
// logged and the request continues. What refuses the request is the
// separate reject_bad_transit test afterwards, which defaults to true
// (kdc/main.c:305-309) -- so the refusal is policy and the check is
// evidence, and a deployment that turned the policy off would still
// have tickets that said truthfully whether anyone had looked.
//
// The error is KDC_ERR_POLICY, which is what that test answers and
// not the PATH_NOT_ACCEPTED the name of the condition suggests.
//
// KDC_OPT_DISABLE_TRANSITED_CHECK therefore refuses the request under
// the default policy rather than waving it through: skipping the
// check leaves the flag clear, and a clear flag is a refusal.
func (k *KDC) checkTransited(s *tgsState) (int32, string) {
	if s.req.Body.Options&wire.OptDisableTransitedCheck == 0 {
		err := k.Paths.Check(string(s.transited.Contents),
			s.header.CRealm, s.req.Body.Realm)
		s.transitChecked = err == nil
	}
	if !s.transitChecked {
		return wire.ErrCodePolicy, "BAD_TRANSIT"
	}
	return 0, ""
}

// tgsTimes fills in the issued ticket's times, from
// do_tgs_req.c:813-852.
func (k *KDC) tgsTimes(s *tgsState) {
	opts := s.req.Body.Options
	s.flags = tgsTicketFlags(opts, s.server, s.header)
	if s.transitChecked {
		s.flags |= wire.FlagTransitedPolicyChecked
	}
	if opts&wire.OptValidate != 0 {
		validateTimes(s)
		return
	}
	// The authtime is *preserved from the presented ticket*, not
	// set to now: it records when the client last authenticated
	// with a password, which a derived ticket does not change.
	s.authTime = stamp(s.header.AuthTime)
	if opts&wire.OptPostdated != 0 {
		s.start = stamp(s.req.Body.From)
	} else {
		s.start = s.now
	}
	if opts&wire.OptRenew != 0 {
		s.end = renewEndTime(s)
	} else {
		s.end = k.tgsEndTime(s)
	}
	// kdc_get_ticket_renewtime clears TKT_FLG_RENEWABLE before it
	// decides anything (kdc/kdc_util.c:1719), and that clearing
	// is load-bearing for a renewal: the flag arrived already
	// set, copied wholesale from the presented ticket, so without
	// this a request that earns no renew time would still claim
	// to be renewable.
	s.flags &^= wire.FlagRenewable
	s.renew = k.tgsRenewTime(s)
	if s.renew != 0 {
		s.flags |= wire.FlagRenewable
	}
	if s.start == s.authTime {
		s.start = 0
	}
}

// validateTimes handles KDC_OPT_VALIDATE, which takes the presented
// ticket's times unchanged (do_tgs_req.c:820-824).
//
// It returns before the renew-time calculation and before the
// starttime-equals-authtime rule, and both omissions matter. A
// postdated ticket being validated keeps the starttime that said when
// it became usable -- zeroing it would be the one thing a client
// could not tolerate here -- and its renew time is not recomputed, so
// the RENEWABLE flag survives from the header rather than being
// re-earned.
func validateTimes(s *tgsState) {
	s.authTime = stamp(s.header.AuthTime)
	s.start = stamp(s.header.StartTime)
	s.end = stamp(s.header.EndTime)
	s.renew = stamp(s.header.RenewTill)
}

// renewEndTime handles KDC_OPT_RENEW (do_tgs_req.c:832-836).
//
// The renewed ticket gets the *same lifetime* the presented one had,
// starting now, and is then clamped to the renew-till the original
// carried. So renewing does not extend how long a ticket is good for
// at a stretch, only how far into the future that stretch can sit --
// and the renew-till is a hard wall the client cannot push back.
//
// The request's till is ignored entirely, which is why this is not
// tgsEndTime with different arguments.
func renewEndTime(s *tgsState) uint32 {
	hstart := stamp(s.header.EffectiveStartTime())
	life := tsDelta(stamp(s.header.EndTime), hstart)
	return tsMin(stamp(s.header.RenewTill),
		tsIncr(s.start, life))
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
//
// The enctype is select_session_keytype's: the first entry of the
// *request's* list that the server has a key for
// (kdc/kdc_util.c:1085-1111). It is emphatically not the server's
// first key -- that is what seals the ticket, and the two differ as
// soon as a realm holds more than one enctype. Reading it from the
// server's key was this implementation's bug until the aes-sha2
// family arrived and the differential harness caught it.
func (k *KDC) tgsSessionKey(s *tgsState) (int32, string) {
	// User-to-user overrides the ordinary selection, for the
	// reason u2uSessionEType gives.
	e, code, status := u2uSessionEType(s)
	if code != 0 {
		return code, status
	}
	if e != 0 {
		key, err := randomKey(e)
		if err != nil {
			return wire.ErrCodeGeneric, "MAKE_SESSION_KEY"
		}
		s.session = wire.EncryptionKey{
			KeyType: int32(e), KeyValue: key,
		}
		return 0, ""
	}
	key, e, err := k.makeSessionKey(
		s.req.Body.EType, s.server, s.serverEType)
	if err != nil {
		return wire.ErrCodeGeneric, "MAKE_SESSION_KEY"
	}
	s.session = wire.EncryptionKey{
		KeyType:  int32(e),
		KeyValue: key,
	}
	return 0, ""
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
