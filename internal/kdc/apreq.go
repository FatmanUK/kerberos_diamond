package kdc

import (
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// The administrative service names (lib/kadm5/admin.h:64-67).
//
// kadmin/admin is what a remote administrator asks for and
// kadmin/changepw what a user changing its own password asks for.
// kadmin/<fqdn> authenticates too, which is how a host with no
// kadmin/admin entry of its own still reaches the surface
// (client_init.c:411-421 falls back to it, and
// tests/t_kadmin_acl.py:429-442 asserts the server accepts it).
const (
	adminName   = "kadmin"
	historyName = "history"
)

// Identity is who an AP-REQ proved itself to be, and what a caller
// has to act on besides the name.
type Identity struct {
	// CRealm and CName are the authenticated client.
	CRealm string
	CName  wire.PrincipalName

	// Service is the principal the client authenticated *to*,
	// which an administrative surface reads as well as the
	// client's own name: upstream forbids a client that arrived
	// on kadmin/changepw from touching anybody else
	// (changepw_not_self, kadmin/server/server_stubs.c:345-354).
	Service wire.PrincipalName

	// Initial reports TKT_FLG_INITIAL, which is the ticket saying
	// its holder typed a password rather than presenting another
	// ticket. Upstream requires it for a self key change
	// (check_self_keychange, server_stubs.c:369-381), and
	// t_kadmin_acl.py:413-427 asserts the requirement.
	Initial bool

	// SubKey is the authenticator's subkey when it sent one, and
	// Seq its sequence number, zero meaning absent. Neither is
	// required here and both are carried for the caller.
	//
	// The sequence number is the replay defence that upstream's
	// own password-change service relies on
	// (KRB5_AUTH_CONTEXT_DO_SEQUENCE, schpw.c:106), and nothing
	// in this package can check it: a replay cache is per-process
	// state, which the crash-only rule forbids outright. So it is
	// handed over rather than skipped, and what makes that
	// tolerable is the transport -- an AP-REQ an attacker never
	// saw cannot be replayed, and this KDC has no cleartext
	// listener to see it on.
	SubKey *wire.EncryptionKey
	Seq    uint32

	// CTime and CUsec are the authenticator's own clock, which a
	// reply has to echo back exactly: that echo *is* mutual
	// authentication, and krb5_rd_rep answers KRB5_MUTUAL_FAILED
	// if either differs (rd_rep.c:106-110). The server's own
	// clock does not come into it.
	CTime time.Time
	CUsec int32

	// MutualRequired reports AP_OPTS_MUTUAL_REQUIRED, which is
	// the client asking to be told the server holds the key too.
	// Whether to answer is the caller's: krb5_rd_req neither
	// honours nor refuses it.
	MutualRequired bool

	// Cksum is the authenticator's checksum field as it arrived,
	// unverified and uninterpreted. Nothing in this package can
	// check it -- openAdminAuth says why -- and for a GSS client
	// it is not a checksum at all but the 0x8003 structure of
	// channel bindings and context flags, which the negotiation
	// layer reads. Absent for a client that sent none, which
	// upstream tolerates (accept_sec_context.c:487-493).
	Cksum *wire.Checksum

	// Session is the ticket's session key, which a caller that
	// replies cannot do without: an AP-REP and a KRB-PRIV are
	// both sealed with it, or with SubKey when the client sent
	// one. Upstream's equivalent is the auth context, which holds
	// both and picks between them per direction (krb5_rd_priv
	// uses recv_subkey when it is set).
	Session wire.EncryptionKey
}

// ReplyKey is the key a reply to this AP-REQ is sealed with: the
// authenticator's subkey when it sent one, and the ticket's session
// key otherwise.
func (i *Identity) ReplyKey() wire.EncryptionKey {
	if i.SubKey != nil {
		return *i.SubKey
	}
	return i.Session
}

// Name is the client fully qualified, which is the form an access
// control list matches and the form a log line wants.
func (i *Identity) Name() string {
	return store.UnparseName(i.CRealm, i.CName.Components)
}

// AcceptAPReq verifies an AP-REQ addressed to one of this realm's
// administrative services and reports who sent it.
//
// This is the acceptor half of an *application* exchange rather than
// of a KDC exchange, which is why it is not readAPReq: there is no
// KDC-REQ-BODY to checksum, the key usage is 11 and not 7, and the
// service is not this realm's ticket-granting service. What it does
// share is everything that opens a ticket -- ticketKey and
// openTicket, which have been free of TGS state since the FAST armor
// path reused them.
//
// Upstream reaches the same place through GSS-API and RPCSEC_GSS, and
// does so by accepting *anything*: the acceptor name is GSS_C_NO_NAME
// (ovsec_kadmd.c:494), so a ticket for any principal in the database
// authenticates, and a gate afterwards narrows it (check_rpcsec_auth,
// kadm_rpc_svc.c:318-331). The gate is what is reproduced here.
// Accepting every principal and then narrowing is an artefact of
// going through GSS and not a property worth copying.
func (k *KDC) AcceptAPReq(der []byte) (*Identity, *wire.KRBError) {
	id, code, status := k.acceptAPReq(der)
	if code != 0 {
		return nil, k.krbError(code, status, nil)
	}
	return id, nil
}

// acceptAPReq is AcceptAPReq in this package's own error style.
func (k *KDC) acceptAPReq(
	der []byte,
) (*Identity, int32, string) {
	ap, err := wire.UnmarshalAPReq(der)
	if err != nil {
		return nil, wire.ErrCodeModified, "DECODE AP-REQ"
	}
	// A session-key ticket is a user-to-user ticket, sealed with
	// a key out of a second ticket this surface has not been
	// given and has no use for. Mutual authentication is *not*
	// refused: an application client is entitled to ask for an
	// AP-REP, and whether one is sent is the caller's business.
	if ap.Options&wire.APOptUseSessionKey != 0 {
		return nil, wire.ErrCodePolicy, "ADMIN SESSION KEY"
	}
	if code, status := k.adminService(ap.Ticket); code != 0 {
		return nil, code, status
	}
	tkt, code, status := k.openAdminTicket(ap)
	if code != 0 {
		return nil, code, status
	}
	a, code, status := k.openAdminAuth(tkt, ap)
	if code != 0 {
		return nil, code, status
	}
	return identityOf(ap, tkt, a), 0, ""
}

// identityOf assembles what the three checks above established.
func identityOf(
	ap wire.APReq,
	tkt wire.EncTicketPart,
	a wire.Authenticator,
) *Identity {
	return &Identity{
		CRealm:  tkt.CRealm,
		CName:   tkt.CName,
		Service: ap.Ticket.SName,
		Initial: tkt.Flags.Has(wire.FlagInitial),
		MutualRequired: ap.Options&
			wire.APOptMutualRequired != 0,

		SubKey:  a.SubKey,
		Seq:     a.SeqNumber,
		CTime:   a.CTime,
		CUsec:   a.CUsec,
		Cksum:   a.Cksum,
		Session: tkt.Key,
	}
}

// adminService is check_rpcsec_auth's own check
// (kadm_rpc_svc.c:318-331): the ticket has to name an administrative
// service of this realm.
//
// Upstream says in a comment why the check exists at all: "Since we
// accept with GSS_C_NO_NAME, the client can authenticate against the
// entire kdb. Therefore, ensure that the service name is something
// reasonable." Exactly two components, this realm, "kadmin" first --
// and not "history" second, which is the one exclusion and the one
// worth understanding: kadmin/history's key is what every stored
// password-history entry is sealed with, so a client holding a ticket
// to it would be talking to the thing that can read them.
func (k *KDC) adminService(tkt wire.Ticket) (int32, string) {
	if tkt.Realm != k.Realm {
		return wire.ErrCodeNotUs, "ADMIN TICKET REALM"
	}
	c := tkt.SName.Components
	if len(c) != 2 || c[0] != adminName {
		return wire.ErrCodeServerNoMatch,
			"NOT AN ADMIN SERVICE"
	}
	if c[1] == historyName {
		return wire.ErrCodeServerNoMatch,
			"ADMIN HISTORY SERVICE"
	}
	return 0, ""
}

// openAdminTicket opens the ticket and then checks the things
// upstream's krb5_rd_req leaves to its caller.
//
// Found while writing this: krb5_rd_req checks the authenticator's
// clock skew and the ticket's INVALID flag (rd_req_dec.c:631-637) and
// **nothing about the ticket's validity interval at all**. An expired
// ticket opens cleanly; the GSS layer stores the end time as the
// security context's lifetime (accept_sec_context.c:346) and leaves
// the application to notice. That is reasonable for a long-lived
// context and wrong for a surface that provisions principals, so the
// interval is checked here -- which is the choice openArmorTicket
// already made for the FAST armor ticket.
func (k *KDC) openAdminTicket(
	ap wire.APReq,
) (wire.EncTicketPart, int32, string) {
	var zero wire.EncTicketPart
	key, code, status := k.ticketKey(ap.Ticket)
	if code != 0 {
		return zero, code, status
	}
	tkt, code, status := openTicket(ap.Ticket, key)
	if code != 0 {
		return zero, code, status
	}
	now := stamp(k.now())
	if tsAfter(now, stamp(tkt.EndTime)) {
		return zero, wire.ErrCodeTktExpired,
			"ADMIN TICKET EXPIRED"
	}
	// An INVALID ticket is postdated and not yet validated, and a
	// start time still ahead is the same condition said the other
	// way round. The TGS path answers TKT_NYV for the first
	// (checkTGSOpts, tgspolicy.go:51-54) and this agrees with it.
	if tkt.Flags.Has(wire.FlagInvalid) ||
		tsAfter(stamp(tkt.StartTime), now) {
		return zero, wire.ErrCodeTktNYV,
			"ADMIN TICKET NOT VALID"
	}
	return tkt, 0, ""
}

// openAdminAuth decrypts the authenticator under the ticket's session
// key at usage 11.
//
// Eleven and not seven: this is an application AP-REQ, which upstream
// reaches through krb5_rd_req, and not the PA-TGS-REQ of a TGS
// exchange. armorSubkey already drew the same distinction for FAST
// armor (fast_util.c:70-77).
//
// And there is deliberately no checksum check here, where
// openAuthenticator ends with one. checkBodyCksum needs the raw
// request to *be* a KDC-REQ so that wire.ReqBodyBytes can find a body
// in it, and an application AP-REQ has no such body; its cksum field
// holds whatever the application chose, which for a GSS client is the
// 0x8003 structure of channel bindings and flags and is not a keyed
// hash at all. Binding a request to its authenticator is the caller's
// problem and cannot be solved from here.
func (k *KDC) openAdminAuth(
	tkt wire.EncTicketPart,
	ap wire.APReq,
) (wire.Authenticator, int32, string) {
	var zero wire.Authenticator
	p, err := crypto.Profile(crypto.EncType(tkt.Key.KeyType))
	if err != nil {
		return zero, wire.ErrCodeETypeNoSupp,
			"ADMIN SESSION ENCTYPE"
	}
	plain, err := p.Decrypt(tkt.Key.KeyValue,
		ap.Authenticator.Cipher, crypto.UsageAPReqAuth)
	if err != nil {
		return zero, wire.ErrCodeBadIntegrity,
			"DECRYPT ADMIN AUTHENTICATOR"
	}
	a, err := wire.UnmarshalAuthenticator(plain)
	if err != nil {
		return zero, wire.ErrCodeModified,
			"DECODE ADMIN AUTHENTICATOR"
	}
	// Two different things, and the pair is the whole of the
	// authentication: the decryption above says the sender holds
	// the session key, and this says the name it claims is the
	// name the KDC sealed into the ticket.
	if a.CRealm != tkt.CRealm || !a.CName.Equal(tkt.CName) {
		return zero, wire.ErrCodeBadMatch,
			"ADMIN AUTHENTICATOR CLIENT"
	}
	if !withinSkew(stamp(a.CTime), stamp(k.now()), k.skew()) {
		return zero, wire.ErrCodeSkew, "ADMIN CLOCK SKEW"
	}
	return a, 0, ""
}
