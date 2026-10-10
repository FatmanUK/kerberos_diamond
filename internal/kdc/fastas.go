package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// The AS half of FAST, which differs from the TGS half in exactly one
// thing and it is the interesting one: where the armor key comes
// from.
//
// A TGS request already carries an AP-REQ, so its armor key can be
// derived from that. An AS request carries nothing authenticated at
// all -- that is what it is for -- so the client has to supply a
// *separate* ticket to armor with, as an AP-REQ in the armor field.
// Which means FAST cannot protect the first exchange a client ever
// makes; it protects every exchange after one, and anonymous PKINIT
// is the only way to bootstrap it from nothing.

// findFastAS unwraps a FAST-armored AS request, if this is one.
//
// It runs before anything else in AS, because the inner request is
// what names the client and this KDC has not looked anything up yet.
func (k *KDC) findFastAS(s *asState) (int32, string) {
	pa := findPAData(s.req.PAData, wire.PAFXFast)
	if pa == nil {
		return 0, ""
	}
	ar, err := wire.UnmarshalPAFXFastRequest(pa.Value)
	if err != nil {
		return wire.ErrCodeModified, "DECODE FAST REQUEST"
	}
	// An AS request has no other source of an armor key, so the
	// armor field is mandatory here where it is forbidden on the
	// TGS path. Upstream's wording for its absence names the
	// contradiction: "No armor key but FAST armored request
	// present" (fast_util.c:181-183).
	if ar.Armor.Type == 0 {
		return wire.ErrCodePreauthFailed,
			"NO ARMOR KEY BUT FAST ARMORED REQUEST"
	}
	if ar.Armor.Type != wire.FastArmorAPRequest {
		return wire.ErrCodePreauthFailed,
			"UNKNOWN FAST ARMOR TYPE"
	}
	f, code, status := k.armorFromAPReq(ar.Armor.Value)
	if code != 0 {
		return code, status
	}
	return k.openFastAS(s, f, ar)
}

// armorFromAPReq derives the armor key from the AP-REQ the client put
// in the armor field (armor_ap_request, fast_util.c:35-90).
func (k *KDC) armorFromAPReq(
	der []byte,
) (*fastState, int32, string) {
	ap, err := wire.UnmarshalAPReq(der)
	if err != nil {
		return nil, wire.ErrCodeModified, "DECODE ARMOR APREQ"
	}
	tkt, code, status := k.openArmorTicket(ap)
	if code != 0 {
		return nil, code, status
	}
	sub, code, status := k.armorSubkey(tkt, ap)
	if code != 0 {
		return nil, code, status
	}
	sp, err := crypto.Profile(crypto.EncType(sub.KeyType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp, "SUBKEY ENCTYPE"
	}
	tp, err := crypto.Profile(crypto.EncType(tkt.Key.KeyType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp, "SESSION ENCTYPE"
	}
	armor, err := sp.CF2(sub.KeyValue, "subkeyarmor",
		tp, tkt.Key.KeyValue, "ticketarmor")
	if err != nil {
		return nil, wire.ErrCodeGeneric, "ARMOR KEY"
	}
	return &fastState{armor: armor, p: sp}, 0, ""
}

// openArmorTicket opens the armor ticket and insists it is one this
// realm issued for its own ticket-granting service
// (fast_util.c:56-68).
//
// The check is what stops a client armoring with any ticket it holds.
// A service ticket's session key is known to that service, so
// armoring with one would let the service read a tunnel it has no
// business in -- and worse, mint one of its own.
func (k *KDC) openArmorTicket(
	ap wire.APReq,
) (wire.EncTicketPart, int32, string) {
	var zero wire.EncTicketPart
	if ap.Ticket.Realm != k.Realm {
		return zero, wire.ErrCodeNotUs, "ARMOR TICKET REALM"
	}
	if !isTGSName(ap.Ticket.SName) ||
		ap.Ticket.SName.Components[1] != k.Realm {
		return zero, wire.ErrCodeServerNoMatch,
			"ARMOR TICKET NOT LOCAL TGS"
	}
	key, code, status := k.ticketKey(ap.Ticket)
	if code != 0 {
		return zero, code, status
	}
	tkt, code, status := openTicket(ap.Ticket, key)
	if code != 0 {
		return zero, code, status
	}
	if code, status := k.validateTicketTimes(
		tkt, "ARMOR TICKET"); code != 0 {
		return zero, code, status
	}
	return tkt, 0, ""
}

// armorSubkey decrypts the armor AP-REQ's authenticator and returns
// its subkey, which is mandatory (fast_util.c:70-77).
//
// The usage is 11 and not 7: this is an application AP-REQ, not the
// PA-TGS-REQ of a TGS exchange, and upstream reaches it through
// krb5_rd_req rather than through its own TGS path.
//
// Without a subkey the armor key would be the ticket's session key
// alone, which is as old as the ticket and known to anyone who
// recorded the exchange that issued it. Upstream answers POLICY,
// which is right: the request is well formed and simply not good
// enough.
func (k *KDC) armorSubkey(
	tkt wire.EncTicketPart,
	ap wire.APReq,
) (*wire.EncryptionKey, int32, string) {
	p, err := crypto.Profile(crypto.EncType(tkt.Key.KeyType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp, "SESSION ENCTYPE"
	}
	plain, err := p.Decrypt(tkt.Key.KeyValue,
		ap.Authenticator.Cipher, crypto.UsageAPReqAuth)
	if err != nil {
		return nil, wire.ErrCodeBadIntegrity,
			"DECRYPT ARMOR AUTHENTICATOR"
	}
	a, err := wire.UnmarshalAuthenticator(plain)
	if err != nil {
		return nil, wire.ErrCodeModified,
			"DECODE ARMOR AUTHENTICATOR"
	}
	if a.SubKey == nil {
		return nil, wire.ErrCodePolicy,
			"ARMOR AP-REQUEST WITHOUT SUBKEY"
	}
	if !withinSkew(stamp(a.CTime), stamp(k.now()), k.skew()) {
		return nil, wire.ErrCodeSkew, "ARMOR CLOCK SKEW"
	}
	return a.SubKey, 0, ""
}

// openFastAS decrypts the tunnel and substitutes the inner request.
//
// The checksummed data is the *outer* encoded KDC-REQ-BODY
// (do_as_req.c:525-531), which is what wire.ReqBodyBytes extracts
// from the raw request this state already keeps.
func (k *KDC) openFastAS(
	s *asState,
	f *fastState,
	ar wire.KrbFastArmoredReq,
) (int32, string) {
	body, err := wire.ReqBodyBytes(s.raw)
	if err != nil {
		return wire.ErrCodeModified, "NO REQ-BODY"
	}
	fr, code, status := f.openInner(ar, body)
	if code != 0 {
		return code, status
	}
	f.innerBody = fr.BodyDER
	s.fast = f
	s.req.Body = fr.Body
	s.req.PAData = fr.PAData
	return 0, ""
}
