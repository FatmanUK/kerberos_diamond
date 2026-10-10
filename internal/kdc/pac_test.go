package kdc

import (
	"bytes"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/pac"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// keyOf is a principal's long-term key of an enctype, as a keyblock.
func keyOf(
	t *testing.T,
	components []string,
	password string,
	e crypto.EncType,
) wire.EncryptionKey {
	t.Helper()
	return wire.EncryptionKey{
		KeyType:  int32(e),
		KeyValue: clientKey(t, components, password, e),
	}
}

// An AS-issued TGT now carries a PAC, and it verifies under the
// krbtgt key.
//
// A TGT gets **no ticket signature and no full checksum**, because
// [MS-PAC] 2.8.3 excludes a ticket-granting service
// (k5_pac_should_have_ticket_signature, pac.c:580-591) -- so the two
// checksums it has are the server's and the privsvr's, which for a
// TGT are the same key twice.
func TestTheASTicketCarriesAVerifiablePAC(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicket(t, k, rep)
	tgtName := wire.PrincipalName{
		Components: []string{tgsName, testRealm}}
	key := keyOf(t, []string{tgsName, testRealm},
		"tgtpassword",
		crypto.EncType(rep.Ticket.EncPart.EType))
	p, err := pac.VerifyTicket(&tkt, tgtName, key, key)
	if err != nil {
		t.Fatalf("the PAC does not verify: %v", err)
	}
	if p == nil {
		t.Fatal("the TGT carries no PAC")
	}
	if _, err := p.Get(pac.TypeTicketChecksum); err == nil {
		t.Error("a TGT carries a ticket signature")
	}
	if _, err := p.Get(pac.TypeFullChecksum); err == nil {
		t.Error("a TGT carries a full checksum")
	}
	assertClientInfo(t, p, "user", tkt.AuthTime)
}

// A service ticket carries a PAC with all four checksums, and the
// ticket signature is the one that proves the PAC belongs to *this*
// ticket -- it is a checksum over the encoded EncTicketPart, so it
// cannot be lifted into another.
func TestTheServiceTicketCarriesAFullPAC(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	srv := wire.PrincipalName{Components: serviceName}
	key := keyOf(t, serviceName, "servicepassword",
		crypto.EncType(rep.Ticket.EncPart.EType))
	tgtKey := keyOf(t, []string{tgsName, testRealm},
		"tgtpassword", crypto.AES256CTSHMACSHA196)
	p, err := pac.VerifyTicket(&tkt, srv, key, tgtKey)
	if err != nil {
		t.Fatalf("the PAC does not verify: %v", err)
	}
	for _, typ := range []uint32{pac.TypeServerChecksum,
		pac.TypePrivsvrChecksum, pac.TypeTicketChecksum,
		pac.TypeFullChecksum} {
		if _, err := p.Get(typ); err != nil {
			t.Errorf("type %d: %v", typ, err)
		}
	}
	// The client info was **copied** from the TGT's PAC, so it
	// still names the client and carries the *original* authtime.
	assertClientInfo(t, p, "user", tkt.AuthTime)
}

// assertClientInfo checks the CLIENT_INFO buffer names a client
// without its realm, which is the rule for every PAC but a
// cross-realm S4U referral's.
func assertClientInfo(
	t *testing.T,
	p *pac.PAC,
	name string,
	authTime time.Time,
) {
	t.Helper()
	ci, err := p.ClientInfo()
	if err != nil {
		t.Fatal(err)
	}
	if ci.Name != name {
		t.Errorf("client info names %q, want %q",
			ci.Name, name)
	}
	// The authtime has to match the ticket's, because
	// VerifyClientInfo compares both and a PAC lifted out of one
	// ticket into another is exactly a PAC whose authtime is
	// somebody else's.
	if !ci.AuthTime.Equal(authTime) {
		t.Errorf("client info is at %v, want %v",
			ci.AuthTime, authTime)
	}
}

// The realm can turn the PAC off, which is kdc.conf's disable_pac
// (handle_pac's second test, kdc_authdata.c:485).
func TestDisablePACLeavesTheTicketEmpty(t *testing.T) {
	k := testKDC(t)
	k.DisablePAC = true
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicket(t, k, rep)
	if len(tkt.AuthorizationData.FullBytes) != 0 {
		t.Errorf("a disabled PAC travelled: % x",
			tkt.AuthorizationData.FullBytes)
	}
}

// KRB5_KDB_NO_AUTH_DATA_REQUIRED on the *server* turns off everything
// the KDC would vouch for -- the PAC and the authentication
// indicators both -- which is handle_pac's first test and the reason
// it returns before add_auth_indicators (kdc_authdata.c:479-481).
func TestNoAuthDataRequiredSuppressesThePAC(t *testing.T) {
	k := testKDC(t)
	k.SPAKEIndicators = []string{"strong"}
	addService(t, k, store.AttrNoAuthDataRequired)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if len(tkt.AuthorizationData.FullBytes) != 0 {
		t.Errorf("the server disabled authdata and got % x",
			tkt.AuthorizationData.FullBytes)
	}
}

// A client that declined a PAC at the AS exchange gets none in any
// service ticket either, because a TGS request can neither ask for
// one nor decline one: what decides it is whether the presented
// ticket carried one (:488-489).
//
// This is the property every golden case relies on.
func TestADeclinedPACDoesNotComeBackAtTheTGS(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	noPAC, err := wire.MarshalPAPACRequest(false)
	if err != nil {
		t.Fatal(err)
	}
	req := asRequest([]string{"user"})
	req.PAData = append(req.PAData, wire.PAData{
		Type: wire.PAPACRequest, Value: noPAC,
	})
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	msg, treq := tgsRequest(t, rep.Ticket, enc.Key.KeyValue,
		serviceName, nil)
	srep, kerr := k.TGS(msg, treq)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := openServiceTicket(t, srep)
	if len(tkt.AuthorizationData.FullBytes) != 0 {
		t.Errorf("a PAC appeared at the TGS: % x",
			tkt.AuthorizationData.FullBytes)
	}
}

// PA-PAC-REQUEST defaults to **yes**, three times over: no padata at
// all, padata without the element, and an element that fails to
// decode (include_pac_p, kdc_preauth.c:1587 and :1598-1602 -- the
// answer is initialised TRUE and only a successful decode overwrites
// it). So declining is something a client has to do correctly on
// purpose.
func TestPACRequestDefaultsToYes(t *testing.T) {
	yes, err := wire.MarshalPAPACRequest(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		why  string
		pa   []wire.PAData
		want bool
	}{
		{"no padata at all", nil, true},
		{"padata without the element", []wire.PAData{
			{Type: wire.PAEncTimestamp}}, true},
		{"an element that will not decode",
			[]wire.PAData{{Type: wire.PAPACRequest,
				Value: []byte{0xFF}}}, true},
		{"an explicit yes",
			[]wire.PAData{{Type: wire.PAPACRequest,
				Value: yes}}, true},
	} {
		if got := includePAC(c.pa); got != c.want {
			t.Errorf("%s: %v, want %v",
				c.why, got, c.want)
		}
	}
}

// A client that rewrites the name in its own PAC is refused.
//
// That is the attack the server signature exists to stop, and the
// signature on a TGT's PAC was made with the **krbtgt** key -- so the
// client holding the ticket cannot recompute it. This is what makes a
// payload-free PAC worth signing at all: S4U2Self believes the header
// ticket's PAC about who the requester is.
//
// Note what is *not* checked on a TGT: only the server signature is,
// privsvr left out entirely (get_verified_pac, kdc_util.c:601-605),
// and verification zeroes both checksum buffers before comparing. So
// a change inside the privsvr checksum's own octets is invisible here
// -- correctly, because that checksum is recomputed when the PAC is
// re-signed and nothing downstream reads the old one.
func TestARewrittenHeaderPACIsRefused(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	tampered := tamperTGTPAC(t, k, tgt)
	msg, req := tgsRequest(t, tampered, session,
		serviceName, nil)
	if _, kerr := k.TGS(msg, req); kerr == nil {
		t.Error("a rewritten PAC was accepted")
	}
}

// The name a CLIENT_INFO buffer carries leaves '@' **unescaped** when
// there is no realm, because that is what
// KRB5_PRINCIPAL_UNPARSE_NO_REALM does (component_length_quoted,
// lib/krb5/krb/unparse.c:70-78).
//
// It reads as a bug and is not: with no realm separator in the string
// there is nothing for an interior at sign to be confused with, and
// an enterprise name is exactly a principal whose one component
// contains one. Escaping it produces a PAC a Windows service rejects.
func TestClientInfoNameQuoting(t *testing.T) {
	for _, c := range []struct {
		components []string
		realm      string
		want       string
	}{
		{[]string{"user"}, "", "user"},
		{[]string{"user"}, "R", "user@R"},
		{[]string{"w2k8u@abc"}, "", "w2k8u@abc"},
		{[]string{"w2k8u@abc"}, "ACME.COM",
			`w2k8u\@abc@ACME.COM`},
		{[]string{"host", "a.b"}, "", "host/a.b"},
		{[]string{"a/b"}, "", `a\/b`},
	} {
		got := clientInfoName(wire.PrincipalName{
			Components: c.components}, c.realm)
		if got != c.want {
			t.Errorf("%v in %q: %q, want %q",
				c.components, c.realm, got, c.want)
		}
	}
}

// tamperTGTPAC re-seals a TGT with one octet of its PAC changed,
// which is the only way to get a bad PAC past the client side: the
// signature is keyed with the krbtgt key, so a test has to hold that
// key to produce one.
func tamperTGTPAC(
	t *testing.T,
	k *KDC,
	tgt wire.Ticket,
) wire.Ticket {
	t.Helper()
	e := crypto.EncType(tgt.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, []string{tgsName, testRealm},
		"tgtpassword", e)
	plain, err := p.Decrypt(key, tgt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	part, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	flipPACOctet(t, &part)
	out, err := wire.MarshalEncTicketPart(part)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(key, out, crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	tgt.EncPart.Cipher = ct
	return tgt
}

// flipPACOctet rewrites the client name inside the ticket's PAC,
// leaving everything around it alone.
//
// It finds the name by searching for its UTF-16LE encoding rather
// than by offset, so the case does not depend on where the
// CLIENT_INFO buffer happens to land.
func flipPACOctet(t *testing.T, part *wire.EncTicketPart) {
	t.Helper()
	ad, err := wire.AuthDataOf(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range ad {
		if d.Type != wire.ADIfRelevant || !hasPAC(t, d) {
			continue
		}
		inner, err := wire.UnmarshalAuthorizationData(d.Data)
		if err != nil {
			t.Fatal(err)
		}
		rewriteName(t, inner[0].Data)
		der, err := wire.MarshalAuthorizationData(inner)
		if err != nil {
			t.Fatal(err)
		}
		ad[i].Data = der
		field, err := wire.AuthDataField(ad)
		if err != nil {
			t.Fatal(err)
		}
		part.AuthorizationData = field
		return
	}
	t.Fatal("the TGT carries no PAC to tamper with")
}

// rewriteName changes "user" to "uses" in a PAC's CLIENT_INFO buffer,
// in place and keeping its length.
func rewriteName(t *testing.T, data []byte) {
	t.Helper()
	want := []byte("u\x00s\x00e\x00r\x00")
	at := bytes.Index(data, want)
	if at < 0 {
		t.Fatal("the PAC does not name the client")
	}
	data[at+6] = 's'
}
