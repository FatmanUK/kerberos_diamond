package golden

import (
	"context"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// addresses is a HostAddresses holding one IPv4 address, wrapped for
// a KDC-REQ-BODY's [9] field.
//
// Neither KDC reads them, so one well-formed value is enough to
// follow where they go -- and where they go is the whole question: a
// forwarded or proxied ticket takes the request's addresses rather
// than the presented ticket's, and repeats them in the reply.
func addresses(t *testing.T) asn1.RawValue {
	t.Helper()
	inner, err := asn1.Marshal([]struct {
		Type    int    `asn1:"explicit,tag:0"`
		Address []byte `asn1:"explicit,tag:1"`
	}{{Type: 2, Address: []byte{10, 0, 0, 7}}})
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        9,
		IsCompound: true,
		Bytes:      inner,
		FullBytes: append(
			[]byte{0xA9, byte(len(inner))}, inner...),
	}
}

// delegatedRequest builds a TGS-REQ carrying one of the two
// address-moving options and a set of addresses to move.
//
// The server named is the presented ticket's own, because that is
// what these options mean: check_tgs_nontgt refuses a forwarded or
// proxied request that asks for anything else (tgs_policy.c:632-647).
// So a forwarded request presents a TGT and asks for a TGT -- the
// credentials a client delegates -- and a proxied one presents a
// service ticket and asks for the same service at another address.
func delegatedRequest(
	t *testing.T,
	g tgt,
	opt wire.Flags,
	name wire.PrincipalName,
	addrs asn1.RawValue,
	till time.Time,
) []byte {
	t.Helper()
	return signTGSReq(t, g, wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptProxiable |
			wire.OptRenewableOK | opt,
		Realm:     Realm,
		SName:     &name,
		Till:      till,
		Nonce:     0x5A,
		Addresses: addrs,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	})
}

// openDelegated is openTGS with the ticket's sealing principal named,
// because a forwarded ticket is sealed with the krbtgt's key and a
// proxied one with the service's.
func openDelegated(
	t *testing.T,
	raw []byte,
	g tgt,
	password string,
	components []string,
) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decrypt(t, rep.Ticket.EncPart, password, components,
		crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// krbtgtName is the ticket-granting service of this realm, which is
// what a forwarded request asks for.
func krbtgtName() wire.PrincipalName {
	return wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{"krbtgt", Realm},
	}
}

// TestForwardedMatchesTheC is the differential test for forwarding: a
// client delegating its credentials asks for a second TGT carrying
// the addresses of the host it is delegating to.
func TestForwardedMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, _ := getTGTFromTheC(t, ctx, o)
	addrs := addresses(t)
	msg := delegatedRequest(t, g, wire.OptForwarded,
		krbtgtName(), addrs, in(2*time.Hour))

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	tgtPrinc := []string{"krbtgt", Realm}
	cx := openDelegated(t, cRaw, g, TgtPassword, tgtPrinc)

	d := diamond(t, "kd_golden_fwd",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openDelegated(t, goRaw, g, TgtPassword, tgtPrinc)

	assertDelegated(t, "oracle", cx, wire.FlagForwarded, addrs)
	assertDelegated(t, "diamond", gx, wire.FlagForwarded, addrs)
	reportDiffs(t, cx, gx)
}

// TestProxiedMatchesTheC is the differential test for proxying, which
// re-addresses a service ticket the client already holds. So the
// setup is an ordinary TGS exchange, and the ticket it returns is
// what gets presented.
func TestProxiedMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, _ := getTGTFromTheC(t, ctx, o)
	held := proxiableServiceTicket(t, ctx, o, g)
	addrs := addresses(t)
	name := wire.PrincipalName{
		Type:       wire.NTSrvHst,
		Components: ServiceName,
	}
	msg := delegatedRequest(t, held, wire.OptProxy, name,
		addrs, in(time.Hour))

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openDelegated(t, cRaw, held, ServicePassword,
		ServiceName)

	d := diamond(t, "kd_golden_proxy",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openDelegated(t, goRaw, held, ServicePassword,
		ServiceName)

	assertDelegated(t, "oracle", cx, wire.FlagProxy, addrs)
	assertDelegated(t, "diamond", gx, wire.FlagProxy, addrs)
	reportDiffs(t, cx, gx)
}

// proxiableServiceTicket obtains an ordinary service ticket from the
// C KDC, marked proxiable so that it can be proxied afterwards:
// check_tgs_opts refuses KDC_OPT_PROXY against a ticket without the
// flag (tgsflagrules, tgs_policy.c:65-77).
func proxiableServiceTicket(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	g tgt,
) tgt {
	t.Helper()
	msg := signTGSReq(t, g, wire.KDCReqBody{
		Options: wire.OptProxiable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  in(2 * time.Hour),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	})
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC for a service ticket: %v",
			err)
	}
	x := openTGS(t, raw, g)
	if !x.Tkt.Flags.Has(wire.FlagProxiable) {
		t.Fatal("the setup ticket is not proxiable")
	}
	return tgt{
		ticket:       x.Rep.Ticket,
		session:      x.Enc.Key.KeyValue,
		sessionEType: crypto.EncType(x.Enc.Key.KeyType),
	}
}

// in is a till time a given distance from now, truncated to the
// second because KerberosTime carries none.
func in(d time.Duration) time.Time {
	return time.Now().UTC().Add(d).Truncate(time.Second)
}

// assertDelegated checks the exchange did what the option asks for,
// rather than merely matching the other side.
func assertDelegated(
	t *testing.T,
	side string,
	x Exchange,
	flag wire.Flags,
	addrs asn1.RawValue,
) {
	t.Helper()
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
	if !x.Tkt.Flags.Has(flag) {
		t.Errorf("%s: ticket flags are %v, want %v set",
			side, x.Tkt.Flags, flag)
	}
	if string(x.Tkt.CAddr.Bytes) != string(addrs.Bytes) {
		t.Errorf("%s: ticket addresses are %X, want %X",
			side, x.Tkt.CAddr.Bytes, addrs.Bytes)
	}
	if string(x.Enc.CAddr.Bytes) != string(addrs.Bytes) {
		t.Errorf("%s: reply addresses are %X, want %X",
			side, x.Enc.CAddr.Bytes, addrs.Bytes)
	}
	// The reply's caddr is [11] where the request body's is [9].
	// The bytes inside are identical, so a missing re-tag is
	// invisible in a length comparison and silent at the client:
	// a decoder meeting an unexpected tag treats it as the end of
	// the sequence rather than complaining, and the encrypted
	// padata after it would be lost too.
	if x.Enc.CAddr.Tag != 11 {
		t.Errorf("%s: reply addresses tagged [%d], want [11]",
			side, x.Enc.CAddr.Tag)
	}
}
