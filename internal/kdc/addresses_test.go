package kdc

import (
	"encoding/asn1"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// hostAddresses is a HostAddresses SEQUENCE holding one IPv4 address,
// wrapped for the request body's [9] addresses field. The KDC does
// not read them, so one well-formed value is enough to follow where
// they go.
func hostAddresses(t *testing.T) asn1.RawValue {
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

// tgsName2 is the ticket-granting service as a request names it,
// which is what a forwarded request asks for: forwarding delegates
// credentials, so the thing asked for is another TGT.
var tgsComponents = []string{tgsName, testRealm}

// A forwarded ticket is for use from somewhere else, so its addresses
// come from the request rather than from the ticket presented -- and
// the reply repeats them, because they are the one thing the client
// did not already have in hand (do_tgs_req.c:1019-1023).
func TestForwardedTicketTakesTheRequestsAddresses(t *testing.T) {
	k := testKDC(t)
	tgt, session := getTGT(t, k)
	addrs := hostAddresses(t)

	msg, req := tgsRequest(t, tgt, session, tgsComponents,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptForwarded
			b.Addresses = addrs
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := decodeTicketWith(t, rep.Ticket, "tgtpassword",
		tgsComponents)
	if string(tkt.CAddr.Bytes) != string(addrs.Bytes) {
		t.Errorf("ticket addresses are %X, want %X",
			tkt.CAddr.Bytes, addrs.Bytes)
	}
	if !tkt.Flags.Has(wire.FlagForwarded) {
		t.Error("the forwarded flag is not set")
	}
	enc := openTGSRep(t, rep, session)
	if string(enc.CAddr.Bytes) != string(addrs.Bytes) {
		t.Errorf("reply addresses are %X, want %X",
			enc.CAddr.Bytes, addrs.Bytes)
	}
	// The tag is the reply's, not the request body's: [11] where
	// the body carries [9]. A client decoding a [9] here would
	// stop reading the sequence and lose the encrypted padata
	// too.
	if enc.CAddr.Tag != 11 {
		t.Errorf("reply addresses are tagged [%d], want [11]",
			enc.CAddr.Tag)
	}
}

// Proxying re-addresses a ticket the client already holds, so it
// presents a service ticket rather than a TGT and asks for the same
// service again.
func TestProxiedTicketTakesTheRequestsAddresses(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	held, session := proxiableTicket(t, k)
	addrs := hostAddresses(t)

	msg, req := tgsRequest(t, held, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptProxy
			b.Addresses = addrs
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if string(tkt.CAddr.Bytes) != string(addrs.Bytes) {
		t.Errorf("ticket addresses are %X, want %X",
			tkt.CAddr.Bytes, addrs.Bytes)
	}
	if !tkt.Flags.Has(wire.FlagProxy) {
		t.Error("the proxy flag is not set")
	}
}

// A ticket-granting ticket cannot be proxied: proxying one would hand
// out the right to obtain tickets rather than the right to use one
// (check_tgs_nontgt, tgs_policy.c:640-645).
func TestProxyingATGTIsRefused(t *testing.T) {
	k := testKDC(t)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, tgsComponents,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptProxiable | wire.OptProxy
			b.Addresses = hostAddresses(t)
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("proxied a ticket-granting ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION", kerr.ErrorCode)
	}
}

// All four of the non-TGT options hand back the ticket presented, so
// the request has to name the same server it does. Upstream applies
// this to forwarding and proxying as well as to renewal and
// validation, which this implementation at first did not.
func TestForwardedMustNameTheTicketsServer(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptForwarded
			b.Addresses = hostAddresses(t)
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("forwarded a ticket to a different server")
	}
	if kerr.ErrorCode != wire.ErrCodeServerNoMatch {
		t.Errorf("code %d, want SERVER_NOMATCH",
			kerr.ErrorCode)
	}
}

// An ordinary request must present a ticket-granting ticket. Without
// the check any service ticket would do -- one the client obtained
// earlier for something unrelated -- and the KDC would derive a
// ticket to somewhere else from it (check_tgs_tgt,
// tgs_policy.c:653-665).
func TestOrdinaryRequestNeedsATGT(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	held, session := proxiableTicket(t, k)

	msg, req := tgsRequest(t, held, session, serviceName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted a service ticket as a TGT")
	}
	if kerr.ErrorCode != wire.ErrCodeNotUs {
		t.Errorf("code %d, want NOT_US", kerr.ErrorCode)
	}
}

// An ordinary request takes the presented ticket's addresses and the
// reply says nothing about them, because the client already knows
// what it asked for.
func TestOrdinaryRequestLeavesTheReplyAddressless(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Addresses = hostAddresses(t)
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	header := headerOf(t, tgt)
	if string(tkt.CAddr.FullBytes) !=
		string(header.CAddr.FullBytes) {
		t.Error("the ticket did not take the TGT's addresses")
	}
	enc := openTGSRep(t, rep, session)
	if enc.CAddr.FullBytes != nil {
		t.Errorf("the reply carries addresses: %X",
			enc.CAddr.FullBytes)
	}
}

// A forwarded request with no addresses at all must not put an empty
// field on the wire: a zero RawValue has to stay absent, not become a
// two-byte stub that nothing can decode.
func TestForwardedWithNoAddressesStaysAbsent(t *testing.T) {
	k := testKDC(t)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, tgsComponents,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptForwarded
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := decodeTicketWith(t, rep.Ticket, "tgtpassword",
		tgsComponents)
	if tkt.CAddr.FullBytes != nil {
		t.Errorf("ticket addresses are %X",
			tkt.CAddr.FullBytes)
	}
	enc := openTGSRep(t, rep, session)
	if enc.CAddr.FullBytes != nil {
		t.Errorf("reply addresses are %X",
			enc.CAddr.FullBytes)
	}
}

// proxiableTicket obtains a service ticket marked proxiable, which is
// what a proxy request re-addresses. checkTGSOpts refuses
// KDC_OPT_PROXY against a ticket without the flag.
func proxiableTicket(
	t *testing.T,
	k *KDC,
) (wire.Ticket, []byte) {
	t.Helper()
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptProxiable
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("obtaining a proxiable ticket: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	if !enc.Flags.Has(wire.FlagProxiable) {
		t.Fatal("the setup ticket is not proxiable")
	}
	return rep.Ticket, enc.Key.KeyValue
}
