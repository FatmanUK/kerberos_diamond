package golden

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// The two KDCs' PACs for an AS exchange are **byte for byte the
// same**, and that is the strongest single assertion in this harness.
//
// It is possible at all because a PAC has no confounder in it: every
// octet is either structure or a keyed checksum over structure. Given
// the same keys, the same client and the same authtime, there is
// nothing left for two implementations to disagree about and still
// agree on -- so unlike every other field here, this one is compared
// as octets and not as a normalised rendering.
//
// **A TGT is the case where it holds.** A service ticket's PAC cannot
// be identical, because its ticket signature covers the encoded
// EncTicketPart and that carries a freshly random session key; all
// four of its checksums therefore differ for a reason that is about
// the ticket and not about the PAC. A ticket-granting ticket has no
// ticket signature at all ([MS-PAC] 2.8.3, by way of
// k5_pac_should_have_ticket_signature, pac.c:580-591), so its PAC
// covers only itself.
//
// What this pins, all at once: the buffer order, every offset and
// length, the implied eight-octet padding, the NT timestamp
// conversion, the UTF-16LE name with no terminating NUL, the
// realm-less unparse, the checksum type chosen for each signature,
// which key signs which, the order the checksums are computed in, and
// that the header is encoded into the data before any of them.
func TestThePACsAreIdentical(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_pac", pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	c := thePAC(t, "oracle", cx)
	g := thePAC(t, "diamond", gx)
	if !bytes.Equal(c, g) {
		t.Errorf("the PACs differ\n oracle:  %s\n"+
			"diamond: %s", pacShape(c), pacShape(g))
	}
}

// thePAC finds the PAC in a ticket's authorization data, insisting
// there is one -- which is the guard against this case passing on two
// absences, the hazard the whole harness runs under.
func thePAC(t *testing.T, side string, x Exchange) []byte {
	t.Helper()
	ad, err := wire.AuthDataOf(x.Tkt.AuthorizationData)
	if err != nil {
		t.Fatalf("%s: the ticket's authdata: %v", side, err)
	}
	for _, d := range ad {
		if d.Type != wire.ADIfRelevant {
			continue
		}
		inner, err := wire.UnmarshalAuthorizationData(d.Data)
		if err != nil {
			continue
		}
		for _, e := range inner {
			if e.Type == wire.ADWin2KPAC {
				return e.Data
			}
		}
	}
	t.Fatalf("%s: the ticket carries no PAC", side)
	return nil
}

// And declining is behaviour too, which t_authdata.py:288-294 tests
// and which every case in this harness relied on until E3.
//
// PA-PAC-REQUEST(false) has to leave the ticket's [10] field absent
// on both sides -- not merely smaller. A KDC that honoured the
// request by issuing an empty PAC, or by issuing one and leaving the
// buffer count at zero, would pass a length comparison and fail here.
func TestDecliningThePACMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	noPAC, err := wire.MarshalPAPACRequest(false)
	if err != nil {
		t.Fatal(err)
	}
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	req.PAData = append(req.PAData, wire.PAData{
		Type: wire.PAPACRequest, Value: noPAC,
	})
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_nopac",
		pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	assertNoAuthData(t, "oracle", cx)
	assertNoAuthData(t, "diamond", gx)
	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	reportDiffs(t, cx, gx)
}

// assertNoAuthData insists a ticket's [10] field is absent, not
// merely small.
func assertNoAuthData(t *testing.T, side string, x Exchange) {
	t.Helper()
	n := len(x.Tkt.AuthorizationData.FullBytes)
	if n != 0 {
		t.Errorf("%s: a declined PAC left %d octets",
			side, n)
	}
}

// The PA-PAC-OPTIONS echo, compared against the C.
//
// The request asks for RBCD **and** for every other bit, so what is
// compared is the mask rather than a pass-through: a KDC that echoed
// the request back would send 0xffffffff and a KDC that honoured only
// what it implements sends 0x10000000. Both sides have to send the
// second, and padataSummary renders this element by its flags rather
// than by its length for exactly that reason -- a KerberosFlags is a
// fixed thirty-two bits, so every possible value is the same number
// of octets.
//
// PA-REQ-ENC-PA-REP goes in too, so the case also pins the *order*:
// the reply checksum, the FAST advertisement, then the echo
// (return_enc_padata, kdc/kdc_preauth.c:1635-1661).
func TestThePACOptionsEchoMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	opts, err := wire.MarshalPAPACOptions(0xFFFFFFFF)
	if err != nil {
		t.Fatal(err)
	}
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	req.PAData = append(req.PAData,
		wire.PAData{Type: wire.PAPACOptions, Value: opts},
		wire.PAData{Type: wire.PAReqEncPARep})
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_pacopts",
		pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	assertEchoedRBCD(t, "oracle", cx)
	assertEchoedRBCD(t, "diamond", gx)
	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	reportDiffs(t, cx, gx)
}

// assertEchoedRBCD insists the echo is there and masked, on each side
// separately -- because two KDCs that both omitted it would agree
// perfectly while testing nothing.
func assertEchoedRBCD(t *testing.T, side string, x Exchange) {
	t.Helper()
	for _, d := range x.Enc.EncPAData {
		if d.Type != wire.PAPACOptions {
			continue
		}
		f, err := wire.UnmarshalPAPACOptions(d.Value)
		if err != nil {
			t.Fatalf("%s: %v", side, err)
		}
		if f != wire.PACOptRBCD {
			t.Errorf("%s: echoed %#08x, want %#08x",
				side, uint32(f),
				uint32(wire.PACOptRBCD))
		}
		return
	}
	t.Errorf("%s: no PA-PAC-OPTIONS in the enc-padata: %v",
		side, x.Enc.EncPAData)
}
