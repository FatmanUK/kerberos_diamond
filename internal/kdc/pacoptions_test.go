package kdc

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// pacOptions builds a PA-PAC-OPTIONS element with the given flags.
func pacOptions(t *testing.T, f wire.Flags) []wire.PAData {
	t.Helper()
	der, err := wire.MarshalPAPACOptions(f)
	if err != nil {
		t.Fatal(err)
	}
	return []wire.PAData{
		{Type: wire.PAPACOptions, Value: der},
	}
}

// The echo is masked down to the one bit MIT implements, and the
// element is **suppressed entirely** when nothing survives
// (kdc_add_pa_pac_options, kdc/kdc_util.c:1839-1843).
//
// Suppression rather than an empty element is the interesting half:
// it is what distinguishes "I do not honour anything you asked for"
// from "I honour this, and the bit happens to be zero".
func TestThePACOptionsEchoIsMasked(t *testing.T) {
	for _, c := range []struct {
		why  string
		ask  wire.Flags
		want wire.Flags
		echo bool
	}{
		{"RBCD alone", wire.PACOptRBCD,
			wire.PACOptRBCD, true},
		{"RBCD and everything else", 0xFFFFFFFF,
			wire.PACOptRBCD, true},
		{"nothing at all", 0, 0, false},
		// Claims, branch-aware and forward-to-full-DC are the
		// three [MS-KILE] bits beside RBCD, and MIT does not
		// name any of them anywhere -- so a client asking for
		// one is told nothing rather than told no.
		{"only bits MIT does not name", 0x0FFFFFFF,
			0, false},
	} {
		got := pacOptionsEcho(pacOptions(t, c.ask))
		if (got != nil) != c.echo {
			t.Errorf("%s: echo %v, want %v",
				c.why, got != nil, c.echo)
			continue
		}
		if got == nil {
			continue
		}
		f, err := wire.UnmarshalPAPACOptions(got.Value)
		if err != nil {
			t.Fatal(err)
		}
		if f != c.want {
			t.Errorf("%s: echoed %#08x, want %#08x",
				c.why, uint32(f), uint32(c.want))
		}
	}
}

// No PA-PAC-OPTIONS in the request means no echo, which is the
// ordinary case: a stock kinit sends none.
func TestNoPACOptionsMeansNoEcho(t *testing.T) {
	if pacOptionsEcho(nil) != nil {
		t.Error("an absent element produced an echo")
	}
	if pacOptionsEcho([]wire.PAData{
		{Type: wire.PAEncTimestamp},
	}) != nil {
		t.Error("an unrelated element produced an echo")
	}
}

// **A malformed element is not an error here, and upstream's is.**
//
// kdc_get_pa_pac_options propagates a decode failure, so a stock KDC
// refuses the whole request over an unreadable PA-PAC-OPTIONS. This
// returns no echo and issues the ticket, because the element carries
// no instruction a KDC has to obey -- it is a capability
// announcement, and the right answer to one that cannot be read is to
// announce nothing back rather than to refuse an authentication.
//
// Recorded as a divergence rather than copied. It is the one place in
// this phase where this project is deliberately more permissive than
// the C, and the test says so.
func TestAMalformedPACOptionsIsIgnored(t *testing.T) {
	if pacOptionsEcho([]wire.PAData{{
		Type: wire.PAPACOptions, Value: []byte{0xFF},
	}}) != nil {
		t.Error("a malformed element produced an echo")
	}
}

// supportsRBCD is the other reader of the same element, and the one
// E6 will use. Nothing calls it yet, so this is what keeps it honest.
func TestSupportsRBCD(t *testing.T) {
	for _, c := range []struct {
		why  string
		pa   []wire.PAData
		want bool
	}{
		{"absent", nil, false},
		{"RBCD set", pacOptions(t, wire.PACOptRBCD), true},
		{"other bits only", pacOptions(t, 0x0F000000),
			false},
		{"malformed", []wire.PAData{{
			Type: wire.PAPACOptions, Value: []byte{1},
		}}, false},
	} {
		if got := supportsRBCD(c.pa); got != c.want {
			t.Errorf("%s: %v, want %v",
				c.why, got, c.want)
		}
	}
}

// And the echo reaches the reply's **encrypted** padata, which is
// where it has to be: a client has to know the answer came from
// something holding the reply key.
//
// It also has to arrive without a PA-REQ-ENC-PA-REP in the request,
// which is the structural point of this step. return_enc_padata calls
// the negotiation handler and then kdc_add_pa_pac_options
// (kdc_preauth.c:1648-1657), and the second does not care whether the
// first produced anything -- so this KDC's enc-padata could no longer
// be one function that returns early.
func TestThePACOptionsEchoTravelsWithoutTheChecksum(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.PAData = append(req.PAData,
		pacOptions(t, wire.PACOptRBCD)...)
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if len(enc.EncPAData) != 1 {
		t.Fatalf("enc-padata carries %d elements: %v",
			len(enc.EncPAData), enc.EncPAData)
	}
	if enc.EncPAData[0].Type != wire.PAPACOptions {
		t.Errorf("enc-padata holds type %d",
			enc.EncPAData[0].Type)
	}
}
