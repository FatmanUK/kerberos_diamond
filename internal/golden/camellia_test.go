package golden

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// The RFC 6803 enctypes end to end, which is what makes them more
// than a set of test vectors.
//
// The published vectors in internal/crypto pin every primitive -- the
// block cipher, the CMAC, the feedback derivation, the string-to-key
// -- but none of them says the enctype is *wired up*: that the KDC
// will choose it when a client asks for it, seal the reply's
// encrypted half under a key derived from the right one of the
// client's six long-term keys, and name it in the enc-part's etype
// field. A row added to the table and never reached would pass
// everything in internal/crypto.
//
// So this is the ordinary AS comparison with the request's etype list
// replaced. Note what does *not* change: the ticket is still sealed
// with the service's first key, which the fixture's order keeps at
// aes256-cts-hmac-sha384-192, because the client's etype list has
// never had anything to do with the key a ticket is sealed with
// (get_first_current_key, kdc/kdc_util.c:461-473). A reader expecting
// the camellia enctype to appear in ticket.enc-part should expect it
// in the *reply's* enc-part instead.
func TestCamelliaASExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	req.Body.EType = []int32{
		int32(crypto.Camellia256CTSCMAC),
		int32(crypto.Camellia128CTSCMAC),
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_camellia",
		pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	assertCamellia(t, "oracle", cx)
	assertCamellia(t, "diamond", gx)
	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	assertTimeRelationships(t, "oracle", cx)
	assertTimeRelationships(t, "diamond", gx)
	reportDiffs(t, cx, gx)
}

// assertCamellia is the part that stops the case passing while
// testing nothing.
//
// Both KDCs answering with aes256-cts-hmac-sha384-192 would agree
// perfectly -- that is what each would do if it ignored the etype
// list or had no camellia key for the client -- and `open` would
// decrypt both without complaint, because it reads the enctype out of
// the reply rather than assuming one. So the enctype each side chose
// is asserted on each side separately, before the two are compared.
func assertCamellia(t *testing.T, who string, x Exchange) {
	t.Helper()
	want := crypto.Camellia256CTSCMAC
	if got := crypto.EncType(x.Enc.Key.KeyType); got != want {
		t.Errorf("%s: session key is enctype %d, want %d",
			who, got, want)
	}
	// And the session key is the cipher's full 32 octets rather
	// than something of a plausible length: a camellia256 key is
	// as long as an aes256 one, so a length check alone would not
	// have caught the wrong family above.
	if got := len(x.Enc.Key.KeyValue); got != 32 {
		t.Errorf("%s: session key is %d octets, want 32",
			who, got)
	}
}

// And the smaller of the pair, which is a different key length and a
// different Ki -- so a port that hard-coded either would pass the
// case above and fail this one.
//
// It is a second exchange rather than a loop over the two, because
// the oracle has to answer it and each exchange is its own round
// trip; a table would read as cheaper than it is.
func TestCamellia128ASExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	req.Body.EType = []int32{
		int32(crypto.Camellia128CTSCMAC),
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_camellia128",
		pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	assertCamellia128(t, "oracle", cx)
	assertCamellia128(t, "diamond", gx)
	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	reportDiffs(t, cx, gx)
}

// assertCamellia128 is assertCamellia for the smaller key: a
// different enctype number and a different length, so neither
// assertion carries over.
func assertCamellia128(t *testing.T, who string, x Exchange) {
	t.Helper()
	want := crypto.Camellia128CTSCMAC
	if got := crypto.EncType(x.Enc.Key.KeyType); got != want {
		t.Errorf("%s: session key is enctype %d, want %d",
			who, got, want)
	}
	if got := len(x.Enc.Key.KeyValue); got != 16 {
		t.Errorf("%s: session key is %d octets, want 16",
			who, got)
	}
}

// The PA-ETYPE-INFO2 a camellia client is given, which is the other
// half of the enctype being reachable: a stock client derives its key
// from what this hint says, so a hint naming the wrong enctype, salt
// or iteration count sends a client to the wrong key and the failure
// reads as "password incorrect".
//
// The iteration count is the detail worth naming. Upstream's default
// for the camellia string-to-key is **32768**, not RFC 3962's 4096
// (krb5int_camellia_string_to_key, lib/crypto/krb/s2k_pbkdf2.c:
// 193-205), and neither side puts it in s2kparams -- each client is
// expected to know its own enctype's default. So what this compares
// is that both sides leave the field the same way; the count itself
// is pinned by the published string-to-key vectors in
// internal/crypto, which would not match at 4096.
func TestCamelliaETypeInfoMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, PreauthName, till)
	req.Body.EType = []int32{
		int32(crypto.Camellia256CTSCMAC),
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cErr := refusal(t, cRaw)

	d := diamond(t, "kd_golden_camellia_info",
		pinned(cErr.STime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	goErr := refusal(t, goRaw)

	compareHints(t, cErr, goErr)
	info := etypeInfo2(t, "oracle", cErr)
	if got := crypto.EncType(info.EType); got !=
		crypto.Camellia256CTSCMAC {
		t.Errorf("the hint names enctype %d, want %d",
			got, crypto.Camellia256CTSCMAC)
	}
}
