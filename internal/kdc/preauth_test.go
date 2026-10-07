package kdc

import (
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// A principal with +requires_preauth gets refused first and told what
// to send, which is the whole of the two-round-trip handshake.
func TestPreauthRequiredCarriesAHint(t *testing.T) {
	k := testKDC(t)
	_, kerr := as(t, k, asRequest([]string{"preauth"}))
	if kerr == nil {
		t.Fatal("issued a ticket without preauth")
	}
	if kerr.ErrorCode != wire.ErrCodePreauthRequired {
		t.Fatalf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodePreauthRequired)
	}
	hints, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatalf("e-data: %v", err)
	}
	// Upstream's order, and the first element is the surprise: an
	// *empty* PA-FX-FAST, which get_preauth_hint_list adds before
	// anything else (kdc/kdc_preauth.c:999-1001) and which is how
	// a client learns it may upgrade this exchange to FAST. Then
	// the etype-info, then the factor.
	want := []int32{
		wire.PAFXFast, wire.PAETypeInfo2, wire.PAEncTimestamp,
	}
	if len(hints) != len(want) {
		t.Fatalf("got %d hints: %+v", len(hints), hints)
	}
	for i, w := range want {
		if hints[i].Type != w {
			t.Errorf("hint %d is type %d, want %d",
				i, hints[i].Type, w)
		}
	}
	// Both the advertisement and the factor carry nothing: they
	// are the presence of an offer, not its content.
	for _, i := range []int{0, 2} {
		if len(hints[i].Value) != 0 {
			t.Errorf("hint %d carries %d bytes",
				i, len(hints[i].Value))
		}
	}
}

// The hint names one enctype, not every enctype the client holds:
// make_etype_info builds exactly one entry, from the already-selected
// client key (kdc/kdc_preauth.c:1046-1069).
func TestETypeInfo2HasOneEntryWithTheSalt(t *testing.T) {
	k := testKDC(t)
	_, kerr := as(t, k, asRequest([]string{"preauth"}))
	if kerr == nil {
		t.Fatal("issued a ticket without preauth")
	}
	hints, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatalf("e-data: %v", err)
	}
	pa := findPAData(hints, wire.PAETypeInfo2)
	if pa == nil {
		t.Fatalf("no PA-ETYPE-INFO2 in %+v", hints)
	}
	info, err := wire.UnmarshalETypeInfo2(pa.Value)
	if err != nil {
		t.Fatalf("PA-ETYPE-INFO2: %v", err)
	}
	if len(info) != 1 {
		t.Fatalf("got %d entries, want 1", len(info))
	}
	want := int32(crypto.AES256CTSHMACSHA196)
	if info[0].EType != want {
		t.Errorf("etype is %d, want %d", info[0].EType, want)
	}
	if info[0].Salt == nil {
		t.Fatal("no salt in the hint")
	}
	expect := string(crypto.Salt(testRealm, []string{"preauth"}))
	if *info[0].Salt != expect {
		t.Errorf("salt is %q, want %q", *info[0].Salt, expect)
	}
	// s2kparams absent means the 4096-iteration default.
	if len(info[0].S2KParams) != 0 {
		t.Errorf("s2kparams is % X", info[0].S2KParams)
	}
}

// encTimestamp builds the PA-ENC-TIMESTAMP a client would send, using
// the salt the hint named rather than one assumed here -- which is
// what makes this a round trip and not two halves of the same
// assumption.
func encTimestamp(
	t *testing.T,
	k *KDC,
	salt string,
	e crypto.EncType,
	at time.Time,
) wire.PAData {
	t.Helper()
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(userPassword, []byte(salt), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := wire.MarshalPAEncTSEnc(wire.PAEncTSEnc{
		PATimestamp: at,
		PAUSec:      123456,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(key, plain, crypto.UsageASReqPAEncTS)
	if err != nil {
		t.Fatal(err)
	}
	value, err := wire.MarshalEncryptedData(wire.EncryptedData{
		EType:  int32(e),
		Cipher: ct,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{
		Type:  wire.PAEncTimestamp,
		Value: value,
	}
}

// hintSalt drives the first round trip and returns what the KDC asked
// for.
func hintSalt(t *testing.T, k *KDC) (string, crypto.EncType) {
	t.Helper()
	_, kerr := as(t, k, asRequest([]string{"preauth"}))
	if kerr == nil {
		t.Fatal("issued a ticket without preauth")
	}
	hints, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatalf("e-data: %v", err)
	}
	// Found by type, not by position. Upstream's hint list leads
	// with the empty PA-FX-FAST that advertises FAST
	// (kdc/kdc_preauth.c:999-1001), so the etype-info is not
	// first and a client has no business assuming it is.
	pa := findPAData(hints, wire.PAETypeInfo2)
	if pa == nil {
		t.Fatalf("no PA-ETYPE-INFO2 in %+v", hints)
	}
	info, err := wire.UnmarshalETypeInfo2(pa.Value)
	if err != nil {
		t.Fatalf("PA-ETYPE-INFO2: %v", err)
	}
	return *info[0].Salt, crypto.EncType(info[0].EType)
}

// The second round trip: the client answers the hint and gets a
// ticket, which must be marked PRE-AUTHENT.
func TestPreauthRoundTripSucceeds(t *testing.T) {
	k := testKDC(t)
	salt, e := hintSalt(t, k)

	req := asRequest([]string{"preauth"})
	req.PAData = []wire.PAData{
		encTimestamp(t, k, salt, e, fixedNow),
	}
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused a valid timestamp: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.Flags.Has(wire.FlagPreAuthent) {
		t.Error("PreAuthent not set after a preauth exchange")
	}
	if !enc.Flags.Has(wire.FlagInitial) {
		t.Error("Initial not set")
	}
}

// A timestamp encrypted under the wrong key is a preauth failure, not
// a ticket. This is the assertion that would pass vacuously if the
// KDC never looked at the padata at all, so it also checks that the
// successful case above was doing work.
func TestPreauthRejectsTheWrongPassword(t *testing.T) {
	k := testKDC(t)
	salt, e := hintSalt(t, k)

	req := asRequest([]string{"preauth"})
	pa := encTimestamp(t, k, salt+"wrong", e, fixedNow)
	req.PAData = []wire.PAData{pa}
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("accepted a timestamp under the wrong key")
	}
	if kerr.ErrorCode != wire.ErrCodePreauthFailed {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodePreauthFailed)
	}
}

// A timestamp that decrypts but names the wrong moment is a *skew*
// error, not a preauth failure. The two are different protocol codes
// because a client acts on them differently: skew is worth retrying
// after resynchronising and a failure is not.
func TestPreauthRejectsStaleTimestamps(t *testing.T) {
	k := testKDC(t)
	salt, e := hintSalt(t, k)

	req := asRequest([]string{"preauth"})
	stale := fixedNow.Add(-time.Hour)
	req.PAData = []wire.PAData{
		encTimestamp(t, k, salt, e, stale),
	}
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("accepted an hour-old timestamp")
	}
	if kerr.ErrorCode != wire.ErrCodeSkew {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeSkew)
	}
}

// A principal *without* the requirement gets a ticket in one round
// trip and sends no PA-ENC-TIMESTAMP -- but the reply still carries
// PA-ETYPE-INFO2.
//
// That last part is not an oversight: return_padata adds etype-info2
// to every AS-REP, not only to a refusal
// (kdc/kdc_preauth.c:1486-1492). This test originally asserted the
// reply had no padata at all, which was this implementation's
// assumption rather than upstream's behaviour, and the differential
// harness caught it.
func TestNoPreauthStillSendsETypeInfo2(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	if len(rep.PAData) != 1 {
		t.Fatalf("reply padata is %+v, want one entry",
			rep.PAData)
	}
	if rep.PAData[0].Type != wire.PAETypeInfo2 {
		t.Errorf("padata type is %d, want %d",
			rep.PAData[0].Type, wire.PAETypeInfo2)
	}
	info, err := wire.UnmarshalETypeInfo2(rep.PAData[0].Value)
	if err != nil {
		t.Fatalf("PA-ETYPE-INFO2: %v", err)
	}
	if len(info) != 1 || info[0].Salt == nil {
		t.Fatalf("etype-info2 is %+v", info)
	}
	enc := decodeReply(t, k, rep)
	if enc.Flags.Has(wire.FlagPreAuthent) {
		t.Error("PreAuthent set without preauth")
	}
}

// PA-PW-SALT is never sent. add_pw_salt includes it only for a
// request that asked for no enctype requiring etype-info2
// (kdc/kdc_preauth.c:805-824), and every AES type requires it -- so a
// request this KDC can answer never qualifies.
func TestNoPWSalt(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	for _, p := range rep.PAData {
		if p.Type == wire.PAPWSalt {
			t.Error("reply carries PA-PW-SALT")
		}
	}
}
