package kdc

import (
	"context"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// setStringAttr puts a string attribute on a stored principal.
func setStringAttr(
	t *testing.T,
	k *KDC,
	components []string,
	key, value string,
) {
	t.Helper()
	ctx := context.Background()
	name := store.UnparseName(testRealm, components)
	p, err := k.Store.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	p.StringAttrs = append(p.StringAttrs, store.StringAttr{
		PrincipalName: p.Name, Key: key, Value: value,
	})
	if err := k.Store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
}

// A service that demands an authentication method the client did not
// use is refused, with KDC_ERR_POLICY (check_indicators,
// kdc_util.c:861-894).
//
// Nothing in this project produces an indicator yet -- upstream's
// come from OTP, PKINIT and SPAKE, of which only SPAKE is in scope --
// so every request for such a service is refused, which is the
// correct answer to "this service demands something this realm cannot
// do".
func TestRequireAuthRefusesWithoutAnIndicator(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	setStringAttr(t, k, serviceName, requireAuthAttr,
		"otp")
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("the service ticket was issued")
	}
	if kerr.ErrorCode != wire.ErrCodePolicy {
		t.Errorf("code %d, want POLICY", kerr.ErrorCode)
	}
}

// **Any one of the required indicators is enough**, which reads
// backwards and is upstream's: the attribute is a space-separated
// list and the loop returns success on the first match (:877-883). So
// `require_auth = "otp pkinit"' means either, not both -- an operator
// who wanted both would need two services.
func TestRequireAuthIsAnyNotAll(t *testing.T) {
	for _, c := range []struct {
		why  string
		want string
		have []string
		ok   bool
	}{
		{"nothing required", "", nil, true},
		{"the one required", "otp",
			[]string{"otp"}, true},
		{"one of two required", "otp pkinit",
			[]string{"pkinit"}, true},
		{"neither of two", "otp pkinit",
			[]string{"spake"}, false},
		{"required but none held", "otp", nil, false},
		{"extra indicators held", "otp",
			[]string{"spake", "otp", "high"}, true},
	} {
		t.Run(c.why, func(t *testing.T) {
			p := &store.Principal{}
			if c.want != "" {
				p.StringAttrs = []store.StringAttr{{
					Key:   requireAuthAttr,
					Value: c.want,
				}}
			}
			code, _ := checkIndicators(p, c.have)
			if (code == 0) != c.ok {
				t.Errorf("code %d", code)
			}
		})
	}
}

// A CAMMAC this KDC made verifies against the local krbtgt key, and
// the indicators come back out of it.
func TestACAMMACRoundTripsThroughTheTicket(t *testing.T) {
	k := testKDC(t)
	tgtKey, tgtEType, tgtKVNO := localTGTKey(t, k)
	part := wire.EncTicketPart{
		CRealm: testRealm,
		CName: wire.PrincipalName{Type: wire.NTPrincipal,
			Components: []string{"user"}},
	}
	ad := signedIndicators(t, k, part, []string{"spake"})
	field, err := wire.AuthDataField(ad)
	if err != nil {
		t.Fatal(err)
	}
	part.AuthorizationData = field
	got := k.authIndicators(part, tgtKey, tgtEType, tgtKVNO)
	if len(got) != 1 || got[0] != "spake" {
		t.Errorf("got %v", got)
	}
}

// **A CAMMAC whose KDC verifier does not check out is silently
// dropped**, not refused (get_auth_indicators simply does not extract
// from it, kdc_authdata.c:362-363).
//
// Copying that matters operationally rather than theoretically:
// refusing would break a realm mid-rollover, when tickets signed
// under the previous krbtgt key are still in circulation. And it is
// the security property as well -- an indicator nobody vouched for is
// not an indicator, so dropping it is the safe outcome, where keeping
// it would let a client assert how it authenticated.
func TestAnUnverifiedCAMMACIsDroppedNotRefused(t *testing.T) {
	k := testKDC(t)
	tgtKey, tgtEType, tgtKVNO := localTGTKey(t, k)
	part := wire.EncTicketPart{
		CRealm: testRealm,
		CName: wire.PrincipalName{Type: wire.NTPrincipal,
			Components: []string{"user"}},
	}
	ad := signedIndicators(t, k, part, []string{"spake"})
	field, err := wire.AuthDataField(ad)
	if err != nil {
		t.Fatal(err)
	}
	part.AuthorizationData = field
	// Changing the ticket after signing breaks the KDC verifier,
	// because its checksum covers the ticket.
	part.CName.Components = []string{"somebodyelse"}
	if got := k.authIndicators(part, tgtKey, tgtEType,
		tgtKVNO); len(got) != 0 {
		t.Errorf("a lifted CAMMAC still verified: %v", got)
	}
	// A wrong key version is also a drop rather than an error.
	part.CName.Components = []string{"user"}
	if got := k.authIndicators(part, tgtKey, tgtEType,
		tgtKVNO+1); len(got) != 0 {
		t.Errorf("a wrong kvno still verified: %v", got)
	}
}

// localTGTKey is this realm's krbtgt key.
func localTGTKey(
	t *testing.T,
	k *KDC,
) ([]byte, crypto.EncType, uint32) {
	t.Helper()
	key, etype, kvno, err := k.localTGT()
	if err != nil {
		t.Fatal(err)
	}
	return key, etype, kvno
}

// signedIndicators builds the CAMMAC-wrapped indicator list for a
// ticket.
func signedIndicators(
	t *testing.T,
	k *KDC,
	part wire.EncTicketPart,
	ind []string,
) wire.AuthorizationData {
	t.Helper()
	serverKey := clientKey(t, serviceName, "servicepassword",
		crypto.AES256CTSHMACSHA196)
	ad, err := k.addIndicators(nil, ind, nil, part,
		serverKey, crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// And a server with NO_AUTH_DATA_REQUIRED gets neither a PAC nor
// indicators, which is one flag turning off everything the KDC would
// otherwise vouch for (handle_pac's first test,
// kdc_authdata.c:479-481). The flag has been in this project's schema
// since the beginning and nothing read it until now.
func TestNoAuthDataRequiredSuppressesIndicators(t *testing.T) {
	k := testKDC(t)
	part := wire.EncTicketPart{CRealm: testRealm}
	server := &store.Principal{
		Attributes: store.AttrNoAuthDataRequired,
	}
	serverKey := clientKey(t, serviceName, "servicepassword",
		crypto.AES256CTSHMACSHA196)
	ad, err := k.addIndicators(nil, []string{"spake"},
		server, part, serverKey,
		crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	if len(ad) != 0 {
		t.Errorf("got %v", ad)
	}
}
