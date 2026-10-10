package kdc

import (
	"encoding/asn1"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// encAuthData seals an authorization-data list the way a client does:
// in the header ticket's session key at key usage 4, which is the way
// upstream tries first.
func encAuthData(
	t *testing.T,
	session []byte,
	ad wire.AuthorizationData,
) asn1.RawValue {
	t.Helper()
	plain, err := wire.MarshalAuthorizationData(ad)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := aes256(t).Encrypt(session, plain,
		crypto.UsageTGSReqAuthDataSession)
	if err != nil {
		t.Fatal(err)
	}
	field, err := wire.EncAuthDataField(wire.EncryptedData{
		EType:  int32(crypto.AES256CTSHMACSHA196),
		Cipher: ct,
	})
	if err != nil {
		t.Fatal(err)
	}
	return field
}

// ticketAuthDataOf opens an issued ticket and decodes its
// authorization data, **less the PAC**.
//
// The PAC is dropped because every ticket carries one now and the
// cases below are about the copy paths. It is asserted separately, in
// TestTheIssuedTicketCarriesAVerifiablePAC, rather than being
// tolerated here and nowhere checked.
func ticketAuthDataOf(
	t *testing.T,
	rep *wire.TGSRep,
) wire.AuthorizationData {
	t.Helper()
	tkt := openServiceTicket(t, rep)
	ad, err := wire.AuthDataOf(tkt.AuthorizationData)
	if err != nil {
		t.Fatalf("the ticket's authdata: %v", err)
	}
	return withoutPAC(t, ad)
}

// withoutPAC drops the AD-IF-RELEVANT container holding the PAC,
// insisting there is exactly one of them -- so a case using this
// still fails if the PAC went missing.
func withoutPAC(
	t *testing.T,
	ad wire.AuthorizationData,
) wire.AuthorizationData {
	t.Helper()
	var out wire.AuthorizationData
	found := 0
	for _, d := range ad {
		if d.Type == wire.ADIfRelevant && hasPAC(t, d) {
			found++
			continue
		}
		out = append(out, d)
	}
	if found != 1 {
		t.Fatalf("the ticket carries %d PACs: %v", found, ad)
	}
	return out
}

// hasPAC reports an AD-IF-RELEVANT container with a PAC in it.
func hasPAC(t *testing.T, d wire.AuthDatum) bool {
	t.Helper()
	inner, err := wire.UnmarshalAuthorizationData(d.Data)
	if err != nil {
		return false
	}
	for _, e := range inner {
		if e.Type == wire.ADWin2KPAC {
			return true
		}
	}
	return false
}

// A client's own authorization data reaches the issued ticket, which
// it did not before: neither reply path named the field, so the [10]
// element was always omitted whatever a client sent.
func TestRequestAuthDataReachesTheTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.EncAuthorizationData = encAuthData(t,
				session, wire.AuthorizationData{
					{Type: 2,
						Data: []byte("mine")},
				})
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	ad := ticketAuthDataOf(t, rep)
	if len(ad) != 1 || string(ad[0].Data) != "mine" {
		t.Errorf("the ticket carries %v", ad)
	}
}

// And a presented ticket's authorization data is carried across,
// which is the half that was a correctness bug rather than a missing
// feature: a client that put something in a ticket expects it still
// to be there after a renewal or a service-ticket request
// (copy_tgt_authdata, kdc_authdata.c:286-296).
func TestTicketAuthDataIsCarriedForward(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	// Put something in the TGT by hand, which is the only way to
	// get there: the AS exchange deliberately copies nothing.
	rep, kerr := tgsWithTGTAuthData(t, k, tgt, session,
		wire.AuthorizationData{
			{Type: 2, Data: []byte("carried")},
		})
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	// No PAC here, and not by accident: tgsWithTGTAuthData
	// re-seals the TGT with *only* the element it was given, so
	// the presented ticket carries none and the issued one
	// therefore carries none either.
	tkt := openServiceTicket(t, rep)
	ad, err := wire.AuthDataOf(tkt.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	if len(ad) != 1 || string(ad[0].Data) != "carried" {
		t.Errorf("the ticket carries %v", ad)
	}
}

// AD-MANDATORY-FOR-KDC refuses the request, from either source.
//
// **This was a live correctness bug.** The element's entire meaning
// is "understand this or reject the request", and a KDC that never
// looked at authorization data could do neither -- it issued a ticket
// and ignored the instruction. Upstream answers KDC_ERR_POLICY from
// both copy paths (:277-280 and :291-292) and t_authdata.py:30-32
// asserts the exit code and the message.
func TestMandatoryForKDCRefusesTheRequest(t *testing.T) {
	mandatory := wire.AuthorizationData{
		{Type: wire.ADMandatoryForKDC, Data: []byte("x")},
	}
	t.Run("in the request", func(t *testing.T) {
		k := testKDC(t)
		addService(t, k, 0)
		tgt, session := getTGT(t, k)
		msg, req := tgsRequest(t, tgt, session, serviceName,
			func(b *wire.KDCReqBody) {
				b.EncAuthorizationData = encAuthData(
					t, session, mandatory)
			})
		_, kerr := k.TGS(msg, req)
		assertPolicyRefusal(t, kerr)
	})
	t.Run("in the ticket", func(t *testing.T) {
		k := testKDC(t)
		addService(t, k, 0)
		tgt, session := getTGT(t, k)
		_, kerr := tgsWithTGTAuthData(t, k, tgt, session,
			mandatory)
		assertPolicyRefusal(t, kerr)
	})
}

// assertPolicyRefusal insists on KDC_ERR_POLICY.
func assertPolicyRefusal(t *testing.T, kerr *wire.KRBError) {
	t.Helper()
	if kerr == nil {
		t.Fatal("the request was answered")
	}
	if kerr.ErrorCode != wire.ErrCodePolicy {
		t.Errorf("code %d, want POLICY", kerr.ErrorCode)
	}
}

// A client cannot hand itself a PAC, directly or wrapped in an
// AD-IF-RELEVANT container -- which is the case a top-level type
// check would miss, because a service unwraps the container without
// caring who put it there.
func TestAClientCannotSupplyKDCIssuedAuthData(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	inner, err := wire.MarshalAuthorizationData(
		wire.AuthorizationData{
			{Type: wire.ADWin2KPAC,
				Data: []byte("forged")},
		})
	if err != nil {
		t.Fatal(err)
	}
	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.EncAuthorizationData = encAuthData(t,
				session, wire.AuthorizationData{
					{Type: wire.ADWin2KPAC,
						Data: []byte("bare")},
					{Type: wire.ADIfRelevant,
						Data: inner},
					{Type: 2,
						Data: []byte("kept")},
				})
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	ad := ticketAuthDataOf(t, rep)
	if len(ad) != 1 || string(ad[0].Data) != "kept" {
		t.Errorf("the ticket carries %v, want only the "+
			"ordinary element", ad)
	}
}

// An AS-issued ticket copies **nothing the client sent**, whatever it
// sent, because upstream's two copy paths both gate on KRB5_TGS_REQ
// (:536 and :556).
//
// It is not empty, though, and has not been since the KDC started
// issuing a PAC: what a ticket carries is what the *KDC* put there.
// So this asserts the shape rather than the absence -- one
// AD-IF-RELEVANT holding one AD-WIN2K-PAC, and nothing else.
func TestTheASExchangeCopiesNoAuthData(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.Body.EncAuthorizationData = asn1.RawValue{
		FullBytes: []byte{0x30, 0x00},
	}
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicket(t, k, rep)
	ad, err := wire.AuthDataOf(tkt.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	if len(ad) != 1 || ad[0].Type != wire.ADIfRelevant {
		t.Fatalf("the ticket carries %d elements: %v",
			len(ad), ad)
	}
	inner, err := wire.UnmarshalAuthorizationData(ad[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != wire.ADWin2KPAC {
		t.Errorf("the container holds %v", inner)
	}
}

// And with PA-PAC-REQUEST(false) the ticket really is empty, which is
// what every golden case has relied on -- declining is something a
// client is entitled to do and this KDC honours it.
func TestADeclinedPACLeavesTheTicketEmpty(t *testing.T) {
	k := testKDC(t)
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
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicket(t, k, rep)
	if len(tkt.AuthorizationData.FullBytes) != 0 {
		t.Errorf("a declined PAC still travelled: % x",
			tkt.AuthorizationData.FullBytes)
	}
}

// tgsWithTGTAuthData re-seals a TGT with authorization data in it and
// then presents it.
//
// Putting it there by hand is the only way to get it there, and that
// is itself a fact worth the helper: the AS exchange deliberately
// copies nothing, so the only authorization data a TGT can carry is
// what a KDC put there -- or, in a test, what a test did.
func tgsWithTGTAuthData(
	t *testing.T,
	k *KDC,
	tgt wire.Ticket,
	session []byte,
	ad wire.AuthorizationData,
) (*wire.TGSRep, *wire.KRBError) {
	t.Helper()
	inner := decodeTicketWith(t, tgt, "tgtpassword",
		[]string{"krbtgt", testRealm})
	field, err := wire.AuthDataField(ad)
	if err != nil {
		t.Fatal(err)
	}
	inner.AuthorizationData = field
	tgt.EncPart = sealTicket(t, inner, "tgtpassword",
		[]string{"krbtgt", testRealm})
	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	return k.TGS(msg, req)
}

// sealTicket encrypts an EncTicketPart under a principal's key, which
// is the reverse of decodeTicketWith.
func sealTicket(
	t *testing.T,
	inner wire.EncTicketPart,
	password string,
	components []string,
) wire.EncryptedData {
	t.Helper()
	plain, err := wire.MarshalEncTicketPart(inner)
	if err != nil {
		t.Fatal(err)
	}
	e := crypto.AES256CTSHMACSHA196
	key := clientKey(t, components, password, e)
	ct, err := aes256(t).Encrypt(key, plain,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	return wire.EncryptedData{
		EType:  int32(e),
		Cipher: ct,
	}
}
