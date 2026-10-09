package golden

import (
	"context"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// TestRequestAuthDataMatchesTheC is the differential case for
// authorization data, and it exists because the field was omitted by
// this KDC until now -- so every case before it compared the
// *absence* of authdata on both sides, which two implementations
// agree about perfectly while testing nothing.
//
// One TGS-REQ carrying enc-authorization-data goes to both. What is
// compared is what each put in the issued ticket's [10] field: the
// ordinary element kept, the KDC-issued ones stripped, and in the
// same order.
func TestRequestAuthDataMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, authTime := getTGTFromTheC(t, ctx, o)
	till := time.Now().UTC().Add(2 * time.Hour).Truncate(
		time.Second)
	msg := tgsRequestWithAuthData(t, g, till)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openTGS(t, cRaw, g)

	d := diamond(t, "kd_golden_authdata",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openTGS(t, goRaw, g)

	assertTGSSucceeded(t, "oracle", cx, authTime)
	assertTGSSucceeded(t, "diamond", gx, authTime)
	assertSameAuthData(t, cx, gx)
	reportDiffs(t, cx, gx)
}

// assertSameAuthData compares the two tickets' authorization data,
// and asserts it is not empty -- which is the guard against the
// hazard this whole case exists for.
func assertSameAuthData(t *testing.T, cx, gx Exchange) {
	t.Helper()
	c := authDataOf(t, "oracle", cx)
	g := authDataOf(t, "diamond", gx)
	if len(c) == 0 {
		t.Fatal("the C KDC copied nothing, so this case " +
			"compares two absences")
	}
	if len(c) != len(g) {
		t.Fatalf("oracle carried %d elements, diamond %d",
			len(c), len(g))
	}
	for i := range c {
		if c[i].Type != g[i].Type {
			t.Errorf("element %d: types %d and %d", i,
				c[i].Type, g[i].Type)
		}
		if string(c[i].Data) != string(g[i].Data) {
			t.Errorf("element %d: data %q and %q", i,
				c[i].Data, g[i].Data)
		}
	}
}

// authDataOf reads one side's issued ticket.
func authDataOf(
	t *testing.T,
	side string,
	x Exchange,
) wire.AuthorizationData {
	t.Helper()
	ad, err := wire.AuthDataOf(x.Tkt.AuthorizationData)
	if err != nil {
		t.Fatalf("%s: the ticket's authdata: %v", side, err)
	}
	return ad
}

// tgsRequestWithAuthData is tgsRequestFor with
// enc-authorization-data, holding one ordinary element and two a
// client may not supply -- one bare and one wrapped in an
// AD-IF-RELEVANT container, which is the case a top-level type check
// would miss.
func tgsRequestWithAuthData(
	t *testing.T,
	g tgt,
	till time.Time,
) []byte {
	t.Helper()
	inner, err := wire.MarshalAuthorizationData(
		wire.AuthorizationData{{
			Type: wire.ADWin2KPAC,
			Data: []byte("wrapped"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	ad := wire.AuthorizationData{
		{Type: 2, Data: []byte("kept")},
		{Type: wire.ADWin2KPAC, Data: []byte("bare")},
		{Type: wire.ADIfRelevant, Data: inner},
	}
	return tgsRequestAuthz(t, g, till,
		sealAuthData(t, g, ad))
}

// sealAuthData encrypts an authorization-data list in the TGT's
// session key at key usage 4, which is the way upstream tries first
// (copy_request_authdata, kdc_authdata.c:252-260).
func sealAuthData(
	t *testing.T,
	g tgt,
	ad wire.AuthorizationData,
) asn1.RawValue {
	t.Helper()
	plain, err := wire.MarshalAuthorizationData(ad)
	if err != nil {
		t.Fatal(err)
	}
	e := g.sessionEType
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(g.session, plain,
		crypto.UsageTGSReqAuthDataSession)
	if err != nil {
		t.Fatal(err)
	}
	field, err := wire.EncAuthDataField(wire.EncryptedData{
		EType:  int32(e),
		Cipher: ct,
	})
	if err != nil {
		t.Fatal(err)
	}
	return field
}

// tgsRequestAuthz is tgsRequestFor with one extra body field.
//
// The body is built, encoded, and only then checksummed into the
// AP-REQ's authenticator -- the same order tgsRequestFor uses, and
// the reason the request is assembled twice: the checksum covers the
// encoded body, so the body cannot change after it is computed.
func tgsRequestAuthz(
	t *testing.T,
	g tgt,
	till time.Time,
	authz asn1.RawValue,
) []byte {
	t.Helper()
	body := wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  till,
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
		EncAuthorizationData: authz,
	}
	req := wire.TGSReq{PAData: []wire.PAData{
		{Type: wire.PAReqEncPARep},
	}, Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = append(req.PAData, tgsAPReq(t, g, bodyDER))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
