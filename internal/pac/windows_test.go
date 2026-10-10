package pac

import (
	"bytes"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// aes256 is a key of the enctype all the verifiable fixtures use.
func aes256(t *testing.T, hexKey string) wire.EncryptionKey {
	t.Helper()
	return wire.EncryptionKey{
		KeyType:  int32(crypto.AES256CTSHMACSHA196),
		KeyValue: hx(t, hexKey),
	}
}

// The four S4U2Self PACs a Windows 2008 KDC produced, verified
// against the keys upstream ships for them and then re-signed and
// verified again -- which is check_pac's own sequence
// (t_pac.c:502-540).
//
// The KDC key for these is **not** published, so upstream passes NULL
// and only the server checksum is checked (t_pac.c:514-515, and the
// comment at :511-512 saying why it substitutes another key for
// re-signing). Verify's nil-key behaviour is what makes that
// expressible here rather than needing a second code path.
//
// The client names are the finding in this case, and they are four
// different answers from one rule: CLIENT_INFO holds the principal
// unparsed **without its realm** unless the PAC is for a cross-realm
// S4U request, and an enterprise name keeps its interior at sign
// unquoted because NO_REALM suppresses exactly that quoting
// (component_length_quoted, lib/krb5/krb/unparse.c:68-78).
func TestTheWindows2008S4UPACs(t *testing.T) {
	for _, c := range s4uCases() {
		t.Run(c.why, func(t *testing.T) {
			key := aes256(t, c.key)
			p, err := Parse(hx(t, c.blob))
			if err != nil {
				t.Fatal(err)
			}
			at := time.Unix(c.authTime, 0).UTC()
			ci := ClientInfo{Name: c.client, AuthTime: at}
			if err := p.VerifyClientInfo(ci); err != nil {
				t.Error(err)
			}
			checkAndResign(t, p, key, ci)
		})
	}
}

// checkAndResign verifies the server checksum against Windows' bytes,
// then rebuilds the PAC from its payload buffers and signs that --
// which says this package's signing agrees with its own verifying,
// after the first half said its verifying agrees with Windows.
//
// **These four cannot simply be re-signed in place**, and the reason
// is worth recording rather than working around. The Windows 2008
// KDC's krbtgt key is not published, and the privsvr checksum buffer
// it left is twenty octets -- four of type and sixteen of checksum,
// which is an **arcfour** checksum length. Upstream re-signs them
// with an arcfour key for exactly that reason, saying so in a comment
// (t_pac.c:511-512), and insert_checksum refuses a buffer of the
// wrong size rather than resizing it (pac_sign.c:116-121). arcfour is
// a declared non-goal here, so the in-place re-sign is not
// reproducible and the rebuild -- which is check_pac's own second
// half (t_pac.c:545-560) -- is what stands in for it.
func checkAndResign(
	t *testing.T,
	p *PAC,
	key wire.EncryptionKey,
	ci ClientInfo,
) {
	t.Helper()
	if err := p.Verify(key, wire.EncryptionKey{},
		false); err != nil {
		t.Fatalf("the server checksum: %v", err)
	}
	again, err := payloadsOf(t, p).Sign(&ci, key, key, false)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Parse(again)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Verify(key, key, false); err != nil {
		t.Errorf("after re-signing: %v", err)
	}
	if err := q.VerifyClientInfo(ci); err != nil {
		t.Errorf("after re-signing: %v", err)
	}
}

// payloadsOf copies a PAC's payload buffers into a fresh one,
// skipping the three the signing rebuilds -- which is the set
// upstream skips (t_pac.c:555-557).
func payloadsOf(t *testing.T, p *PAC) *PAC {
	t.Helper()
	fresh := New()
	for _, typ := range p.Types() {
		if typ == TypeServerChecksum ||
			typ == TypePrivsvrChecksum ||
			typ == TypeClientInfo {
			continue
		}
		content, err := p.Get(typ)
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.Add(typ, content); err != nil {
			t.Fatal(err)
		}
	}
	return fresh
}

type s4uCase struct {
	why      string
	blob     string
	key      string
	client   string
	authTime int64
}

func s4uCases() []s4uCase {
	return []s4uCase{
		{"an ordinary name", refS4UPAC, refS4UServerKey,
			"w2k8u", 1538430362},
		{"an enterprise name", refS4UPACEnterprise,
			refS4UServerKey, "w2k8u@abc", 1538437551},
		{"cross-realm, so the realm is in the name",
			refS4UPACXRealm, refS4UPrivsvrKey,
			"w2k8u@ACME.COM", 1538469429},
		{"cross-realm and enterprise",
			refS4UPACEntXRealm, refS4UPrivsvrKey,
			"w2k8u@abc@ACME.COM", 1538484998},
	}
}

// The Windows Server 2022 ticket, which is the strongest anchor in
// this phase and the only one that checks all four checksums at once.
//
// It opens with a published key, its PAC verifies under the server
// and krbtgt keys, and the **ticket** checksum verifies over a
// re-encoding of the EncTicketPart with the PAC replaced by a single
// zero octet -- so this also compares this project's DER encoder
// against a Windows one, because a checksum over a re-encoding only
// matches if the re-encoding is byte-identical to what the Windows
// KDC signed.
func TestTheWindows2022Ticket(t *testing.T) {
	enc, sprinc := openADTicket(t)
	p, err := VerifyTicket(&enc, sprinc,
		aes256(t, refADServerKey),
		aes256(t, refADKrbtgtKey))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("the ticket carries no PAC")
	}
	// The server is also the client in upstream's use of this
	// fixture, and CLIENT_INFO holds the realm-less form.
	want := ClientInfo{Name: "administrator",
		AuthTime: enc.AuthTime}
	if err := p.VerifyClientInfo(want); err != nil {
		t.Error(err)
	}
	// All four buffer types are present, which is what makes the
	// case cover the full checksum rather than three of them.
	for _, typ := range []uint32{TypeServerChecksum,
		TypePrivsvrChecksum, TypeTicketChecksum,
		TypeFullChecksum} {
		if _, err := p.Get(typ); err != nil {
			t.Errorf("type %d: %v", typ, err)
		}
	}
}

// And the comparison upstream makes: strip the authorization data,
// re-sign with the same keys, and require the element to come back
// **byte for byte** what the Windows KDC produced (t_pac.c:752-766).
//
// This is not a round trip. Nothing in this package produced the
// bytes being compared against, so what passes here is agreement with
// Microsoft about the buffer order, the eight-octet padding, the
// in-place header encoding, the zero-fill-then-sign order, the usage
// every checksum is computed at, and the DER of the ticket the ticket
// checksum covers -- all at once, and a single octet wrong anywhere
// shows up as a different element.
func TestResigningTheWindowsTicketReproducesIt(t *testing.T) {
	enc, sprinc := openADTicket(t)
	server := aes256(t, refADServerKey)
	privsvr := aes256(t, refADKrbtgtKey)
	p, err := VerifyTicket(&enc, sprinc, server, privsvr)
	if err != nil {
		t.Fatal(err)
	}
	original := onlyElement(t, enc)
	// Signing appends to whatever is there, so the list has to be
	// empty for the result to be comparable -- which is also
	// upstream's step (t_pac.c:752-753).
	enc.AuthorizationData = asn1.RawValue{}
	ci := ClientInfo{Name: "administrator",
		AuthTime: enc.AuthTime}
	if err := SignTicket(&enc, p, sprinc, &ci,
		server, privsvr); err != nil {
		t.Fatal(err)
	}
	// A guard against the comparison being vacuous: the element
	// carries a whole PAC, so anything short means one side came
	// back empty and two empties would match.
	if len(original) < 500 {
		t.Fatalf("the original element is %d octets",
			len(original))
	}
	if got := onlyElement(t, enc); !bytes.Equal(got, original) {
		t.Errorf("re-signed element differs: %d octets, "+
			"want %d", len(got), len(original))
	}
	assertAWrongKeyDiffers(t, p, sprinc, server, privsvr,
		original)
}

// onlyElement is the contents of a ticket's single authorization-data
// element, insisting there is exactly one.
func onlyElement(t *testing.T, enc wire.EncTicketPart) []byte {
	t.Helper()
	list, err := wire.AuthDataOf(enc.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("%d elements, want 1", len(list))
	}
	return list[0].Data
}

// And the other half of that guard: with the krbtgt key one bit out,
// the element must *not* match.
//
// Without this the comparison above could pass for a reason that has
// nothing to do with the checksums -- if, say, the signing wrote them
// into a copy and the element came from somewhere else. Three of the
// four checksums are keyed with privsvr, so changing it has to change
// the bytes.
func assertAWrongKeyDiffers(
	t *testing.T,
	p *PAC,
	sprinc wire.PrincipalName,
	server, privsvr wire.EncryptionKey,
	want []byte,
) {
	t.Helper()
	enc, _ := openADTicket(t)
	enc.AuthorizationData = asn1.RawValue{}
	wrong := wire.EncryptionKey{KeyType: privsvr.KeyType,
		KeyValue: append([]byte(nil), privsvr.KeyValue...)}
	wrong.KeyValue[0] ^= 1
	ci := ClientInfo{Name: "administrator",
		AuthTime: enc.AuthTime}
	if err := SignTicket(&enc, p, sprinc, &ci,
		server, wrong); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(onlyElement(t, enc), want) {
		t.Error("a different krbtgt key signed identically")
	}
}

// openADTicket decodes the Windows ticket, decrypts its enc-part with
// the published server key, and returns the EncTicketPart and the
// server name it was issued for.
func openADTicket(t *testing.T) (
	wire.EncTicketPart, wire.PrincipalName,
) {
	t.Helper()
	tkt, err := wire.UnmarshalTicket(hx(t, refADTicket))
	if err != nil {
		t.Fatal(err)
	}
	prof, err := crypto.Profile(
		crypto.EncType(tkt.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := prof.Decrypt(hx(t, refADServerKey),
		tkt.EncPart.Cipher, crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	return enc, tkt.SName
}
