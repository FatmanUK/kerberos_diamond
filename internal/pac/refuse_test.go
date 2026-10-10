package pac

import (
	"encoding/binary"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// A changed octet anywhere in the PAC breaks the server checksum,
// which is the whole point of having one -- and it is checked here
// against Windows' own bytes rather than against something this
// package signed, so a verifier that quietly recomputed instead of
// comparing would fail.
func TestTamperingBreaksTheServerChecksum(t *testing.T) {
	key := aes256(t, refS4UServerKey)
	for _, at := range []int{0, 32, 100, 300} {
		raw := hx(t, refS4UPAC)
		raw[at] ^= 0x01
		p, err := Parse(raw)
		if err != nil {
			// A changed octet in the table may well not
			// parse at all, which is also a refusal.
			continue
		}
		err = p.Verify(key, wire.EncryptionKey{}, false)
		if err == nil {
			t.Errorf("octet %d changed and it verified",
				at)
		}
	}
}

// CKSUMTYPE_SHA1 in the *server* checksum is refused outright
// (pac.c:496-498), and this is a real attack rather than tidiness: an
// unkeyed checksum there is one anybody can compute, and the server
// checksum is the one checked against a key the client may not hold.
//
// The refusal has to come before the length check and before the
// comparison, so what is asserted is that a PAC otherwise correct
// except for that type is refused.
func TestAnUnkeyedServerChecksumIsRefused(t *testing.T) {
	key := aes256(t, refS4UServerKey)
	p, err := Parse(hx(t, refS4UPAC))
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.locate(TypeServerChecksum)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(p.span(b), uint32(cksumSHA1))
	if err := p.Verify(key, wire.EncryptionKey{},
		false); err == nil {
		t.Error("an unkeyed server checksum verified")
	}
}

// A ticket with no PAC in it is **success with no PAC**, not a
// refusal (pac.c:641-645). That is what lets a realm issuing none
// interoperate with one that does, and a reimplementation that
// errored here would refuse every ticket this project issues today.
func TestATicketWithNoPACIsNotAnError(t *testing.T) {
	server := wire.PrincipalName{Type: wire.NTSrvInst,
		Components: []string{"host", "example.test"}}
	for _, why := range []string{
		"no authorization data at all",
		"authorization data with no PAC",
	} {
		enc := wire.EncTicketPart{}
		if why != "no authorization data at all" {
			other := wire.AuthorizationData{
				{Type: 2, Data: []byte("o")},
			}
			field, err := wire.AuthDataField(other)
			if err != nil {
				t.Fatal(err)
			}
			enc.AuthorizationData = field
		}
		p, err := VerifyTicket(&enc, server,
			wire.EncryptionKey{}, wire.EncryptionKey{})
		if err != nil {
			t.Errorf("%s: %v", why, err)
		}
		if p != nil {
			t.Errorf("%s: found a PAC", why)
		}
	}
}

// The two server names that do not get a ticket signature, from
// [MS-PAC] 2.8.3 by way of k5_pac_should_have_ticket_signature
// (pac.c:580-591) -- and the near misses that do, because each
// exception is an exact two-component name and nothing broader.
func TestWhichServersGetATicketSignature(t *testing.T) {
	for _, c := range []struct {
		components []string
		want       bool
	}{
		{[]string{"krbtgt", "EXAMPLE.TEST"}, false},
		{[]string{"kadmin", "changepw"}, false},
		{[]string{"kadmin", "admin"}, true},
		{[]string{"krbtgt"}, true},
		{[]string{"krbtgt", "A", "B"}, true},
		{[]string{"host", "www.example.test"}, true},
	} {
		got := ShouldHaveTicketSignature(
			wire.PrincipalName{Components: c.components})
		if got != c.want {
			t.Errorf("%v: %v, want %v",
				c.components, got, c.want)
		}
	}
}

// Signing a ticket puts the PAC **first**, ahead of anything already
// there, and leaves the rest in order (pac_sign.c:396-401).
//
// Position is how the verifier finds it and how a re-signing
// reproduces the same octets, so this is not cosmetic.
func TestTheSignedPACComesFirst(t *testing.T) {
	server := wire.PrincipalName{Type: wire.NTSrvInst,
		Components: []string{"host", "example.test"}}
	key := aes256(t, refADServerKey)
	field, err := wire.AuthDataField(wire.AuthorizationData{
		{Type: 2, Data: []byte("first")},
		{Type: 3, Data: []byte("second")},
	})
	if err != nil {
		t.Fatal(err)
	}
	enc := wire.EncTicketPart{AuthorizationData: field}
	if err := SignTicket(&enc, New(), server, nil,
		key, key); err != nil {
		t.Fatal(err)
	}
	list, err := wire.AuthDataOf(enc.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("%d elements, want 3", len(list))
	}
	if list[0].Type != wire.ADIfRelevant {
		t.Errorf("element 0 is type %d", list[0].Type)
	}
	if list[1].Type != 2 || list[2].Type != 3 {
		t.Errorf("the rest came back as %d, %d",
			list[1].Type, list[2].Type)
	}
	if _, err := VerifyTicket(&enc, server, key,
		key); err != nil {
		t.Errorf("what SignTicket wrote does not verify: %v",
			err)
	}
}
