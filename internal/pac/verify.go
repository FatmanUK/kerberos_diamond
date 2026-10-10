package pac

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Verify checks the server and privsvr checksums, and the full
// checksum when the ticket is a service ticket (verify_pac_checksums,
// pac.c:508-578).
//
// Either key may be absent -- a nil slice -- and then its checksums
// are not checked. That is upstream's `if (server != NULL)' and it is
// how a service with only its own key verifies the half it can.
//
// The copy the checksums are verified over has the server and privsvr
// checksum *contents* zeroed, which is the inverse of how they were
// computed: each was computed when the later ones were still zero, so
// verification has to put them back.
func (p *PAC) Verify(
	server, privsvr wire.EncryptionKey,
	expectFull bool,
) error {
	copied := make([]byte, len(p.data))
	copy(copied, p.data)
	if err := p.zero(copied, TypeServerChecksum); err != nil {
		return err
	}
	if err := p.zero(copied, TypePrivsvrChecksum); err != nil {
		return err
	}
	if len(server.KeyValue) > 0 {
		if err := p.check(TypeServerChecksum, server,
			copied); err != nil {
			return err
		}
	}
	if len(privsvr.KeyValue) == 0 {
		return nil
	}
	return p.verifyPrivsvr(privsvr, copied, expectFull)
}

// verifyPrivsvr is the half that needs the privsvr key: the full
// checksum, over a copy with all three zeroed, and then the privsvr
// checksum over the server checksum's own octets.
func (p *PAC) verifyPrivsvr(
	privsvr wire.EncryptionKey,
	copied []byte,
	expectFull bool,
) error {
	if expectFull {
		if err := p.zero(copied,
			TypeFullChecksum); err != nil {
			return err
		}
		if err := p.check(TypeFullChecksum, privsvr,
			copied); err != nil {
			return err
		}
	}
	b, err := p.locate(TypeServerChecksum)
	if err != nil {
		return err
	}
	if b.size < signatureHdr {
		return fmt.Errorf("%w: server checksum is %d octets",
			ErrMalformed, b.size)
	}
	return p.check(TypePrivsvrChecksum, privsvr,
		p.span(b)[signatureHdr:])
}

// VerifyTicketChecksum checks the KRB5_PAC_TICKET_CHECKSUM against a
// DER-encoded EncTicketPart, which the caller must have re-encoded
// with the PAC element's contents replaced by a single zero octet.
//
// Doing the replacement outside this function is deliberate: it needs
// the whole authorization-data list and the ticket around it, which
// is the KDC's business and not the PAC's.
func (p *PAC) VerifyTicketChecksum(
	privsvr wire.EncryptionKey,
	der []byte,
) error {
	return p.check(TypeTicketChecksum, privsvr, der)
}

// zero blanks one checksum buffer's contents -- not its type prefix
// -- inside a copy of the data (zero_signature, pac.c:439-471).
func (p *PAC) zero(copied []byte, typ uint32) error {
	b, err := p.locate(typ)
	if err != nil {
		return err
	}
	if b.size < signatureHdr {
		return fmt.Errorf("%w: type %d is %d octets",
			ErrMalformed, typ, b.size)
	}
	at := b.offset + signatureHdr
	clear(copied[at : b.offset+uint64(b.size)])
	return nil
}

// check verifies one checksum buffer over data (verify_checksum,
// pac.c:473-506).
//
// Three refusals, and the first is a real attack rather than
// tidiness:
//
//   - **CKSUMTYPE_SHA1 in the server checksum** is refused outright
//     (:496-498). An unkeyed checksum there would mean anyone could
//     compute it, so the one place a PAC is checked against a key
//     the client might not have is exactly where an unkeyed type
//     must not be honoured.
//   - an unkeyed type anywhere is refused, which falls out here of
//     ProfileForCksum: every type this project knows is keyed.
//   - the length comes from the **checksum type** and not from the
//     buffer, deliberately, because [MS-PAC] 2.8 allows an
//     RODCIdentifier trailer after the checksum (:500-508). A
//     verifier that took the buffer's length would feed the trailer
//     to the comparison and reject a PAC a real domain controller
//     issued.
func (p *PAC) check(
	typ uint32,
	key wire.EncryptionKey,
	data []byte,
) error {
	b, err := p.locate(typ)
	if err != nil {
		return err
	}
	if b.size < signatureHdr {
		return fmt.Errorf("%w: type %d is %d octets",
			ErrMalformed, typ, b.size)
	}
	span := p.span(b)
	ct := crypto.CksumType(binary.LittleEndian.Uint32(span))
	if typ == TypeServerChecksum && ct == cksumSHA1 {
		return fmt.Errorf(
			"%w: an unkeyed checksum type in the server "+
				"checksum", ErrModified)
	}
	prof, err := crypto.ProfileForCksum(ct)
	if err != nil {
		return err
	}
	return compare(prof, key, data, span, typ)
}

// cksumSHA1 is CKSUMTYPE_SHA1 (krb5.hin), the unkeyed type the server
// checksum must not carry. It is named here rather than in
// internal/crypto because that package implements no unkeyed
// checksums at all and a constant for one would have no other use.
const cksumSHA1 crypto.CksumType = 14

// compare computes the checksum and compares it in constant time.
func compare(
	prof *crypto.EncProfile,
	key wire.EncryptionKey,
	data, span []byte,
	typ uint32,
) error {
	n := prof.TrailerLength
	if signatureHdr+n > len(span) {
		return fmt.Errorf(
			"%w: type %d holds %d octets, needs %d",
			ErrMalformed, typ, len(span), signatureHdr+n)
	}
	want, err := prof.Checksum(key.KeyValue, data,
		UsageAppDataCksum)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, span[signatureHdr:signatureHdr+n]) {
		return fmt.Errorf("%w: type %d", ErrModified, typ)
	}
	return nil
}

// ShouldHaveTicketSignature says whether a ticket for this server
// carries a KRB5_PAC_TICKET_CHECKSUM, and with it a full checksum
// (k5_pac_should_have_ticket_signature, pac.c:580-591).
//
// Two exceptions, both from [MS-PAC] 2.8.3: a ticket-granting
// service, and `kadmin/changepw'. The reason is the same in both
// cases -- the checksum covers the ticket, and these two tickets are
// re-issued or consumed in ways that would invalidate it.
func ShouldHaveTicketSignature(server wire.PrincipalName) bool {
	c := server.Components
	if len(c) == 2 && c[0] == "krbtgt" {
		return false
	}
	return !(len(c) == 2 && c[0] == "kadmin" &&
		c[1] == "changepw")
}
