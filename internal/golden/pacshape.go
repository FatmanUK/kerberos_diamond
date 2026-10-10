package golden

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/pac"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// pacShape renders a PAC for comparison: its buffer table, its
// payloads, and for each checksum buffer the checksum *type* and
// length but **not** the value.
//
// The exclusion is not an exemption, and the reason is specific. A
// PAC has no confounder in it -- every octet is structure or a keyed
// checksum over structure -- so two KDCs holding the same keys and
// issuing for the same client at the same authtime produce
// *identical* PACs, and a TGT's PAC is compared byte for byte
// elsewhere for exactly that reason.
//
// A **service** ticket's cannot be. Its ticket signature covers the
// encoded EncTicketPart, which carries the session key, and the
// session key is freshly random on each side -- so the ticket
// checksum differs, the full checksum over the PAC containing it
// differs, the server checksum over that differs, and the privsvr
// checksum over the server's differs. All four, necessarily, for a
// reason that is about the ticket and not about the PAC.
//
// What is left is everything a reimplementation could get wrong: the
// buffer order, each buffer's offset and length, the eight-octet
// padding implied between them, the CLIENT_INFO buffer octet for
// octet, and which checksum type each signature uses.
func pacShape(data []byte) string {
	p, err := pac.Parse(data)
	if err != nil {
		return fmt.Sprintf("<unparseable PAC: %v>", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pac[%d buffers]", len(p.Types()))
	for _, typ := range p.Types() {
		content, err := p.Get(typ)
		if err != nil {
			fmt.Fprintf(&b, " %d:<%v>", typ, err)
			continue
		}
		fmt.Fprintf(&b, " %d:%s", typ,
			bufferShape(typ, content))
	}
	return b.String()
}

// bufferShape renders one buffer: its contents in full, or for a
// signature its type and length alone.
func bufferShape(typ uint32, content []byte) string {
	if !isPACSignature(typ) {
		return fmt.Sprintf("len=%d,%s", len(content),
			hex.EncodeToString(content))
	}
	if len(content) < 4 {
		return fmt.Sprintf("len=%d,short", len(content))
	}
	return fmt.Sprintf("cksumtype=%d,len=%d",
		binary.LittleEndian.Uint32(content),
		len(content)-4)
}

// isPACSignature reports a buffer whose contents are a checksum.
func isPACSignature(typ uint32) bool {
	switch typ {
	case pac.TypeServerChecksum, pac.TypePrivsvrChecksum,
		pac.TypeTicketChecksum, pac.TypeFullChecksum:
		return true
	}
	return false
}

// authzShape renders a ticket's authorization-data field for
// comparison: every element by type, with a PAC rendered by pacShape
// and everything else by its octets.
//
// It replaces a bare length, which is what this field was compared by
// before anything put authorization data in a ticket. A length match
// would have passed on two PACs whose buffers were in different
// orders.
func authzShape(raw wire.AuthorizationData) string {
	parts := make([]string, 0, len(raw))
	for _, d := range raw {
		parts = append(parts, elementShape(d))
	}
	return strings.Join(parts, " | ")
}

// elementShape renders one authorization-data element, descending one
// level into an AD-IF-RELEVANT container -- which is where a PAC
// lives, and is also where the KDC-only filter looks.
func elementShape(d wire.AuthDatum) string {
	switch d.Type {
	case wire.ADWin2KPAC:
		return fmt.Sprintf("128{%s}", pacShape(d.Data))
	case wire.ADIfRelevant:
		inner, err := wire.UnmarshalAuthorizationData(d.Data)
		if err != nil {
			return fmt.Sprintf("1{unparseable: %v}", err)
		}
		return fmt.Sprintf("1{%s}", authzShape(inner))
	}
	return fmt.Sprintf("%d:%s", d.Type,
		hex.EncodeToString(d.Data))
}
