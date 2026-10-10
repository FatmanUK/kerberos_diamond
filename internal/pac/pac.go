// Package pac implements the Microsoft Privilege Attribute
// Certificate: the container a Windows KDC puts in every ticket, and
// the one a stock MIT KDC puts there too.
//
// **Nothing here decodes a buffer's contents, and that is upstream's
// shape rather than a shortcut.** `authdata.h:45-48` says so of
// itself -- "Decoding the contents of the buffers is left to the
// application" -- and the whole of `lib/krb5/krb/pac.c` contains no
// NDR at all. A PAC is a framing format with checksums over it; what
// the payloads mean is somebody else's problem, and for a realm that
// is not doing Windows interop they mean nothing, because a stock MIT
// KDC emits **no LOGON_INFO buffer at all**. `KRB5_PAC_LOGON_INFO`
// can only reach a PAC through a KDB module's issue_pac method
// (kdc/kdc_authdata.c:507), and exactly one module in upstream's tree
// implements it: the *test* module, where the contents are the four
// bytes "fake" (plugins/kdb/test/kdb_test.c:820).
//
// So this package is the framing, the CLIENT_INFO buffer, and four
// checksums. Everything else is opaque bytes in and opaque bytes out.
package pac

import (
	"errors"
	"fmt"
)

// The buffer types, from krb5.hin:8159-8172. Only three of them have
// any meaning to this package; the rest are named so that a caller
// asking for one does not have to write a number.
const (
	TypeLogonInfo       uint32 = 1
	TypeCredentialsInfo uint32 = 2
	TypeServerChecksum  uint32 = 6
	TypePrivsvrChecksum uint32 = 7
	TypeClientInfo      uint32 = 10
	TypeDelegationInfo  uint32 = 11
	TypeUPNDNSInfo      uint32 = 12
	TypeClientClaims    uint32 = 13
	TypeDeviceInfo      uint32 = 14
	TypeDeviceClaims    uint32 = 15
	TypeTicketChecksum  uint32 = 16
	TypeAttributesInfo  uint32 = 17
	TypeRequestor       uint32 = 18
	TypeFullChecksum    uint32 = 19
)

// The sizes the format fixes (authdata.h:68-73).
//
// Alignment is 8 and so is the header, which is a coincidence worth
// not relying on: the header is a buffer count and a version, both
// 32-bit, and the alignment is what every payload's offset is a
// multiple of.
const (
	Alignment     = 8
	headerLen     = 8
	bufferLen     = 16
	signatureHdr  = 4
	clientInfoHdr = 10

	// maxBuffers is upstream's MAX_BUFFERS (pac.c:32). A count
	// outside 1..4096 is refused before anything is allocated,
	// which is what makes a fuzzed count harmless.
	maxBuffers = 4096

	// ntEpoch is the seconds between the NT epoch and the Unix
	// one (authdata.h:74). An NT time is that many tenths of a
	// microsecond.
	ntEpoch = 11644473600
)

// Errors this package reports.
var (
	// ErrMalformed is a PAC that does not parse.
	ErrMalformed = errors.New("malformed PAC")

	// ErrNoBuffer is a buffer type the PAC does not carry.
	ErrNoBuffer = errors.New("no such PAC buffer")

	// ErrDuplicate is an attempt to add a buffer type the PAC
	// already has, which upstream reports as EEXIST
	// (pac.c:51-52).
	ErrDuplicate = errors.New("PAC buffer already present")

	// ErrModified is a checksum that does not verify.
	ErrModified = errors.New("PAC checksum does not verify")
)

// buffer is one PAC_INFO_BUFFER: a type, a length and an offset.
//
// The offset is 64-bit **on the wire** even though a uint32 bounds
// the whole encoding (authdata.h:52-56), so it is kept as one here
// rather than narrowed on the way in -- narrowing would hide an
// out-of-range value that the parser is supposed to refuse.
type buffer struct {
	typ    uint32
	size   uint32
	offset uint64
}

// PAC is a parsed or under-construction Privilege Attribute
// Certificate.
//
// It holds the whole encoding, header included, because every
// checksum is over a span of it: the buffer table is a view of data
// rather than the authority for it, and signing writes the table back
// into data in place.
type PAC struct {
	data    []byte
	buffers []buffer
	version uint32
}

// New is an empty PAC: no buffers, and a header of the right length
// with nothing in it yet (krb5_pac_init, pac.c:218-243).
//
// The header is not encoded until Sign runs, which is the one thing
// about this format that reads as a mistake and is not -- see
// encodeHeader.
func New() *PAC {
	return &PAC{data: make([]byte, headerLen)}
}

// Bytes is the PAC's encoding.
func (p *PAC) Bytes() []byte { return p.data }

// Types lists the buffer types in the order they appear
// (krb5_pac_get_types, pac.c:178-196).
//
// The order is worth preserving rather than sorting: it is the order
// a re-signing reproduces, and upstream's own octet comparison
// against a Windows KDC's output depends on it.
func (p *PAC) Types() []uint32 {
	out := make([]uint32, len(p.buffers))
	for i := range p.buffers {
		out[i] = p.buffers[i].typ
	}
	return out
}

// Get returns a copy of one buffer's contents.
func (p *PAC) Get(typ uint32) ([]byte, error) {
	b, err := p.locate(typ)
	if err != nil {
		return nil, err
	}
	out := make([]byte, b.size)
	copy(out, p.span(b))
	return out, nil
}

// locate finds the single buffer of a type.
//
// Two buffers of one type is an error rather than a choice
// (k5_pac_locate_buffer, pac.c:127-156): a PAC carrying two server
// checksums has no answer to which one is the server checksum, and
// picking either would let one be the one that verifies while the
// other is the one a reader uses.
func (p *PAC) locate(typ uint32) (*buffer, error) {
	var found *buffer
	for i := range p.buffers {
		if p.buffers[i].typ != typ {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf(
				"%w: two buffers of type %d",
				ErrMalformed, typ)
		}
		found = &p.buffers[i]
	}
	if found == nil {
		return nil, fmt.Errorf("%w: type %d",
			ErrNoBuffer, typ)
	}
	return found, nil
}

// span is a buffer's contents inside p.data, aliased rather than
// copied, which is what lets signing write a checksum in place.
func (p *PAC) span(b *buffer) []byte {
	return p.data[b.offset : b.offset+uint64(b.size)]
}
