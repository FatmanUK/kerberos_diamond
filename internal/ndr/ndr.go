// Package ndr encodes and decodes the one NDR structure Kerberos
// needs: the PAC's S4U_DELEGATION_INFO buffer.
//
// **This is the only NDR anywhere in the picture.** `pac.c` contains
// none, and `authdata.h:45-48` says decoding buffer contents is left
// to the application; upstream's whole tree has one NDR file,
// `kdc/ndr.c`, for this buffer alone. It exists because a
// constrained-delegation ticket records the chain it came through,
// and Microsoft chose a DCE RPC serialisation for that record.
//
// It is also not general NDR and does not pretend to be. Upstream's
// own header comment says so of the hardest part: an
// RPC_UNICODE_STRING is a *conformant-varying array*, so where its
// Length and MaximumLength appear in the stream depends on whether
// the string is at the top level of the struct or not (DCE-1.1-RPC
// 14.3.7.2, MS-RPCE 4.7) -- and neither upstream nor this decodes
// that generically. What both do is read and write the exact layout
// Active Directory produces, which is anchored by captured bytes
// rather than derived from the specification.
package ndr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// DelegationInfo is PAC_S4U_DELEGATION_INFO ([MS-PAC] 2.9).
type DelegationInfo struct {
	// ProxyTarget is the service the ticket being issued is for,
	// unparsed **without** its realm (update_delegation_info,
	// kdc_authdata.c:412-419).
	ProxyTarget string

	// TransitedServices is the chain, each entry **with** its
	// realm (:421-427). The asymmetry with ProxyTarget is
	// upstream's and is visible in the captured bytes: the target
	// is `svc2/adserver.ad.test' and a transited service is
	// `svc1/adserver.ad.test@AD.TEST'.
	TransitedServices []string
}

// ErrMalformed reports a buffer that is not the layout this package
// reads.
var ErrMalformed = errors.New("malformed NDR")

// The two headers every MS-RPCE type-serialised buffer starts with
// (MS-RPCE 2.2.6.1 and 2.2.6.2).
//
// The filler in the common header is 0xcccccccc rather than zero,
// which is what uninitialised stack looked like on the machine that
// first produced one; it is part of the format now and both ends
// write it.
const (
	headerLen  = 16
	version    = 1
	endianness = 0x10
	commonLen  = 8
	filler     = 0xcccccccc
)

// firstPointer is where Microsoft's referent identifiers start, and
// they increment by four (write_ptr, kdc/ndr.c:36-42).
//
// They are identifiers and not addresses, so their values carry no
// meaning -- but they are in the octets, so reproducing a captured
// buffer means reproducing the sequence.
const firstPointer = 0x00020000

// Marshal encodes a DelegationInfo (ndr_enc_delegation_info,
// kdc/ndr.c:176-253).
//
// The layout is a struct whose variable-length members are
// *deferred*: each one leaves a pointer and a length pair in the
// fixed part and its contents go afterwards, in order. So the proxy
// target's contents come before the transited services' length pairs,
// which come before their contents -- which is the order below and is
// not the order the struct is written in.
func Marshal(di DelegationInfo) ([]byte, error) {
	target := wcharPointer(di.ProxyTarget)
	n := len(di.TransitedServices)
	var b []byte
	b = append(b, version, endianness, commonLen, 0)
	b = le32(b, filler)
	// The payload length is written back once it is known.
	b = le32(b, 0)
	b = le32(b, 0)

	p := pointers{}
	b = p.write(b)
	b = le16(b, uint16(2*target.wchars))
	b = le16(b, uint16(2*(target.wchars+1)))
	b = p.write(b)
	b = le32(b, uint32(n))
	b = p.write(b)
	b = append(b, target.bytes...)
	b = le32(b, uint32(n))

	svcs := make([]wchars, n)
	for i, s := range di.TransitedServices {
		svcs[i] = wcharPointer(s)
		b = le16(b, uint16(2*svcs[i].wchars))
		b = le16(b, uint16(2*(svcs[i].wchars+1)))
		b = p.write(b)
	}
	for i := range svcs {
		b = append(b, svcs[i].bytes...)
	}
	// Padded to eight, because RPC_UNICODE_STRING aligns on four
	// and the buffer as a whole on eight (kdc/ndr.c:231-233).
	if len(b)%8 != 0 {
		b = le32(b, 0)
	}
	binary.LittleEndian.PutUint32(b[8:],
		uint32(len(b)-headerLen))
	return b, nil
}

// pointers hands out Microsoft's referent identifiers in Microsoft's
// sequence.
type pointers struct{ next uint32 }

func (p *pointers) write(b []byte) []byte {
	if p.next == 0 {
		p.next = firstPointer
	}
	out := le32(b, p.next)
	p.next += 4
	return out
}

// wchars is a string already encoded as the format wants it.
type wchars struct {
	wchars int
	bytes  []byte
}

// wcharPointer encodes one string (enc_wchar_pointer,
// kdc/ndr.c:27-62): a maximum count of **one more** than the
// characters, a zero offset, the actual count, the UTF-16LE units,
// and a two-octet pad when the count is odd.
//
// The maximum count is one more because the array is sized for a
// terminator the actual count excludes -- so the string travels
// unterminated inside space for a terminated one, which is what
// `Buffer is not a String' in upstream's comment means.
func wcharPointer(s string) wchars {
	units := utf16.Encode([]rune(s))
	var b []byte
	b = le32(b, uint32(len(units)+1))
	b = le32(b, 0)
	b = le32(b, uint32(len(units)))
	for _, u := range units {
		b = le16(b, u)
	}
	if len(units)%2 == 1 {
		b = le16(b, 0)
	}
	return wchars{wchars: len(units), bytes: b}
}

func le16(b []byte, v uint16) []byte {
	return binary.LittleEndian.AppendUint16(b, v)
}

func le32(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}

// Unmarshal decodes a DelegationInfo (ndr_dec_delegation_info,
// kdc/ndr.c:255-331).
//
// Most of the fixed part is read and discarded, and that is not
// laziness: the pointers are referent identifiers with no meaning
// outside the buffer, and the length pairs are redundant with the
// counts inside each deferred string. What *is* checked is the two
// headers and the payload length, because those are what tell a
// malformed buffer from a short one -- and this buffer arrives from
// the network inside a PAC.
//
// **Reused pointers are not handled**, which upstream says of itself
// (:291-292): a delegation loop could in principle encode one string
// twice by pointing at it twice, and neither implementation reads
// that.
func Unmarshal(data []byte) (DelegationInfo, error) {
	in := &reader{b: data}
	if err := checkHeaders(in, len(data)); err != nil {
		return DelegationInfo{}, err
	}
	// A pointer, the proxy target's length pair, another pointer,
	// the transited count, and a third pointer -- all redundant
	// with what follows (:296-310).
	in.skip(4 + 2 + 2 + 4 + 4 + 4)
	target, err := in.wcharPointer()
	if err != nil {
		return DelegationInfo{}, err
	}
	n := in.le32()
	// The bound is upstream's and it is what stops a claimed
	// count from allocating against a short buffer: each entry
	// costs at least eight octets of deferred header (:313-317).
	if int(n) > len(data)/8 {
		return DelegationInfo{}, fmt.Errorf(
			"%w: %d transited services in %d octets",
			ErrMalformed, n, len(data))
	}
	in.skip(8 * int(n))
	out := DelegationInfo{ProxyTarget: target}
	for i := uint32(0); i < n; i++ {
		s, err := in.wcharPointer()
		if err != nil {
			return DelegationInfo{}, err
		}
		out.TransitedServices = append(
			out.TransitedServices, s)
	}
	if in.bad {
		return DelegationInfo{}, fmt.Errorf(
			"%w: ran off the end", ErrMalformed)
	}
	return out, nil
}

// checkHeaders reads the common and private headers and refuses
// anything but the one shape (:273-288).
func checkHeaders(in *reader, total int) error {
	v, e := in.byte(), in.byte()
	hdr := in.le16()
	in.skip(4)
	if v != version || e != endianness || hdr != commonLen {
		return fmt.Errorf(
			"%w: version %d, endianness %#x, header %d",
			ErrMalformed, v, e, hdr)
	}
	n := in.le32()
	in.skip(4)
	if total < headerLen ||
		int(n) != total-headerLen {
		return fmt.Errorf(
			"%w: payload length %d in %d octets",
			ErrMalformed, n, total)
	}
	return nil
}

// reader is a little-endian cursor that remembers having run off the
// end rather than reporting it at each step, which is upstream's
// k5input and is what keeps the decoder readable.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.take(n) }
func (r *reader) byte() byte { return r.take(1)[0] }
func (r *reader) le16() uint16 {
	return binary.LittleEndian.Uint16(r.take(2))
}
func (r *reader) le32() uint32 {
	return binary.LittleEndian.Uint32(r.take(4))
}

// wcharPointer reads one deferred string (dec_wchar_pointer,
// kdc/ndr.c:68-91).
func (r *reader) wcharPointer() (string, error) {
	r.skip(4) // the maximum count
	r.skip(4) // the offset, "should not be checked"
	n := r.le32()
	if n > 1<<30 {
		return "", fmt.Errorf("%w: a %d-character string",
			ErrMalformed, n)
	}
	raw := r.take(int(n) * 2)
	if r.bad {
		return "", fmt.Errorf("%w: a string ran off the end",
			ErrMalformed)
	}
	units := make([]uint16, n)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if n%2 == 1 {
		r.skip(2)
	}
	return string(utf16.Decode(units)), nil
}
