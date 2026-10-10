package pac

import (
	"encoding/binary"
	"fmt"
)

// Parse decodes a PAC (krb5_pac_parse, pac.c:267-336).
//
// Everything in the header travels **little-endian**, in a protocol
// that is big-endian everywhere else, because the format is
// Microsoft's rather than Kerberos'.
//
// The four refusals are all of the input validation there is, and
// each of them matters because a PAC arrives from the network inside
// a ticket:
//
//   - a version that is not zero (:282);
//   - a buffer count outside 1..4096 (:285-286) -- note the lower
//     bound: an empty PAC is refused, not parsed as empty;
//   - an offset that is not a multiple of eight (:308);
//   - and an offset or length outside the data, computed as
//     `size > len - offset' so that the sum cannot wrap (:311-315).
func Parse(data []byte) (*PAC, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("%w: %d octets",
			ErrMalformed, len(data))
	}
	n := binary.LittleEndian.Uint32(data)
	version := binary.LittleEndian.Uint32(data[4:])
	if version != 0 {
		return nil, fmt.Errorf("%w: version %d",
			ErrMalformed, version)
	}
	if n < 1 || n > maxBuffers {
		return nil, fmt.Errorf("%w: %d buffers",
			ErrMalformed, n)
	}
	hdr := headerLen + uint64(n)*bufferLen
	if uint64(len(data)) < hdr {
		return nil, fmt.Errorf(
			"%w: %d buffers do not fit in %d octets",
			ErrMalformed, n, len(data))
	}
	bufs, err := parseBuffers(data[headerLen:hdr], n, hdr,
		uint64(len(data)))
	if err != nil {
		return nil, err
	}
	p := &PAC{version: version, buffers: bufs,
		data: make([]byte, len(data))}
	copy(p.data, data)
	return p, nil
}

// parseBuffers reads the buffer table and bounds-checks every entry
// against the whole encoding's length.
func parseBuffers(
	table []byte,
	n uint32,
	hdr, total uint64,
) ([]buffer, error) {
	out := make([]buffer, n)
	for i := range out {
		e := table[i*bufferLen:]
		out[i] = buffer{
			typ:    binary.LittleEndian.Uint32(e),
			size:   binary.LittleEndian.Uint32(e[4:]),
			offset: binary.LittleEndian.Uint64(e[8:]),
		}
		if err := check(&out[i], hdr, total); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// check is the per-buffer validation, split out because the
// arithmetic is the part worth reading on its own.
func check(b *buffer, hdr, total uint64) error {
	if b.offset%Alignment != 0 {
		return fmt.Errorf(
			"%w: type %d is at %d, not a multiple of %d",
			ErrMalformed, b.typ, b.offset, Alignment)
	}
	// The order of these two comparisons is upstream's and it is
	// what makes the sum unable to wrap: offset is known to be
	// within the data before total-offset is computed.
	if b.offset < hdr || b.offset > total ||
		uint64(b.size) > total-b.offset {
		return fmt.Errorf(
			"%w: type %d is %d octets at %d, in %d",
			ErrMalformed, b.typ, b.size, b.offset, total)
	}
	return nil
}

// Add appends a buffer (k5_pac_add_buffer, pac.c:39-105).
//
// The format grows from the middle, which is the whole of this
// function's difficulty. A new buffer needs sixteen more octets of
// table, so **every existing payload moves sixteen octets later** and
// every recorded offset is bumped by sixteen before the payload is
// appended at the end.
//
// The payload is then zero-padded up to a multiple of eight, and the
// recorded size is the **unpadded** length -- so the padding is
// implicit in where the next buffer starts and is invisible in the
// table. A reader that trusted the gap between consecutive offsets
// would be reading padding as content.
func (p *PAC) Add(typ uint32, content []byte) error {
	_, err := p.locate(typ)
	if err == nil {
		return fmt.Errorf("%w: type %d", ErrDuplicate, typ)
	}
	if len(p.buffers) >= maxBuffers {
		return fmt.Errorf("%w: %d buffers",
			ErrMalformed, len(p.buffers))
	}
	_, err = p.add(typ, len(content))
	if err != nil {
		return err
	}
	copy(p.span(&p.buffers[len(p.buffers)-1]), content)
	return nil
}

// add makes room for a buffer of size octets and returns the span it
// occupies, zero-filled. It is Add without the copy, which is what a
// zero-filled checksum buffer wants.
func (p *PAC) add(typ uint32, size int) ([]byte, error) {
	table := headerLen + len(p.buffers)*bufferLen
	pad := 0
	if size%Alignment != 0 {
		pad = Alignment - size%Alignment
	}
	// The payload lands after the table has grown, which is why
	// the offset is the *old* length plus sixteen.
	at := uint64(len(p.data) + bufferLen)
	grown := make([]byte, len(p.data)+bufferLen+size+pad)
	copy(grown, p.data[:table])
	copy(grown[table+bufferLen:], p.data[table:])
	p.data = grown
	for i := range p.buffers {
		p.buffers[i].offset += bufferLen
	}
	p.buffers = append(p.buffers, buffer{
		typ: typ, size: uint32(size), offset: at,
	})
	return p.span(&p.buffers[len(p.buffers)-1]), nil
}
