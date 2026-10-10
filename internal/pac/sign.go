package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// UsageAppDataCksum is KRB5_KEYUSAGE_APP_DATA_CKSUM (krb5.hin:960),
// the key usage every PAC checksum is computed at -- all four of
// them, under two different keys.
const UsageAppDataCksum crypto.Usage = 17

// Sign computes the PAC's checksums and returns its encoding
// (sign_pac, pac_sign.c:208-284).
//
// **The order is load-bearing and is not the order the buffers are
// created in.** Three zero-filled buffers go in first -- server,
// privsvr, and on a service ticket the full checksum -- then the
// header is encoded *into* the data so that it is inside everything
// signed, and only then are the checksums computed, in the order
// full, server, privsvr. Each covers the ones written before it:
//
//   - the full checksum covers the whole PAC with all three checksum
//     buffers still zero, under the privsvr key;
//   - the server checksum covers the whole PAC *including the full
//     checksum just written*, under the server key;
//   - the privsvr checksum covers **only the server checksum's
//     bytes**, minus its four-octet type prefix, under the privsvr
//     key.
//
// So the privsvr checksum is a signature over a signature, which is
// what lets a KDC confirm that it was the one that vouched for this
// PAC without re-reading any of the contents.
//
// isService decides whether the full checksum exists at all, and the
// caller gets that from ShouldHaveTicketSignature.
func (p *PAC) Sign(
	ci *ClientInfo,
	server, privsvr wire.EncryptionKey,
	isService bool,
) ([]byte, error) {
	if ci != nil {
		if err := p.SetClientInfo(*ci); err != nil {
			return nil, err
		}
	}
	types, err := p.insertChecksums(server, privsvr, isService)
	if err != nil {
		return nil, err
	}
	if err := p.encodeHeader(); err != nil {
		return nil, err
	}
	if err := p.computeAll(server, privsvr, types,
		isService); err != nil {
		return nil, err
	}
	out := make([]byte, len(p.data))
	copy(out, p.data)
	// Upstream zeroes the header again on the way out
	// (pac_sign.c:280-281) so a PAC object never holds a stale
	// encoded header. It only matters if the object is signed
	// twice, and a reimplementation that kept it would diverge on
	// the second signing.
	clear(p.data[:headerLen+len(p.buffers)*bufferLen])
	return out, nil
}

// cksumTypes is the checksum type for each key, which is the
// enctype's mandatory one and nothing the caller may choose.
type cksumTypes struct {
	server, privsvr crypto.CksumType
}

// insertChecksums creates the zero-filled buffers, in upstream's
// creation order: server, privsvr, then the full checksum.
func (p *PAC) insertChecksums(
	server, privsvr wire.EncryptionKey,
	isService bool,
) (cksumTypes, error) {
	var t cksumTypes
	var err error
	t.server, err = p.insert(TypeServerChecksum, server)
	if err != nil {
		return t, err
	}
	t.privsvr, err = p.insert(TypePrivsvrChecksum, privsvr)
	if err != nil {
		return t, err
	}
	if isService {
		_, err = p.insert(TypeFullChecksum, privsvr)
	}
	return t, err
}

// insert adds, or re-zeroes, one checksum buffer and writes its type
// into the first four octets (insert_checksum, pac_sign.c:98-139).
//
// Re-signing reuses the buffer that is there, and refuses if it is
// the wrong size for the checksum this key needs -- which is how a
// PAC signed under one enctype cannot be quietly re-signed under
// another with a different checksum length.
func (p *PAC) insert(
	typ uint32,
	key wire.EncryptionKey,
) (crypto.CksumType, error) {
	prof, err := crypto.Profile(crypto.EncType(key.KeyType))
	if err != nil {
		return 0, err
	}
	want := signatureHdr + prof.TrailerLength
	span, err := p.reuseOrAdd(typ, want)
	if err != nil {
		return 0, err
	}
	binary.LittleEndian.PutUint32(span,
		uint32(prof.RequiredCksum))
	return prof.RequiredCksum, nil
}

// reuseOrAdd returns a zeroed span of exactly want octets for a
// buffer type, adding it if it is absent.
func (p *PAC) reuseOrAdd(typ uint32, want int) ([]byte, error) {
	if b, err := p.locate(typ); err == nil {
		if int(b.size) != want {
			return nil, fmt.Errorf(
				"%w: type %d is %d octets, want %d",
				ErrMalformed, typ, b.size, want)
		}
		span := p.span(b)
		clear(span)
		return span, nil
	}
	return p.add(typ, want)
}

// encodeHeader writes the buffer count, the version and the whole
// buffer table into the front of the data (encode_header,
// pac_sign.c:141-181).
//
// **This is why the header is not kept encoded as buffers are
// added.** Every checksum covers the header, so the header has to be
// final before any of them is computed; writing it on each Add would
// mean writing it once more here anyway, and leaving it stale between
// the two would be the bug.
func (p *PAC) encodeHeader() error {
	n := len(p.buffers)
	hdr := headerLen + n*bufferLen
	if len(p.data) < hdr {
		return fmt.Errorf("%w: %d buffers in %d octets",
			ErrMalformed, n, len(p.data))
	}
	binary.LittleEndian.PutUint32(p.data, uint32(n))
	binary.LittleEndian.PutUint32(p.data[4:], p.version)
	for i := range p.buffers {
		b := &p.buffers[i]
		e := p.data[headerLen+i*bufferLen:]
		binary.LittleEndian.PutUint32(e, b.typ)
		binary.LittleEndian.PutUint32(e[4:], b.size)
		binary.LittleEndian.PutUint64(e[8:], b.offset)
		if err := check(b, uint64(hdr),
			uint64(len(p.data))); err != nil {
			return err
		}
	}
	return nil
}

// computeAll runs the three checksums in their signing order.
func (p *PAC) computeAll(
	server, privsvr wire.EncryptionKey,
	t cksumTypes,
	isService bool,
) error {
	if isService {
		_, err := p.compute(TypeFullChecksum, privsvr,
			t.privsvr, p.data)
		if err != nil {
			return err
		}
	}
	sum, err := p.compute(TypeServerChecksum, server,
		t.server, p.data)
	if err != nil {
		return err
	}
	_, err = p.compute(TypePrivsvrChecksum, privsvr,
		t.privsvr, sum)
	return err
}

// compute writes one checksum over data into a buffer, and returns
// the checksum's own octets -- which is what the privsvr checksum
// then covers (compute_pac_checksum, pac_sign.c:184-206).
func (p *PAC) compute(
	typ uint32,
	key wire.EncryptionKey,
	ct crypto.CksumType,
	data []byte,
) ([]byte, error) {
	prof, err := crypto.ProfileForCksum(ct)
	if err != nil {
		return nil, err
	}
	b, err := p.locate(typ)
	if err != nil {
		return nil, err
	}
	// The checksum is computed over a snapshot, because the
	// destination is inside the data being covered: writing into
	// p.data as the hash reads it would be a different message.
	msg := make([]byte, len(data))
	copy(msg, data)
	sum, err := prof.Checksum(key.KeyValue, msg,
		UsageAppDataCksum)
	if err != nil {
		return nil, err
	}
	out := p.span(b)[signatureHdr:]
	if len(sum) != len(out) {
		return nil, fmt.Errorf(
			"%w: a %d-octet checksum in %d octets",
			ErrMalformed, len(sum), len(out))
	}
	copy(out, sum)
	return out, nil
}

// cksumProfile is the enctype row a key belongs to, which is what
// says the checksum type its checksums take.
func cksumProfile(
	key wire.EncryptionKey,
) (*crypto.EncProfile, error) {
	return crypto.Profile(crypto.EncType(key.KeyType))
}
