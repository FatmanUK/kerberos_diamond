package wire

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// KDCProxyMessage is the MS-KKDCP envelope: a plain SEQUENCE with no
// application tag (asn1_k_encode.c:1637-1650), POSTed as the body of
// an HTTPS request.
type KDCProxyMessage struct {
	// KerbMessage is the *TCP* payload, 4-byte big-endian length
	// prefix included, not the bare DER message
	// (sendto_kdc.c:604, make_proxy_request). Omitting the prefix
	// is the first thing to check when a client rejects a reply.
	KerbMessage []byte

	// TargetDomain is the realm, and is what lets one proxy serve
	// several. Absent when empty.
	TargetDomain string

	// DCLocatorHint is a Windows domain-controller selection
	// hint, absent when zero. Nothing here produces one.
	DCLocatorHint int32
}

type derKDCProxyMessage struct {
	KerbMessage   []byte        `asn1:"explicit,tag:0"`
	TargetDomain  asn1.RawValue `asn1:"explicit,optional,tag:1"`
	DCLocatorHint int32         `asn1:"explicit,optional,tag:2"`
}

// MarshalKDCProxyMessage encodes a KDC-PROXY-MESSAGE.
func MarshalKDCProxyMessage(m KDCProxyMessage) ([]byte, error) {
	return asn1.Marshal(derKDCProxyMessage{
		KerbMessage:   m.KerbMessage,
		TargetDomain:  optCtxGstring(1, m.TargetDomain),
		DCLocatorHint: m.DCLocatorHint,
	})
}

// UnmarshalKDCProxyMessage decodes a KDC-PROXY-MESSAGE.
func UnmarshalKDCProxyMessage(
	b []byte) (KDCProxyMessage, error) {
	var d derKDCProxyMessage
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return KDCProxyMessage{}, derErr(
			"KDC-PROXY-MESSAGE", err)
	}
	domain, _, err := optCtxGstringValue(d.TargetDomain)
	if err != nil {
		return KDCProxyMessage{}, err
	}
	return KDCProxyMessage{
		KerbMessage:   d.KerbMessage,
		TargetDomain:  domain,
		DCLocatorHint: d.DCLocatorHint,
	}, nil
}

// MaxFrame caps a framed message, at exactly the figure upstream's
// TCP listener uses: it allocates a 1 MiB connection buffer and
// rejects any declared length above bufsiz - 4, the four bytes being
// the prefix itself (net-server.c:1278,1391). The proxy has to agree
// with that, or a client would see a different limit over HTTPS than
// over TCP.
const MaxFrame = 1024*1024 - 4

// Frame prefixes a message with the 4-byte big-endian length that
// Kerberos-over-TCP uses, and that KDC-PROXY-MESSAGE carries inside
// kerb-message.
func Frame(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	copy(out[4:], msg)
	return out
}

// Unframe strips the length prefix, checking it against the data
// actually present rather than trusting it.
func Unframe(framed []byte) ([]byte, error) {
	if len(framed) < 4 {
		return nil, fmt.Errorf(
			"%w: framed message is %d bytes, want >= 4",
			ErrMalformed, len(framed))
	}
	n := binary.BigEndian.Uint32(framed[:4])
	if n > MaxFrame {
		return nil, fmt.Errorf(
			"%w: frame claims %d bytes, limit is %d",
			ErrMalformed, n, MaxFrame)
	}
	if int(n) != len(framed)-4 {
		return nil, fmt.Errorf(
			"%w: frame claims %d bytes, %d follow",
			ErrMalformed, n, len(framed)-4)
	}
	return framed[4:], nil
}
