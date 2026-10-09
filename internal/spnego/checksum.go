package spnego

import "encoding/binary"

// CksumTypeGSSCB is the checksum type the Kerberos GSS mechanism puts
// in an authenticator (gssapiP_krb5.h:95). It is not a checksum type
// at all: RFC 4121 §4.1.1 appropriates the authenticator's cksum
// field to carry structured data, and 0x8003 is the marker saying so.
const CksumTypeGSSCB int32 = 0x8003

// The GSS context flags (gssapi.hin:137-146 and gssapi_ext.h:229-231,
// :605).
const (
	FlagDeleg uint32 = 1 << iota
	FlagMutual
	FlagReplay
	FlagSequence
	FlagConf
	FlagInteg
	FlagAnon
	FlagProtReady
	FlagTrans
)

const (
	FlagChannelBound uint32 = 0x0800
	FlagDCEStyle     uint32 = 0x1000
	FlagIdentify     uint32 = 0x2000
	FlagExtError     uint32 = 0x4000
	FlagDelegPolicy  uint32 = 0x8000
)

// InitiatorFlags is the subset of flags an acceptor takes from the
// initiator's checksum (INITIATOR_FLAGS,
// accept_sec_context.c:413-417).
//
// Deleg is pointedly absent. A client asking for delegation does not
// get the flag by asking: upstream sets it only after a forwarded
// credential has actually been read out of the checksum and stored
// (:578). So a context's flags report what happened rather than what
// was requested, and an acceptor that merely passed the request
// through would be telling an application it holds a credential it
// does not have.
const InitiatorFlags = FlagInteg | FlagConf | FlagMutual |
	FlagReplay | FlagSequence | FlagDCEStyle | FlagIdentify |
	FlagExtError

// cbLen is the length of the channel-bindings hash in an 0x8003
// checksum: an MD5, always (CB_MD5_LEN,
// accept_sec_context.c:406-407). The algorithm is not negotiable and
// not replaceable, which is why nothing here is configurable.
const cbLen = 16

// minLen is the fixed part: a four-octet length, the bindings, and
// four octets of flags (MIN_8003_LEN, :409-411).
const minLen = 4 + cbLen + 4

// forCredsOption is the option identifier a delegated credential
// travels under (KRB5_GSS_FOR_CREDS_OPTION, gssapiP_krb5.h:110).
const forCredsOption = 1

// Checksum is the decoded contents of an 0x8003 authenticator
// checksum.
//
// Everything in it is little-endian, in a protocol that is big-endian
// everywhere else. That is not a transcription error: RFC 4121
// §4.1.1 specifies it, because the field was designed around a
// particular implementation's host order and the mistake outlived the
// reason.
type Checksum struct {
	// ChannelBindings is the MD5 the initiator computed over its
	// channel bindings, or sixteen zero octets when it had none.
	ChannelBindings [cbLen]byte

	// Flags is the flags word as it arrived, unmasked. Use
	// Accepted for the subset an acceptor may honour.
	Flags uint32

	// DelegCred is a KRB-CRED the initiator forwarded, which this
	// project never reads: a credential delegated to an
	// administrative surface is a credential that surface could
	// spend as the user, and there is nothing here that wants to.
	DelegCred []byte

	// Extensions are the trailing extension records, which exist
	// for IAKERB's Finished message and nothing else.
	Extensions []Extension
}

// Extension is a trailing record in an 0x8003 checksum. Its tag and
// length are four octets *big*-endian, where the delegation option's
// are two octets little-endian -- a difference upstream's own comment
// calls out (accept_sec_context.c:582-583).
type Extension struct {
	ID   uint32
	Body []byte
}

// Accepted is the flags an acceptor may honour, which is the
// initiator's word masked. Deleg is reported separately because a
// delegated credential has to have arrived for it to mean anything.
func (c *Checksum) Accepted() uint32 {
	return c.Flags & InitiatorFlags
}

// Mutual reports whether the initiator asked for mutual
// authentication, which is what decides whether an AP-REP is sent at
// all (accept_sec_context.c:989).
func (c *Checksum) Mutual() bool {
	return c.Accepted()&FlagMutual != 0
}

// ParseChecksum decodes an 0x8003 checksum (process_checksum,
// accept_sec_context.c:519-601).
func ParseChecksum(b []byte) (*Checksum, error) {
	if len(b) < minLen {
		return nil, ErrBadToken
	}
	// Upstream refuses a bindings length that is not exactly
	// sixteen rather than skipping over whatever was declared
	// (:527-532), which closes the obvious way to make the rest
	// of the structure land where an attacker chose.
	if binary.LittleEndian.Uint32(b[:4]) != cbLen {
		return nil, ErrBadToken
	}
	c := &Checksum{}
	copy(c.ChannelBindings[:], b[4:4+cbLen])
	c.Flags = binary.LittleEndian.Uint32(b[4+cbLen : minLen])
	rest := b[minLen:]
	if len(rest) >= 4 && c.Flags&FlagDeleg != 0 {
		cred, tail, err := delegOption(rest)
		if err != nil {
			return nil, err
		}
		c.DelegCred, rest = cred, tail
	}
	exts, err := extensions(rest)
	if err != nil {
		return nil, err
	}
	c.Extensions = exts
	return c, nil
}

// delegOption reads the forwarded-credential option, whose header is
// two octets of identifier and two of length, both little-endian.
//
// The gate is upstream's and is worth keeping as it stands: the
// option is read only when four octets remain *and* the initiator set
// the delegation flag (:555). Neither alone is enough -- without the
// flag the four octets are an extension, and without the octets the
// flag is an unfulfilled request.
func delegOption(b []byte) ([]byte, []byte, error) {
	id := binary.LittleEndian.Uint16(b[:2])
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	if id != forCredsOption {
		return nil, nil, ErrBadToken
	}
	if len(b) < 4+n {
		return nil, nil, ErrBadToken
	}
	return b[4 : 4+n], b[4+n:], nil
}

// extensions reads the trailing records, four octets of identifier
// and four of length, both big-endian (:582-601).
func extensions(b []byte) ([]Extension, error) {
	var out []Extension
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, ErrBadToken
		}
		n := binary.BigEndian.Uint32(b[4:8])
		if uint64(len(b)-8) < uint64(n) {
			return nil, ErrBadToken
		}
		out = append(out, Extension{
			ID:   binary.BigEndian.Uint32(b[:4]),
			Body: b[8 : 8+n],
		})
		b = b[8+n:]
	}
	return out, nil
}

// Marshal encodes an 0x8003 checksum, which exists so that a test can
// build one the way an initiator does (make_gss_checksum,
// init_sec_context.c:332-345).
func (c *Checksum) Marshal() []byte {
	out := make([]byte, 0, minLen+len(c.DelegCred))
	out = binary.LittleEndian.AppendUint32(out, cbLen)
	out = append(out, c.ChannelBindings[:]...)
	out = binary.LittleEndian.AppendUint32(out, c.Flags)
	if c.DelegCred != nil {
		out = binary.LittleEndian.AppendUint16(out,
			forCredsOption)
		out = binary.LittleEndian.AppendUint16(out,
			uint16(len(c.DelegCred)))
		out = append(out, c.DelegCred...)
	}
	for _, e := range c.Extensions {
		out = binary.BigEndian.AppendUint32(out, e.ID)
		out = binary.BigEndian.AppendUint32(out,
			uint32(len(e.Body)))
		out = append(out, e.Body...)
	}
	return out
}
