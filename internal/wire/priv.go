package wire

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// HostAddress is one network address, and the only address type this
// project constructs rather than passing through.
//
// The project's own notes record that addresses travel as opaque DER
// and that nothing here parses one, which stays true of a ticket's
// caddr and of a request's addresses. This type exists because
// EncKRBPrivPart's s-address is **mandatory** (asn1_k_encode.c:812),
// so a password-change reply cannot be built without one.
type HostAddress struct {
	Type    int32
	Address []byte
}

// derHostAddress is the SEQUENCE (asn1_k_encode.c:214-220).
type derHostAddress struct {
	Type    int32  `asn1:"explicit,tag:0"`
	Address []byte `asn1:"explicit,tag:1"`
}

// AddrTypeDirectional is MIT's ADDRTYPE_DIRECTIONAL (krb5.hin:325),
// an address that names a *direction* rather than a host: 00000000
// from the initiator and 00000001 from the acceptor.
//
// It is what upstream falls back to when it cannot determine the
// address a request arrived on (schpw.c:290, kpropd.c:1203), and for
// a KDC reached over HTTPS that is always the case -- a kpasswd frame
// arrives inside an HTTP request body and the socket underneath
// belongs to the transport, not to Kerberos. So this is the address
// this project sends, deliberately, and not for want of looking one
// up.
const AddrTypeDirectional int32 = 3

// DirectionalInit and DirectionalAccept are the two
// (lib/krb5/os/addr.c:36-41).
func DirectionalInit() HostAddress {
	return HostAddress{
		Type:    AddrTypeDirectional,
		Address: []byte{0, 0, 0, 0},
	}
}

func DirectionalAccept() HostAddress {
	return HostAddress{
		Type:    AddrTypeDirectional,
		Address: []byte{0, 0, 0, 1},
	}
}

// KRBPriv carries application data encrypted and integrity-protected
// under a session key. The password-change protocol is the only thing
// in this project that uses one, and it is how a new password reaches
// the KDC.
type KRBPriv struct {
	EncPart EncryptedData
}

// derKRBPriv is APPLICATION 21 (asn1_k_encode.c:815-823).
//
// The enc-part is at context tag **3** and not 2, which is not a
// mistake: RFC 4120 leaves 2 unused in KRB-PRIV, and upstream's
// encoder says so by simply not having one. A reader who assumed the
// fields were numbered without gaps would write a message no client
// can decode.
type derKRBPriv struct {
	Vno     int32            `asn1:"explicit,tag:0"`
	MsgType int32            `asn1:"explicit,tag:1"`
	EncPart derEncryptedData `asn1:"explicit,tag:3"`
}

// MarshalKRBPriv encodes a KRB-PRIV.
func MarshalKRBPriv(p KRBPriv) ([]byte, error) {
	return asn1.MarshalWithParams(derKRBPriv{
		Vno:     Pvno,
		MsgType: MsgPriv,
		EncPart: p.EncPart.der(),
	}, appParams(tagPriv))
}

// UnmarshalKRBPriv decodes a KRB-PRIV.
func UnmarshalKRBPriv(b []byte) (KRBPriv, error) {
	var d derKRBPriv
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagPriv)); err != nil {
		return KRBPriv{}, derErr("KRB-PRIV", err)
	}
	if err := checkPvno(d.Vno); err != nil {
		return KRBPriv{}, err
	}
	if d.MsgType != MsgPriv {
		return KRBPriv{}, msgTypeErr(d.MsgType, MsgPriv)
	}
	return KRBPriv{EncPart: d.EncPart.value()}, nil
}

// EncKRBPrivPart is the sealed half: the application's own bytes,
// plus the freshness evidence that stops them being replayed.
type EncKRBPrivPart struct {
	// UserData is whatever the application put in. For a password
	// change it is the new password, or a DER ChangePasswdData
	// for the set-password form.
	UserData []byte

	// Timestamp, Usec and SeqNumber are each absent when zero.
	// Upstream sends either the timestamp pair or the sequence
	// number depending on the auth context's flags, and the
	// password-change service asks for the sequence number
	// (KRB5_AUTH_CONTEXT_DO_SEQUENCE, schpw.c:106).
	Timestamp time.Time
	Usec      int32
	SeqNumber uint32

	// SAddress is the sender's and is mandatory; RAddress is the
	// recipient's and is not.
	//
	// Neither is compared here, and for the password-change
	// service neither is compared by upstream either: it sets no
	// remote address before reading, on purpose, so that a client
	// behind a NAT still works, and explains itself at
	// schpw.c:152-159. The client does the same in the other
	// direction (changepw.c:166), so an s-address in a reply is
	// never checked -- it only has to be *there*.
	SAddress HostAddress
	RAddress *HostAddress
}

// derEncKRBPrivPart is APPLICATION 28 (asn1_k_encode.c:805-814).
type derEncKRBPrivPart struct {
	UserData []byte `asn1:"explicit,tag:0"`

	Stamp time.Time `asn1:"explicit,optional,generalized,tag:1"`

	Usec int32    `asn1:"explicit,optional,tag:2"`
	Seq  *big.Int `asn1:"explicit,optional,tag:3"`

	SAddress derHostAddress `asn1:"explicit,tag:4"`
	RAddress derHostAddress `asn1:"explicit,optional,tag:5"`
}

// MarshalEncKRBPrivPart encodes a KRB-PRIV's sealed half.
func MarshalEncKRBPrivPart(
	p EncKRBPrivPart,
) ([]byte, error) {
	d := derEncKRBPrivPart{
		UserData: p.UserData,
		Stamp:    p.Timestamp.UTC().Truncate(time.Second),
		Usec:     p.Usec,
		Seq:      seqnoDER(p.SeqNumber),
		SAddress: derHostAddress{
			Type:    p.SAddress.Type,
			Address: p.SAddress.Address,
		},
	}
	if p.RAddress != nil {
		d.RAddress = derHostAddress{
			Type:    p.RAddress.Type,
			Address: p.RAddress.Address,
		}
	}
	return asn1.MarshalWithParams(d,
		appParams(tagEncPrivPart))
}

// UnmarshalEncKRBPrivPart decodes a KRB-PRIV's sealed half.
func UnmarshalEncKRBPrivPart(
	b []byte,
) (EncKRBPrivPart, error) {
	var d derEncKRBPrivPart
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagEncPrivPart)); err != nil {
		return EncKRBPrivPart{},
			derErr("EncKrbPrivPart", err)
	}
	seq, err := seqnoValue(d.Seq)
	if err != nil {
		return EncKRBPrivPart{}, err
	}
	p := EncKRBPrivPart{
		UserData:  d.UserData,
		Timestamp: d.Stamp,
		Usec:      d.Usec,
		SeqNumber: seq,
		SAddress: HostAddress{
			Type:    d.SAddress.Type,
			Address: d.SAddress.Address,
		},
	}
	if len(d.RAddress.Address) > 0 {
		p.RAddress = &HostAddress{
			Type:    d.RAddress.Type,
			Address: d.RAddress.Address,
		}
	}
	return p, nil
}

// ChangePasswdData is the RFC 3244 set-password request: a new
// password, and optionally whose it is.
//
// It travels as a KRB-PRIV's user data when the frame's version is
// 0xff80. For the older version 1 the user data is the raw password
// with no structure at all, which is the whole difference between
// changing your own password and setting somebody else's.
//
// An absent target means "mine" (schpw.c:170-196). Upstream's own
// struct carries one principal and splits it across two fields on the
// wire -- target's name at [1] and the same target's realm at [2]
// (asn1_k_encode.c:941-947) -- so the two are always both present or
// both absent in anything it writes.
type ChangePasswdData struct {
	NewPassword []byte

	// TargName and TargRealm name the principal whose password is
	// being set, and are empty for a self change.
	TargName  *PrincipalName
	TargRealm string
}

// derChangePasswdData is a bare SEQUENCE with no application tag,
// which is why it is the one message here that cannot be anchored
// against reference_encode.out: upstream's test program does not
// cover encode_krb5_setpw_req.
type derChangePasswdData struct {
	NewPassword []byte           `asn1:"explicit,tag:0"`
	TargName    derPrincipalName `asn1:"explicit,optional,tag:1"`
	TargRealm   asn1.RawValue    `asn1:"explicit,optional,tag:2"`
}

// MarshalChangePasswdData encodes a set-password request.
func MarshalChangePasswdData(
	c ChangePasswdData,
) ([]byte, error) {
	d := derChangePasswdData{NewPassword: c.NewPassword}
	if c.TargName != nil {
		d.TargName = c.TargName.der()
	}
	if c.TargRealm != "" {
		d.TargRealm = ctxGstring(2, c.TargRealm)
	}
	return asn1.Marshal(d)
}

// UnmarshalChangePasswdData decodes a set-password request.
func UnmarshalChangePasswdData(
	b []byte,
) (ChangePasswdData, error) {
	var d derChangePasswdData
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return ChangePasswdData{},
			derErr("ChangePasswdData", err)
	}
	c := ChangePasswdData{NewPassword: d.NewPassword}
	if len(d.TargName.Components) > 0 {
		n, err := d.TargName.value()
		if err != nil {
			return ChangePasswdData{}, err
		}
		c.TargName = &n
	}
	if len(d.TargRealm.Bytes) > 0 {
		realm, err := ctxGstringValue(d.TargRealm)
		if err != nil {
			return ChangePasswdData{}, err
		}
		c.TargRealm = realm
	}
	return c, nil
}
