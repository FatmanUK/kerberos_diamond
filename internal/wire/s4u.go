package wire

import "encoding/asn1"

// PAForUser is [MS-SFU] 2.2.1, the *legacy* protocol-transition
// request a Windows 2003 server sends (asn1_k_encode.c:950-958).
//
// The name and the realm are two fields of one principal, which is
// why they are separate here: the C holds a krb5_principal and
// encodes its name into [0] and its realm into [1].
type PAForUser struct {
	UserName  PrincipalName
	UserRealm string

	// Cksum is keyed with the **TGT's session key** and is not
	// over DER at all -- see S4UForUserChecksumData.
	Cksum Checksum

	// AuthPackage is a label the client sends and nothing reads.
	// Windows sends "Kerberos"; upstream's own test fixture sends
	// "krb5data" (ktest.c), and the KDC only ever feeds it to the
	// checksum.
	AuthPackage string
}

type derPAForUser struct {
	UserName    derPrincipalName `asn1:"explicit,tag:0"`
	UserRealm   asn1.RawValue    `asn1:"explicit,tag:1"`
	Cksum       derChecksum      `asn1:"explicit,tag:2"`
	AuthPackage asn1.RawValue    `asn1:"explicit,tag:3"`
}

// MarshalPAForUser encodes a PA-FOR-USER.
func MarshalPAForUser(p PAForUser) ([]byte, error) {
	return asn1.Marshal(derPAForUser{
		UserName:    p.UserName.der(),
		UserRealm:   ctxGstring(1, p.UserRealm),
		Cksum:       derChecksum(p.Cksum),
		AuthPackage: ctxGstring(3, p.AuthPackage),
	})
}

// UnmarshalPAForUser decodes a PA-FOR-USER.
func UnmarshalPAForUser(b []byte) (PAForUser, error) {
	var d derPAForUser
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return PAForUser{}, derErr("PA-FOR-USER", err)
	}
	name, err := d.UserName.value()
	if err != nil {
		return PAForUser{}, err
	}
	realm, err := ctxGstringValue(d.UserRealm)
	if err != nil {
		return PAForUser{}, err
	}
	pkg, err := ctxGstringValue(d.AuthPackage)
	if err != nil {
		return PAForUser{}, err
	}
	return PAForUser{
		UserName:    name,
		UserRealm:   realm,
		Cksum:       Checksum(d.Cksum),
		AuthPackage: pkg,
	}, nil
}

// S4UOptUseReplyKeyUsage asks the KDC to sign the reply's S4UUserID
// at key usage **27** instead of 26
// (KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE, k5-int.h:772).
//
// It is the only bit of the options field a KDC acts on: the reply
// masks everything else away (kdc_make_s4u2self_rep,
// kdc_util.c:1470-1472), the same way PA-PAC-OPTIONS is masked.
const S4UOptUseReplyKeyUsage Flags = 0x20000000

// S4UOptCheckLogonHours is the other bit [MS-SFU] defines
// (k5-int.h:771). MIT neither reads it nor echoes it, so it is named
// here only so that a reader of the options field knows what the
// missing bit is.
const S4UOptCheckLogonHours Flags = 0x40000000

// S4UUserID is [MS-SFU] 2.2.2's inner structure
// (asn1_k_encode.c:960-978).
type S4UUserID struct {
	// Nonce must equal the KDC-REQ's own nonce, which is what
	// binds this padata to the request it arrived in
	// (verify_s4u_x509_user_checksum, kdc_util.c:1360-1361).
	Nonce int32

	// UserName is **optional**, and its absence is how a
	// certificate-only request names nobody: upstream's
	// is_s4u_principal_present tests the component count, so a
	// principal of no components is omitted rather than encoded
	// empty (:964-970). The realm is required either way.
	UserName  *PrincipalName
	UserRealm string

	// SubjectCert is a DER certificate, or nothing. Upstream
	// hands it to the KDB module and parses none of it, and
	// t_s4u.py:219-221 exploits that by using a fake PEM that is
	// just base64 of a principal name.
	SubjectCert []byte

	Options Flags
}

type derS4UUserID struct {
	Nonce       int32            `asn1:"explicit,tag:0"`
	UserName    derPrincipalName `asn1:"optional,explicit,tag:1"`
	UserRealm   asn1.RawValue    `asn1:"explicit,tag:2"`
	SubjectCert []byte           `asn1:"optional,explicit,tag:3"`
	Options     asn1.BitString   `asn1:"optional,explicit,tag:4"`
}

// MarshalS4UUserID encodes an S4UUserID.
func MarshalS4UUserID(u S4UUserID) ([]byte, error) {
	d := derS4UUserID{
		Nonce:       u.Nonce,
		UserRealm:   ctxGstring(2, u.UserRealm),
		SubjectCert: u.SubjectCert,
	}
	if u.UserName != nil && len(u.UserName.Components) > 0 {
		d.UserName = u.UserName.der()
	}
	if u.Options != 0 {
		d.Options = u.Options.bitString()
	}
	return asn1.Marshal(d)
}

// UnmarshalS4UUserID decodes an S4UUserID.
func UnmarshalS4UUserID(b []byte) (S4UUserID, error) {
	var d derS4UUserID
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return S4UUserID{}, derErr("S4UUserID", err)
	}
	return s4uUserIDValue(d)
}

func s4uUserIDValue(d derS4UUserID) (S4UUserID, error) {
	realm, err := ctxGstringValue(d.UserRealm)
	if err != nil {
		return S4UUserID{}, err
	}
	out := S4UUserID{
		Nonce:       d.Nonce,
		UserRealm:   realm,
		SubjectCert: d.SubjectCert,
	}
	if len(d.UserName.Components) > 0 {
		name, err := d.UserName.value()
		if err != nil {
			return S4UUserID{}, err
		}
		out.UserName = &name
	}
	if len(d.Options.Bytes) > 0 {
		f, err := flagsFromBitString(d.Options)
		if err != nil {
			return S4UUserID{}, err
		}
		out.Options = f
	}
	return out, nil
}

// PAS4UX509User is [MS-SFU] 2.2.2, the protocol-transition request a
// Windows 2008 server sends (asn1_k_encode.c:980-985).
type PAS4UX509User struct {
	UserID S4UUserID

	// Cksum is over the **received octets** of field [0], not
	// over a re-encoding -- see S4UUserIDField.
	Cksum Checksum
}

type derPAS4UX509User struct {
	UserID derS4UUserID `asn1:"explicit,tag:0"`
	Cksum  derChecksum  `asn1:"explicit,tag:1"`
}

// MarshalPAS4UX509User encodes a PA-S4U-X509-USER.
func MarshalPAS4UX509User(p PAS4UX509User) ([]byte, error) {
	var d derPAS4UX509User
	raw, err := MarshalS4UUserID(p.UserID)
	if err != nil {
		return nil, err
	}
	if _, err := asn1.Unmarshal(raw, &d.UserID); err != nil {
		return nil, derErr("S4UUserID", err)
	}
	d.Cksum = derChecksum(p.Cksum)
	return asn1.Marshal(d)
}

// UnmarshalPAS4UX509User decodes a PA-S4U-X509-USER.
func UnmarshalPAS4UX509User(b []byte) (PAS4UX509User, error) {
	var d derPAS4UX509User
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return PAS4UX509User{}, derErr(
			"PA-S4U-X509-USER", err)
	}
	id, err := s4uUserIDValue(d.UserID)
	if err != nil {
		return PAS4UX509User{}, err
	}
	return PAS4UX509User{
		UserID: id, Cksum: Checksum(d.Cksum),
	}, nil
}

// S4UUserIDBytes returns the **received octets** of a
// PA-S4U-X509-USER's user-id field, which is what its checksum covers
// (fetch_asn1_field(data, 1, 0), kdc_util.c:1376).
//
// Not a re-encoding. A peer whose encoder differs from this one's in
// any way -- a length form, an optional field's presence rule --
// would have checksummed *its* bytes, and re-encoding before checking
// would compare a different message. The TGS body checksum has the
// same problem and ReqBodyBytes exists for it; this is the same trick
// one level in, and upstream's comment at :1368-1370 says so
// explicitly: "This is similar to the behaviour in
// kdc_process_tgs_req()".
//
// The caller still falls back to a re-encode if this fails to verify,
// which is also upstream's (:1382-1397) and is the tolerance that
// lets an implementation whose encoder differs interoperate anyway.
func S4UUserIDBytes(der []byte) ([]byte, error) {
	seq, err := tlvContent(der)
	if err != nil {
		return nil, err
	}
	return ctxField(seq, 0)
}

// S4UForUserChecksumData builds what a PA-FOR-USER's checksum is
// computed over (verify_for_user_checksum, kdc_util.c:1264-1288).
//
// **It is not DER at all**, which is the thing to know about it: a
// four-octet name type, then each name component, then the realm,
// then the auth-package, concatenated with no separators and no
// lengths. Two consequences, and both are real:
//
//   - **the name type is little-endian**, in a protocol that is
//     big-endian everywhere else, because [MS-SFU] specified it from
//     a Windows implementation (:1263-1268);
//   - **there are no separators**, so a/b and ab with the same realm
//     checksum identically -- the same collision the default salt
//     has, and for the same reason.
//
// Neither is a defect to be fixed here. A checksum is only useful if
// both ends compute it over the same octets.
func S4UForUserChecksumData(p PAForUser) []byte {
	out := make([]byte, 4, 32)
	t := uint32(p.UserName.Type)
	out[0] = byte(t)
	out[1] = byte(t >> 8)
	out[2] = byte(t >> 16)
	out[3] = byte(t >> 24)
	for _, c := range p.UserName.Components {
		out = append(out, c...)
	}
	out = append(out, p.UserRealm...)
	return append(out, p.AuthPackage...)
}
