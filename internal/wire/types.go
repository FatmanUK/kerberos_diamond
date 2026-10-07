package wire

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// Principal name types, from RFC 4120 section 6.2.
const (
	NTUnknown    int32 = 0
	NTPrincipal  int32 = 1
	NTSrvInst    int32 = 2
	NTSrvHst     int32 = 3
	NTEnterprise int32 = 10
)

// PrincipalName is a principal's name without its realm. The realm
// travels separately in every message that carries a name, which is
// why it is not a field here.
type PrincipalName struct {
	Type       int32
	Components []string
}

// String renders the name as Kerberos writes it, components separated
// by slashes. It does not include a realm.
func (p PrincipalName) String() string {
	out := ""
	for i, c := range p.Components {
		if i > 0 {
			out += "/"
		}
		out += c
	}
	return out
}

// Equal compares two names by their components, ignoring the name
// type. That is krb5_principal_compare_flags
// (lib/krb5/krb/princ_comp.c:70-136), which compares the realm and
// then the components and never looks at the type at all.
//
// Ignoring it is not laxity. The type is a hint about how a name was
// spelled -- NT-SRV-INST, NT-SRV-HST, NT-PRINCIPAL -- and the same
// principal arrives under different ones from different clients, so
// comparing it would refuse a request that named exactly the right
// principal. This implementation compared the type at first, and a
// forwarded request naming krbtgt as NT-SRV-HST was refused with
// SERVER_NOMATCH where upstream issued the ticket.
//
// The realm is not compared here because a PrincipalName does not
// carry one: a KDC-REQ-BODY has a single realm for both of its
// principals (asn1_k_encode.c:443-545), so a caller holding two names
// from one message has already established they share it.
func (p PrincipalName) Equal(q PrincipalName) bool {
	if len(p.Components) != len(q.Components) {
		return false
	}
	for i := range p.Components {
		if p.Components[i] != q.Components[i] {
			return false
		}
	}
	return true
}

// derPrincipalName is the DER shape of PrincipalName.
type derPrincipalName struct {
	Type       int32           `asn1:"explicit,tag:0"`
	Components []asn1.RawValue `asn1:"explicit,tag:1"`
}

func (p PrincipalName) der() derPrincipalName {
	return derPrincipalName{
		Type:       p.Type,
		Components: gstrings(p.Components),
	}
}

func (d derPrincipalName) value() (PrincipalName, error) {
	cs, err := gstringValues(d.Components)
	if err != nil {
		return PrincipalName{}, err
	}
	return PrincipalName{Type: d.Type, Components: cs}, nil
}

// EncryptedData is a ciphertext with the enctype and key version
// needed to decrypt it.
type EncryptedData struct {
	EType int32

	// KVNO is the key version. Zero means absent: upstream omits
	// the field when the value is zero rather than tracking
	// presence, so a kvno of 0 cannot be expressed and does not
	// occur.
	//
	// It is int32 and not the UInt32 RFC 4120 specifies, because
	// upstream deliberately encodes it signed
	// (asn1_k_encode.c:202-212): Windows read-only domain
	// controllers overload the high 16 bits for krbtgt principals
	// and write the result as a signed integer, and MIT matches
	// them for interop. encoding/asn1 has no unsigned support
	// anyway, so there is nothing lost by agreeing.
	KVNO int32

	Cipher []byte
}

// derEncryptedData is the DER shape. KVNO is optional, and Go's asn1
// omits an optional field only when it is the zero value, which is
// exactly upstream's rule here.
type derEncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int32  `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

func (e EncryptedData) der() derEncryptedData {
	return derEncryptedData{
		EType: e.EType, KVNO: e.KVNO, Cipher: e.Cipher,
	}
}

func (d derEncryptedData) value() EncryptedData {
	return EncryptedData{
		EType: d.EType, KVNO: d.KVNO, Cipher: d.Cipher,
	}
}

// EncryptionKey is a session or long-term key.
type EncryptionKey struct {
	KeyType  int32
	KeyValue []byte
}

type derEncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// Checksum is a keyed or unkeyed checksum.
type Checksum struct {
	Type     int32
	Checksum []byte
}

type derChecksum struct {
	Type     int32  `asn1:"explicit,tag:0"`
	Checksum []byte `asn1:"explicit,tag:1"`
}

// MarshalChecksum encodes a standalone Checksum, which is how the RFC
// 6806 reply checksum travels inside a PA-REQ-ENC-PA-REP.
func MarshalChecksum(c Checksum) ([]byte, error) {
	return asn1.Marshal(derChecksum{
		Type: c.Type, Checksum: c.Checksum,
	})
}

// UnmarshalChecksum decodes a standalone Checksum.
func UnmarshalChecksum(b []byte) (Checksum, error) {
	var d derChecksum
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return Checksum{}, derErr("Checksum", err)
	}
	return Checksum{Type: d.Type, Checksum: d.Checksum}, nil
}

// PAData is one pre-authentication item.
type PAData struct {
	Type  int32
	Value []byte
}

// Pre-authentication data types the AS exchange uses.
const (
	PATGSReq       int32 = 1
	PAEncTimestamp int32 = 2
	PAPWSalt       int32 = 3
	PAETypeInfo    int32 = 11
	PAETypeInfo2   int32 = 19
	PAReqEncPARep  int32 = 149
	PAPACRequest   int32 = 128
	PAFXCookie     int32 = 133
	PAFXFast       int32 = 136

	// PAFXError carries a KRB-ERROR *inside* a FAST reply, where
	// the outer message is the refusal and this is the real one
	// (RFC 6113; krb5.hin:1836). A client refuses a FAST error
	// container that does not hold one.
	PAFXError int32 = 137

	// PAEncryptedChallenge is the only pre-authentication factor
	// a FAST tunnel offers, because upstream refuses to offer
	// PA-ENC-TIMESTAMP whenever an armor key exists
	// (kdc/kdc_preauth_encts.c:38-43).
	PAEncryptedChallenge int32 = 138
)

// derPAData's first context tag is 1, not 0. There is no [0] field at
// all (asn1_k_encode.c:371-377), and a struct numbered from zero
// decodes as garbage.
type derPAData struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

// paDataDER returns nil, not an empty slice, for no padata.
// encoding/asn1 omits an optional field only when it equals the zero
// value, and an empty non-nil slice does not -- it would go on the
// wire as an empty SEQUENCE where upstream's DEFOPTIONALEMPTYTYPE
// writes nothing at all.
func paDataDER(ps []PAData) []derPAData {
	if len(ps) == 0 {
		return nil
	}
	out := make([]derPAData, len(ps))
	for i, p := range ps {
		out[i] = derPAData{Type: p.Type, Value: p.Value}
	}
	return out
}

func paDataValues(ds []derPAData) []PAData {
	if len(ds) == 0 {
		return nil
	}
	out := make([]PAData, len(ds))
	for i, d := range ds {
		out[i] = PAData{Type: d.Type, Value: d.Value}
	}
	return out
}

// LastReqEntry is one entry of a reply's last-req field.
type LastReqEntry struct {
	Type  int32
	Value time.Time
}

type derLastReqEntry struct {
	Type  int32     `asn1:"explicit,tag:0"`
	Value time.Time `asn1:"explicit,generalized,tag:1"`
}

// Transited encoding types, from krb5.hin:1854.
const (
	// TransitedDomainX500Compress is the only type defined, and
	// the KDC sets it on every ticket it issues even though the
	// contents are empty (do_as_req.c:689).
	TransitedDomainX500Compress int32 = 1
)

// TransitedEncoding records the realms a ticket crossed.
type TransitedEncoding struct {
	Type     int32
	Contents []byte
}

type derTransitedEncoding struct {
	Type     int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// checkPvno rejects a message whose protocol version is not 5.
//
// Upstream encodes pvno as a constant and, on decode, reports a
// mismatch as KRB5KDC_ERR_BAD_PVNO specifically rather than as a
// generic parse failure, because a peer speaking version 4 is worth
// telling apart from a peer speaking nonsense.
func checkPvno(got int32) error {
	if got != Pvno {
		return fmt.Errorf("%w: pvno is %d, want %d",
			ErrMalformed, got, Pvno)
	}
	return nil
}

func derKey(k EncryptionKey) derEncryptionKey {
	return derEncryptionKey{
		KeyType: k.KeyType, KeyValue: k.KeyValue,
	}
}

func (d derEncryptionKey) value() EncryptionKey {
	return EncryptionKey{
		KeyType: d.KeyType, KeyValue: d.KeyValue,
	}
}

func derTransited(t TransitedEncoding) derTransitedEncoding {
	return derTransitedEncoding{
		Type: t.Type, Contents: t.Contents,
	}
}

func (d derTransitedEncoding) value() TransitedEncoding {
	return TransitedEncoding{
		Type: d.Type, Contents: d.Contents,
	}
}

func derLastReqs(es []LastReqEntry) []derLastReqEntry {
	out := make([]derLastReqEntry, len(es))
	for i, e := range es {
		out[i] = derLastReqEntry{
			Type:  e.Type,
			Value: kerberosTime(e.Value),
		}
	}
	return out
}

func lastReqValues(ds []derLastReqEntry) []LastReqEntry {
	out := make([]LastReqEntry, len(ds))
	for i, d := range ds {
		out[i] = LastReqEntry{Type: d.Type, Value: d.Value}
	}
	return out
}

// MarshalPADataSeq encodes a bare SEQUENCE OF PA-DATA, which is what
// a KRB-ERROR's e-data carries (encode_krb5_padata_sequence, used at
// kdc/do_as_req.c:814). There is no application tag and no wrapper.
//
// An empty sequence encodes as the two bytes 30 00, which upstream's
// own reference output shows, so it is a thing that can legitimately
// travel -- unlike the optional padata field inside a KDC-REQ, which
// is omitted when empty.
func MarshalPADataSeq(ps []PAData) ([]byte, error) {
	ds := make([]derPAData, len(ps))
	for i, p := range ps {
		ds[i] = derPAData{Type: p.Type, Value: p.Value}
	}
	return asn1.Marshal(ds)
}

// UnmarshalPADataSeq decodes a bare SEQUENCE OF PA-DATA.
func UnmarshalPADataSeq(b []byte) ([]PAData, error) {
	var ds []derPAData
	if _, err := asn1.Unmarshal(b, &ds); err != nil {
		return nil, derErr("PA-DATA sequence", err)
	}
	return paDataValues(ds), nil
}

// MarshalEncryptedData encodes an EncryptedData on its own, which is
// how a PA-ENC-TIMESTAMP's value is carried.
func MarshalEncryptedData(e EncryptedData) ([]byte, error) {
	return asn1.Marshal(e.der())
}

// UnmarshalEncryptedData decodes a standalone EncryptedData.
func UnmarshalEncryptedData(b []byte) (EncryptedData, error) {
	var d derEncryptedData
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return EncryptedData{}, derErr("EncryptedData", err)
	}
	return d.value(), nil
}
