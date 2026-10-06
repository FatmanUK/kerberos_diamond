package wire

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// Protocol error codes, from the order of the entries in
// lib/krb5/error_tables/krb5_err.et. The wire code is the API code
// minus ERROR_TABLE_BASE_krb5, and anything outside 0..128 is sent as
// KRB_ERR_GENERIC instead (kdc_util.c:691-698).
const (
	ErrCodeNone               int32 = 0
	ErrCodeNameExp            int32 = 1
	ErrCodeServiceExp         int32 = 2
	ErrCodeBadPvno            int32 = 3
	ErrCodeCPrincipalUnknown  int32 = 6
	ErrCodeSPrincipalUnknown  int32 = 7
	ErrCodePrincipalNotUnique int32 = 8
	ErrCodeNullKey            int32 = 9
	ErrCodeCannotPostdate     int32 = 10
	ErrCodeNeverValid         int32 = 11
	ErrCodePolicy             int32 = 12
	ErrCodeBadOption          int32 = 13
	ErrCodeETypeNoSupp        int32 = 14
	ErrCodeSumTypeNoSupp      int32 = 15
	ErrCodePADataTypeNoSupp   int32 = 16
	ErrCodeClientRevoked      int32 = 18
	ErrCodeKeyExpired         int32 = 23
	ErrCodePreauthFailed      int32 = 24
	ErrCodePreauthRequired    int32 = 25
	ErrCodeServerNoMatch      int32 = 26
	ErrCodeMustUseUser2User   int32 = 27
	ErrCodePathNotAccepted    int32 = 28
	ErrCodeSvcUnavailable     int32 = 29
	ErrCodeGeneric            int32 = 60
)

// The AP errors, which a TGS exchange answers with because the
// request carries an AP-REQ. Same table, continuing from 31
// (lib/krb5/error_tables/krb5_err.et).
const (
	ErrCodeBadIntegrity int32 = 31
	ErrCodeTktExpired   int32 = 32
	ErrCodeTktNYV       int32 = 33
	ErrCodeRepeat       int32 = 34
	ErrCodeNotUs        int32 = 35
	ErrCodeBadMatch     int32 = 36
	ErrCodeSkew         int32 = 37
	ErrCodeBadVersion   int32 = 39
	ErrCodeMsgType      int32 = 40
	ErrCodeModified     int32 = 41
	ErrCodeBadKeyVer    int32 = 44
	ErrCodeNoKey        int32 = 45
	ErrCodeInappCksum   int32 = 50
)

// KRBError is the KDC's refusal. It is a message in its own right,
// not a status code: the fields a client actually reads are ErrorCode
// and, for the preauth handshake, EData.
type KRBError struct {
	// CTime and CUsec echo the client's clock and are optional.
	// CUsec is optional-when-zero, so a genuine microsecond of 0
	// cannot be told from an absent one -- while SUsec, which is
	// mandatory, can be zero perfectly well
	// (asn1_k_encode.c:914-917).
	CTime time.Time
	CUsec int32

	STime time.Time
	SUsec int32

	ErrorCode int32

	// CRealm and CName are optional and travel together.
	CRealm string
	CName  *PrincipalName

	Realm string
	SName PrincipalName

	// EText is optional and empty means absent. EData carries the
	// PA-ETYPE-INFO2 sequence on a KDC_ERR_PREAUTH_REQUIRED,
	// which is the only reason the AS exchange reads it.
	EText string
	EData []byte
}

type derKRBError struct {
	Pvno    int32 `asn1:"explicit,tag:0"`
	MsgType int32 `asn1:"explicit,tag:1"`

	CTime time.Time `asn1:"explicit,optional,generalized,tag:2"`
	CUsec int32     `asn1:"explicit,optional,tag:3"`
	STime time.Time `asn1:"explicit,generalized,tag:4"`
	SUsec int32     `asn1:"explicit,tag:5"`

	ErrorCode int32 `asn1:"explicit,tag:6"`

	CRealm asn1.RawValue    `asn1:"explicit,optional,tag:7"`
	CName  derPrincipalName `asn1:"explicit,optional,tag:8"`

	Realm asn1.RawValue    `asn1:"explicit,tag:9"`
	SName derPrincipalName `asn1:"explicit,tag:10"`

	EText asn1.RawValue `asn1:"explicit,optional,tag:11"`
	EData []byte        `asn1:"explicit,optional,tag:12"`
}

// MarshalKRBError encodes a KRB-ERROR.
func MarshalKRBError(e KRBError) ([]byte, error) {
	d := derKRBError{
		Pvno:      Pvno,
		MsgType:   MsgKRBError,
		CTime:     optTime(e.CTime),
		CUsec:     e.CUsec,
		STime:     kerberosTime(e.STime),
		SUsec:     e.SUsec,
		ErrorCode: e.ErrorCode,
		Realm:     ctxGstring(9, e.Realm),
		SName:     e.SName.der(),
		EText:     optCtxGstring(11, e.EText),
		EData:     e.EData,
	}
	if e.CName != nil {
		d.CRealm = optCtxGstring(7, e.CRealm)
		d.CName = e.CName.der()
	}
	return asn1.MarshalWithParams(d, appParams(tagKRBError))
}

// UnmarshalKRBError decodes a KRB-ERROR.
func UnmarshalKRBError(b []byte) (KRBError, error) {
	var d derKRBError
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagKRBError)); err != nil {
		return KRBError{}, derErr("KRB-ERROR", err)
	}
	if err := checkPvno(d.Pvno); err != nil {
		return KRBError{}, err
	}
	if d.MsgType != MsgKRBError {
		return KRBError{}, msgTypeErr(d.MsgType, MsgKRBError)
	}
	return d.value()
}

func (d derKRBError) value() (KRBError, error) {
	realm, err := ctxGstringValue(d.Realm)
	if err != nil {
		return KRBError{}, err
	}
	sname, err := d.SName.value()
	if err != nil {
		return KRBError{}, err
	}
	etext, _, err := optCtxGstringValue(d.EText)
	if err != nil {
		return KRBError{}, err
	}
	e := KRBError{
		CTime:     d.CTime,
		CUsec:     d.CUsec,
		STime:     d.STime,
		SUsec:     d.SUsec,
		ErrorCode: d.ErrorCode,
		Realm:     realm,
		SName:     sname,
		EText:     etext,
		EData:     d.EData,
	}
	return e, d.client(&e)
}

// client fills in the optional client name and realm.
func (d derKRBError) client(e *KRBError) error {
	if len(d.CName.Components) == 0 {
		return nil
	}
	n, err := d.CName.value()
	if err != nil {
		return err
	}
	crealm, _, err := optCtxGstringValue(d.CRealm)
	if err != nil {
		return err
	}
	e.CName = &n
	e.CRealm = crealm
	return nil
}

// Error makes a KRB-ERROR usable as a Go error, so a decoded refusal
// can be returned rather than translated at every call site.
func (e KRBError) Error() string {
	if e.EText != "" {
		return fmt.Sprintf("KRB-ERROR %d: %s",
			e.ErrorCode, e.EText)
	}
	return fmt.Sprintf("KRB-ERROR %d", e.ErrorCode)
}
