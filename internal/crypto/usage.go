package crypto

// Usage is a Kerberos key usage number, which separates the keys used
// for different purposes even when they derive from one long-term
// key.
//
// The numbers are from include/krb5/krb5.hin:944-1007. They are NOT
// unique: 26 and 27 are each shared between the SAM, S4U X.509 and
// referral mechanisms, so a usage is a label on a message, never a
// key into a table of them.
type Usage uint32

// The usages the AS exchange needs. The wider set is added as the
// messages that carry them are implemented.
const (
	// UsageASReqPAEncTS is the PA-ENC-TIMESTAMP in an AS-REQ,
	// encrypted under the client's long-term key.
	UsageASReqPAEncTS Usage = 1

	// UsageKDCRepTicket is a ticket's enc-part, encrypted under
	// the service's key -- for an AS-REP, the krbtgt's.
	UsageKDCRepTicket Usage = 2

	// UsageASRepEncPart is an AS-REP's enc-part, encrypted under
	// the client's long-term key (or, under FAST, a key
	// strengthened from it).
	UsageASRepEncPart Usage = 3

	// UsageTGSReqAuthCksum keys the authenticator's checksum over
	// the TGS-REQ body, and UsageTGSReqAuth encrypts the
	// authenticator itself -- both under the TGT's session key.
	// Two usages for one message is what stops a captured
	// checksum being replayed as a ciphertext or the reverse.
	UsageTGSReqAuthCksum Usage = 6
	UsageTGSReqAuth      Usage = 7

	// UsageAPReqAuth encrypts an ordinary application AP-REQ's
	// authenticator (krb5.hin:954). It is distinct from
	// UsageTGSReqAuth, and FAST is where that distinction becomes
	// load-bearing: the AP-REQ a client puts in a FAST armor
	// field is an application one, so its authenticator is at 11
	// even though it reaches the KDC inside a KDC request.
	UsageAPReqAuth Usage = 11

	// UsageAPRepEncPart and UsageKRBPrivEncPart are the halves of
	// an application exchange's reply (krb5.hin:955-956). Only
	// the password-change protocol uses them here: its reply
	// carries an AP-REP and a KRB-PRIV, in that order, in one
	// frame.
	UsageAPRepEncPart   Usage = 12
	UsageKRBPrivEncPart Usage = 13

	// UsageTGSRepEncPartSessKey and UsageTGSRepEncPartSubKey
	// encrypt a TGS-REP's enc-part. Which one applies depends on
	// whether the client put a subkey in its authenticator, and
	// getting it wrong produces a reply the client cannot read
	// while looking correct from the KDC's side.
	UsageTGSRepEncPartSessKey Usage = 8
	UsageTGSRepEncPartSubKey  Usage = 9

	// UsageASReq keys the checksum a KDC puts in the reply's
	// encrypted padata when the client asked for one (RFC 6806).
	// It is 56, far from the others, and is listed separately in
	// the header for that reason (krb5.hin:1000).
	UsageASReq Usage = 56

	// The RFC 6113 usages (krb5.hin:994-999). Four for the tunnel
	// itself and two for the encrypted-challenge factor inside
	// it, one per direction -- a challenge and its answer must
	// not be interchangeable.
	UsageFASTReqCksum   Usage = 50
	UsageFASTEnc        Usage = 51
	UsageFASTRep        Usage = 52
	UsageFASTFinished   Usage = 53
	UsageEncChallClient Usage = 54
	UsageEncChallKDC    Usage = 55

	// UsagePAFXCookie is far out of the sequence because the
	// cookie is MIT's own extension rather than part of RFC 6113
	// (krb5.hin:1006).
	UsagePAFXCookie Usage = 513
)
