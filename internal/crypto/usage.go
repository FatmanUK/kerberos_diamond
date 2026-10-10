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

	// UsageTGSReqAuthDataSession and UsageTGSReqAuthDataSubkey
	// decrypt a TGS-REQ's enc-authorization-data
	// (krb5.hin:947-948).
	//
	// **Which one applies is decided by trying, not by looking.**
	// RFC 4120 says the subkey at usage 5 when a subkey is
	// present and the session key at usage 4 when it is not --
	// but krb5 before 1.7 always used the session key and usage
	// 4, so upstream tries that first and falls back to the
	// correct way (copy_request_authdata,
	// kdc/kdc_authdata.c:252-266, with a comment calling it
	// conservatism). A KDC that tried only the correct way would
	// refuse requests a stock KDC accepts.
	UsageTGSReqAuthDataSession Usage = 4
	UsageTGSReqAuthDataSubkey  Usage = 5

	// UsageTGSReqAuthCksum keys the authenticator's checksum over
	// the TGS-REQ body, and UsageTGSReqAuth encrypts the
	// authenticator itself -- both under the TGT's session key.
	// Two usages for one message is what stops a captured
	// checksum being replayed as a ciphertext or the reverse.
	UsageTGSReqAuthCksum Usage = 6
	UsageTGSReqAuth      Usage = 7

	// UsageAPReqAuthCksum keys the checksum in an application
	// AP-REQ's authenticator (krb5.hin:953). The Kerberos GSS
	// mechanism normally puts structured data in that field
	// instead of a checksum and so never uses this -- but Samba
	// sends a real checksum over empty data, and upstream
	// verifies it here rather than refusing the token
	// (accept_sec_context.c:494-512).
	UsageAPReqAuthCksum Usage = 10

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

// The two [MS-SFU] usages the S4U2Self padata is signed at
// (krb5.hin:981-983).
//
// They collide with KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRACKID and
// KRB5_KEYUSAGE_PA_SAM_RESPONSE, and upstream's header says so in a
// comment above each. The collision is harmless here for the reason
// it is harmless there: SAM-2 is effectively dead and is a declared
// non-goal, so no message in this project is ever ambiguous about
// which of the two a usage means.
//
// Which of the pair signs the *reply* is the client's choice:
// S4U-OPTS-USE-REPLY-KEY-USAGE asks for 27, and without it the reply
// is signed at 26 like the request (kdc_make_s4u2self_rep,
// kdc_util.c:1479-1482).
const (
	UsageS4UX509UserRequest Usage = 26
	UsageS4UX509UserReply   Usage = 27
)
