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

	// UsageASReq keys the checksum a KDC puts in the reply's
	// encrypted padata when the client asked for one (RFC 6806).
	// It is 56, far from the others, and is listed separately in
	// the header for that reason (krb5.hin:1000).
	UsageASReq Usage = 56
)
