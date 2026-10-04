// Package wire encodes and decodes the Kerberos 5 protocol messages.
//
// Nothing is implemented yet. The types the AS exchange needs come
// first: AS-REQ, KDC-REQ-BODY, AS-REP, EncASRepPart, Ticket,
// EncTicketPart, PrincipalName, EncryptedData, PA-DATA, KRB-ERROR and
// KDC-PROXY-MESSAGE.
//
// The approach is encoding/asn1 struct tags for the bulk, with
// hand-written helpers for what it cannot express: GeneralString, the
// KerberosFlags BIT STRING, and the fields upstream omits when they
// are zero rather than when they are absent.
package wire
