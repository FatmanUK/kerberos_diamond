// Package crypto implements the Kerberos 5 encryption types.
//
// Nothing is implemented yet. The first two are
// aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 (RFC 3962),
// which is what an unconfigured client negotiates.
//
// Enctypes live in a dispatch table keyed by enctype number from the
// outset, even with two entries, because the families that follow
// derive keys differently and must be rows rather than special cases.
package crypto
