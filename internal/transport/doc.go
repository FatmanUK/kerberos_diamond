// Package transport carries Kerberos 5 messages over TLS.
//
// Nothing is implemented yet. There is no cleartext listener: the KDC
// is an HTTPS server speaking MS-KKDCP, and this package holds both
// halves of that — the server the KDC listens with, and the client
// kdiamond-proxy forwards with on behalf of clients built without a
// TLS module of their own.
package transport
