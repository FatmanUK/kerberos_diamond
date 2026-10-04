// Package golden runs the same exchange against this KDC and against
// a Kerberos 5 built from the kerberos submodule, and compares what
// each answers.
//
// Nothing is implemented yet. It exists because porting a protocol by
// reading C is guesswork without an oracle.
//
// The comparison is of decoded messages, not bytes: every encryption
// prepends a fresh random confounder, so two runs of the same
// exchange with the same keys never agree octet for octet.
package golden
