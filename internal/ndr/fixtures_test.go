package ndr

// The three S4U_DELEGATION_INFO buffers upstream captured from
// communication with Active Directory 2019 (kdc/t_ndr.c:40-116),
// extracted from the C arrays mechanically.
//
// They are the whole anchor for this package, and they have to be:
// the layout is not derivable from the specification, because an
// RPC_UNICODE_STRING's length fields move depending on where the
// string sits in the struct and neither implementation decodes that
// generically. What can be checked is that decoding one of these and
// re-encoding it reproduces the octets -- which is exactly the test
// upstream runs (t_ndr.c:165-171).
//
// The three cases are, in upstream's own words:
//
//	svc1/... to svc2/...
//	svc1/... to longsvc/...        (an odd-length name, so padded)
//	svc1/... to svc2/... then to longsvc/...   (two transited)

const refDIShort = "" +
	" 01 10 08 00 CC CC CC CC A0 00 00 00" +
	" 00 00 00 00 00 00 02 00 2A 00 2C 00" +
	" 04 00 02 00 01 00 00 00 08 00 02 00" +
	" 16 00 00 00 00 00 00 00 15 00 00 00" +
	" 73 00 76 00 63 00 32 00 2F 00 61 00" +
	" 64 00 73 00 65 00 72 00 76 00 65 00" +
	" 72 00 2E 00 61 00 64 00 2E 00 74 00" +
	" 65 00 73 00 74 00 00 00 01 00 00 00" +
	" 3A 00 3C 00 0C 00 02 00 1E 00 00 00" +
	" 00 00 00 00 1D 00 00 00 73 00 76 00" +
	" 63 00 31 00 2F 00 61 00 64 00 73 00" +
	" 65 00 72 00 76 00 65 00 72 00 2E 00" +
	" 61 00 64 00 2E 00 74 00 65 00 73 00" +
	" 74 00 40 00 41 00 44 00 2E 00 54 00" +
	" 45 00 53 00 54 00 00 00"

const refDILong = "" +
	" 01 10 08 00 CC CC CC CC A8 00 00 00" +
	" 00 00 00 00 00 00 02 00 30 00 32 00" +
	" 04 00 02 00 01 00 00 00 08 00 02 00" +
	" 19 00 00 00 00 00 00 00 18 00 00 00" +
	" 6C 00 6F 00 6E 00 67 00 73 00 76 00" +
	" 63 00 2F 00 61 00 64 00 73 00 65 00" +
	" 72 00 76 00 65 00 72 00 2E 00 61 00" +
	" 64 00 2E 00 74 00 65 00 73 00 74 00" +
	" 01 00 00 00 3A 00 3C 00 0C 00 02 00" +
	" 1E 00 00 00 00 00 00 00 1D 00 00 00" +
	" 73 00 76 00 63 00 31 00 2F 00 61 00" +
	" 64 00 73 00 65 00 72 00 76 00 65 00" +
	" 72 00 2E 00 61 00 64 00 2E 00 74 00" +
	" 65 00 73 00 74 00 40 00 41 00 44 00" +
	" 2E 00 54 00 45 00 53 00 54 00 00 00" +
	" 00 00 00 00"

const refDIDouble = "" +
	" 01 10 08 00 CC CC CC CC F8 00 00 00" +
	" 00 00 00 00 00 00 02 00 30 00 32 00" +
	" 04 00 02 00 02 00 00 00 08 00 02 00" +
	" 19 00 00 00 00 00 00 00 18 00 00 00" +
	" 6C 00 6F 00 6E 00 67 00 73 00 76 00" +
	" 63 00 2F 00 61 00 64 00 73 00 65 00" +
	" 72 00 76 00 65 00 72 00 2E 00 61 00" +
	" 64 00 2E 00 74 00 65 00 73 00 74 00" +
	" 02 00 00 00 3A 00 3C 00 0C 00 02 00" +
	" 3A 00 3C 00 10 00 02 00 1E 00 00 00" +
	" 00 00 00 00 1D 00 00 00 73 00 76 00" +
	" 63 00 31 00 2F 00 61 00 64 00 73 00" +
	" 65 00 72 00 76 00 65 00 72 00 2E 00" +
	" 61 00 64 00 2E 00 74 00 65 00 73 00" +
	" 74 00 40 00 41 00 44 00 2E 00 54 00" +
	" 45 00 53 00 54 00 00 00 1E 00 00 00" +
	" 00 00 00 00 1D 00 00 00 73 00 76 00" +
	" 63 00 32 00 2F 00 61 00 64 00 73 00" +
	" 65 00 72 00 76 00 65 00 72 00 2E 00" +
	" 61 00 64 00 2E 00 74 00 65 00 73 00" +
	" 74 00 40 00 41 00 44 00 2E 00 54 00" +
	" 45 00 53 00 54 00 00 00 00 00 00 00"

// Two blobs from upstream's fuzzing that must be refused
// (t_ndr.c:118-128). The first has a corrupt common header and a
// transited-service count of 0xffffffff; the second a payload length
// that does not match.
const refDIFuzz1 = "" +
	" 01 10 08 20 20 20 20 20 24 00 00 00" +
	" 20 20 20 20 20 20 20 20 20 20 20 20" +
	" 20 20 20 20 20 20 20 20 20 FF FF FF" +
	" FF 20 20 20 20 20 20 20 00 00 00 00" +
	" 20 20 20 20"

const refDIFuzz2 = "" +
	" 01 10 08 00 00 FF FF FF 24 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 1E 00 1E 00 00 00 00 1E 16 00 00" +
	" 1E 00 00 00 00 1E 00 00 00 00 00 00" +
	" 00 00 00 1E"
