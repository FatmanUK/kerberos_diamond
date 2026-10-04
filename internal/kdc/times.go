package kdc

import "time"

// Kerberos timestamps are a 32-bit count of seconds since the epoch,
// and upstream compares them *unsigned*: ts_after, ts_delta, ts_min
// and friends cast to uint32 first (include/k5-int.h:2325-2361). The
// effect is that the negative half of the range represents 2038 to
// 2106 rather than 1902 to 1969, and the ordering at the protocol
// boundary is the unsigned one.
//
// A Go port that compared time.Time values directly would agree with
// upstream for every date before 2038 and disagree about every expiry
// after it. These helpers reproduce the C exactly by doing the
// comparison on the 32-bit value, and the Go times are only ever
// derived from that.

// kdcInfinity is upstream's "no limit" timestamp: krb5_timestamp -1
// (kdc/extern.c:43). Read unsigned it is 0xFFFFFFFF, so it means
// 2106-02-07T06:28:15Z and not a moment in 1969.
const kdcInfinity = uint32(0xFFFFFFFF)

// stamp converts a time to the 32-bit value the protocol carries.
func stamp(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	return uint32(t.Unix())
}

// unstamp converts back.
func unstamp(s uint32) time.Time {
	return time.Unix(int64(s), 0).UTC()
}

// tsAfter is upstream's ts_after: an unsigned comparison.
func tsAfter(a, b uint32) bool { return a > b }

// tsMin returns the earlier of two timestamps, unsigned.
func tsMin(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// tsDelta is upstream's ts_delta: the difference as a *signed* 32-bit
// value, computed in unsigned arithmetic so it wraps rather than
// overflowing. An interval longer than 68 years comes back negative,
// which is exactly the case kdc_get_ticket_endtime guards against.
func tsDelta(a, b uint32) int32 { return int32(a - b) }

// tsIncr is upstream's ts_incr: add a signed interval, wrapping.
func tsIncr(s uint32, delta int32) uint32 {
	return s + uint32(delta)
}

// optStamp converts a timestamp that is absent when zero, keeping the
// Go zero time for absent rather than mapping it to 1970.
func optStamp(s uint32) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return unstamp(s)
}
