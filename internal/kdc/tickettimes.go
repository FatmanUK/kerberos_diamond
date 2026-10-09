package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// validateTicketTimes is krb5int_validate_times
// (lib/krb5/krb/valid_times.c:29-49), which every path that opens a
// presented ticket runs: krb5_rd_req calls it at rd_req_dec.c:627,
// and so FAST armor and the GSS acceptor and the password-change
// service all get it.
//
// Three details, each of which a reimplementation gets wrong by
// leaving it out:
//
//   - **both boundaries forgive clock skew.** A ticket that expired
//     within the skew window still opens, and one whose start time
//     is that far ahead opens too. A server that compared against
//     the raw times would refuse tickets a stock server accepts, for
//     clients whose clock is merely a little off -- which is the
//     condition skew exists for.
//   - **an absent start time means the authentication time.** A
//     ticket with no starttime is not a ticket valid from the
//     beginning of time.
//   - the two codes are TKT_NYV and TKT_EXPIRED, and they are
//     distinguishable on purpose: one says wait and the other says
//     get a new ticket.
func (k *KDC) validateTicketTimes(
	tkt wire.EncTicketPart,
	what string,
) (int32, string) {
	now := stamp(k.now())
	skew := uint32(k.skew().Seconds())
	start := stamp(tkt.StartTime)
	if tkt.StartTime.IsZero() {
		start = stamp(tkt.AuthTime)
	}
	if tsAfter(start, now+skew) {
		return wire.ErrCodeTktNYV, what + " NOT YET VALID"
	}
	if tsAfter(now, stamp(tkt.EndTime)+skew) {
		return wire.ErrCodeTktExpired, what + " EXPIRED"
	}
	return 0, ""
}
