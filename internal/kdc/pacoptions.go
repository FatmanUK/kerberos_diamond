package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// pacOptionsEcho is the PA-PAC-OPTIONS element a reply's *encrypted*
// padata carries, or nil (kdc_add_pa_pac_options,
// kdc/kdc_util.c:1825-1853).
//
// Three things about it, and all three are decisions upstream made
// rather than consequences of the format.
//
// **The field is masked down to the one bit MIT implements** before
// being echoed (:1839). So what travels back is not what the client
// asked for but what the KDC *honoured*, which is the only useful
// thing to tell a client: a client reading its own request back would
// learn nothing. The other [MS-KILE] bits -- claims, branch-aware,
// forward-to-full-DC -- are not merely unimplemented, they are not
// named anywhere in MIT at all.
//
// **When nothing survives the mask the element is suppressed
// entirely** (:1840-1843), rather than an empty one being sent. A
// client that asked only for something unsupported therefore gets
// silence, which is the honest answer and is also what distinguishes
// "not honoured" from "honoured, and the bit is zero".
//
// **A malformed element is not an error.** Upstream's decode failure
// propagates out of kdc_get_pa_pac_options and so refuses the
// request; this returns nil instead and issues the ticket, because
// the element carries no instruction a KDC has to obey -- it is a
// capability announcement, and the right response to one that cannot
// be read is not to announce anything back. Recorded as a divergence
// rather than copied, because refusing an AS request over an
// unreadable *advertisement* is a failure mode with no upside.
func pacOptionsEcho(pa []wire.PAData) *wire.PAData {
	d := findPAData(pa, wire.PAPACOptions)
	if d == nil {
		return nil
	}
	opts, err := wire.UnmarshalPAPACOptions(d.Value)
	if err != nil {
		return nil
	}
	opts &= wire.PACOptRBCD
	if opts == 0 {
		return nil
	}
	der, err := wire.MarshalPAPACOptions(opts)
	if err != nil {
		return nil
	}
	return &wire.PAData{
		Type: wire.PAPACOptions, Value: der,
	}
}

// supportsRBCD reports whether a request announced resource-based
// constrained delegation (kdc_get_pa_pac_rbcd, kdc_util.c:1855-1872).
//
// Nothing reads it yet: its one caller upstream is
// check_s4u2proxy_policy (tgs_policy.c:534), which is E6. It is here
// because the codec and the mask are this step's and splitting the
// two readers of one padata element across two commits would mean
// writing the decode twice.
func supportsRBCD(pa []wire.PAData) bool {
	d := findPAData(pa, wire.PAPACOptions)
	if d == nil {
		return false
	}
	opts, err := wire.UnmarshalPAPACOptions(d.Value)
	if err != nil {
		return false
	}
	return opts&wire.PACOptRBCD != 0
}
