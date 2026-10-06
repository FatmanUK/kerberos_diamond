// Package transit is the transited-realm field: the record a ticket
// carries of which realms it was passed through on its way here.
//
// The field matters because a cross-realm trust is not transitive by
// accident. If realm A trusts B and B trusts C, a ticket for a client
// of A can reach a service of C -- but only because B vouched for it,
// and a service in C has to be able to tell that from a ticket A
// issued directly. The transited field is how: every KDC that
// forwards a request adds the realm it is forwarding *from*, and the
// KDC that finally issues the service ticket checks the whole list
// against the realms it is willing to see in a path.
//
// Two things live here, and they are not inverses of each other. Add
// is kdc/kdc_transit.c's add_to_transited, which appends a realm to
// the compressed encoding. Check is lib/krb5/krb/chk_trans.c's
// krb5_check_transited_list, which expands the encoding back into the
// realms it names and refuses any the caller does not allow. The
// expansion is the larger of the two because the encoding is lossy
// about *intermediates*: ",EDU," does not name MIT.EDU, it names
// "everything between the client's realm and the server's", and
// working out what that is takes the two end realms as well as the
// field.
package transit

import "errors"

// ErrIllegalPath is KRB5KRB_AP_ERR_ILL_CR_TKT, which is what both
// upstream functions answer for every kind of malformed or
// unacceptable path. It is deliberately one error: a KDC does not
// tell a client *which* realm in a path it objected to.
var ErrIllegalPath = errors.New(
	"transit: illegal cross-realm ticket")

// ErrNoPath is KRB5_NO_TKT_IN_RLM, which Tree answers when there is
// no path to walk at all.
var ErrNoPath = errors.New("transit: no path between the realms")

// maxLen is MAXLEN in chk_trans.c:43 and MAX_REALM_LN in
// kdc_transit.c:36. The two differ -- 512 and 500 -- and the smaller
// is used for both, because a path this side would build and then
// refuse to read back is worse than one it refuses to build.
const maxLen = 500

// Separator is KRB5_REALM_BRANCH_CHAR, the character that separates
// the components of a domain-style realm name
// (include/krb5/krb5.hin). X.500-style realms use '/' instead and are
// recognised by a leading slash rather than by configuration.
const Separator = '.'
