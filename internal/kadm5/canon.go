package kadm5

import (
	"context"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// canonical looks a principal up and authorises the operation against
// **the name it resolves to**, not the name that was asked for.
//
// Which operations do this is not a judgement call: upstream's server
// stubs pass a record out of stub_setup when they want it
// canonicalised, and stub_setup looks the principal up
// (server_stubs.c:295-300) so that rec.principal is the canonical
// name. The stubs that take that record use it for the ACL check
// *and* for the operation -- the comment at :646-648 says why, "to
// ensure consistency with the ACL check" -- and the stubs that do
// not, addprinc and delprinc, check the requested name instead.
//
// t_kadmin_acl.py asserts the split from the outside, one operation
// at a time: cpw, chrand, getprinc, getstrs, modprinc, purgekeys,
// setstr and extract canonicalise (:119-121, :199-201, :225-227,
// :255-257, :271-273, :316-318, :369-371), and addprinc and delprinc
// do not (:155-160, :172-176).
//
// The lookup coming **first** also fixes the order of the two
// failures: a principal that is not there is reported as missing
// before the authorisation is considered, which is what upstream does
// because stub_setup's error short-circuits the stub. So a client
// asking about a name it may not touch learns whether that name
// exists -- upstream's trade, and copying it is the point.
func (s *Server) canonical(
	ctx context.Context,
	c *Caller,
	op acl.Op,
	requested string,
) (*store.Principal, *acl.Restrictions, error) {
	p, err := s.Store.Lookup(ctx, c.qualify(requested))
	if err != nil {
		return nil, nil, err
	}
	r, err := c.permit(op, p.Name)
	if err != nil {
		return nil, nil, err
	}
	if err := c.selfOnly(p.Name); err != nil {
		return nil, nil, err
	}
	return p, r, nil
}
