package kadm5

import (
	"context"
	"encoding/json"

	"github.com/FatmanUK/diamond_krb/internal/acl"
	"github.com/FatmanUK/diamond_krb/internal/store"
)

// PolicyInfo is what getpol reports, which is kadm5_policy_ent_rec
// (admin.h:215-236).
type PolicyInfo struct {
	Policy string `json:"policy"`

	PWMinLife    int32 `json:"pw_min_life"`
	PWMaxLife    int32 `json:"pw_max_life"`
	PWMinLength  int32 `json:"pw_min_length"`
	PWMinClasses int32 `json:"pw_min_classes"`
	PWHistoryNum int32 `json:"pw_history_num"`

	PWMaxFail           int32 `json:"pw_max_fail"`
	PWFailCountInterval int32 `json:"pw_failcnt_interval"`
	PWLockoutDuration   int32 `json:"pw_lockout_duration"`
}

// getPol reports one policy.
//
// The ACL gate is a-typical and upstream's: the self module permits a
// principal to read **its own policy** with no ACL line, comparing
// policy names rather than principal names (SelfPolicy,
// auth_self.c:48-55). So this needs the client's own policy before it
// can decide, which is one extra lookup and the reason getpol does
// not look like the others.
func (s *Server) getPol(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[policyNamed](body)
	if err != nil {
		return nil, err
	}
	if err := s.permitPolicyRead(ctx, c, in.Policy); err != nil {
		return nil, err
	}
	pol, err := s.Store.LookupPolicy(ctx, in.Policy)
	if err != nil {
		return nil, err
	}
	return policyInfo(pol), nil
}

// permitPolicyRead is getpol's gate.
//
// The policy name reaches the self module and **not** the ACL: a
// principal may read its own policy by comparing policy names
// (SelfPolicy, auth_self.c:48-55), and the ACL check that follows
// passes no target at all, which is what acl_getpol does
// (auth_acl.c:701-707). See policyWrite for why that matters more
// than it looks.
func (s *Server) permitPolicyRead(
	ctx context.Context,
	c *Caller,
	policy string,
) error {
	mine, err := s.Store.Lookup(ctx, c.Name())
	if err == nil &&
		acl.SelfPolicy(acl.GetPol, policy, mine.Policy) {
		return nil
	}
	if _, ok := c.ACL.Check(acl.GetPol, c.Name(), ""); !ok {
		return &Refusal{Op: acl.GetPol, Target: policy}
	}
	return nil
}

// policyInfo renders a policy.
func policyInfo(p *store.Policy) *PolicyInfo {
	return &PolicyInfo{
		Policy:              p.Name,
		PWMinLife:           p.PWMinLife,
		PWMaxLife:           p.PWMaxLife,
		PWMinLength:         p.PWMinLength,
		PWMinClasses:        p.PWMinClasses,
		PWHistoryNum:        p.PWHistoryNum,
		PWMaxFail:           p.PWMaxFail,
		PWFailCountInterval: p.PWFailCountInterval,
		PWLockoutDuration:   p.PWLockoutDuration,
	}
}

// listPols lists every policy name.
func (s *Server) listPols(
	ctx context.Context,
	c *Caller,
	_ json.RawMessage,
) (any, error) {
	if err := c.permitGlobal(acl.ListPols); err != nil {
		return nil, err
	}
	names, err := s.Store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"policies": names}, nil
}

// getPrivs reports what the caller may do, and **it returns every bit
// regardless of the ACL**, which is upstream's behaviour and not a
// stub left unfinished here.
//
// kadm5_get_privs says so itself (server_misc.c:146-158): the
// interface asks "what may this client do" and the ACL can only
// answer "may this client do *this* to *that*", so there is no honest
// answer to give. Returning everything loses nothing, because each
// operation is checked when it is attempted; returning a guess would
// be worse, because a client would believe it.
func (s *Server) getPrivs(
	_ context.Context,
	_ *Caller,
	_ json.RawMessage,
) (any, error) {
	all := []string{"get", "add", "modify", "delete"}
	return map[string]any{
		"privs":    all,
		"complete": false,
	}, nil
}
