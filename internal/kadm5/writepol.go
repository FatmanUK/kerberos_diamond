package kadm5

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// PolicyWrite is addpol's and modpol's arguments, with every field a
// pointer for the same reason PrincWrite's are: presence is the mask.
type PolicyWrite struct {
	Policy string `json:"policy"`

	PWMinLife    *string `json:"pw_min_life"`
	PWMaxLife    *string `json:"pw_max_life"`
	PWMinLength  *int32  `json:"pw_min_length"`
	PWMinClasses *int32  `json:"pw_min_classes"`
	PWHistoryNum *int32  `json:"pw_history_num"`

	PWMaxFail       *int32  `json:"pw_max_fail"`
	FailCntInterval *string `json:"pw_failcnt_interval"`
	LockoutDuration *string `json:"pw_lockout_duration"`
}

// addPol creates a policy.
func (s *Server) addPol(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[PolicyWrite](body)
	if err != nil {
		return nil, err
	}
	if err := c.policyWrite(acl.AddPol, in.Policy); err != nil {
		return nil, err
	}
	pol := store.NewPolicy(in.Policy)
	if err := applyPolicy(pol, &in); err != nil {
		return nil, err
	}
	if err := s.Store.SavePolicy(ctx, pol); err != nil {
		return nil, err
	}
	return policyInfo(pol), nil
}

// modPol changes one.
func (s *Server) modPol(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[PolicyWrite](body)
	if err != nil {
		return nil, err
	}
	if err := c.policyWrite(acl.ModPol, in.Policy); err != nil {
		return nil, err
	}
	pol, err := s.Store.LookupPolicy(ctx, in.Policy)
	if err != nil {
		return nil, err
	}
	if err := applyPolicy(pol, &in); err != nil {
		return nil, err
	}
	if err := s.Store.SavePolicy(ctx, pol); err != nil {
		return nil, err
	}
	return policyInfo(pol), nil
}

// delPol removes one, which the store refuses while a principal names
// it.
func (s *Server) delPol(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[policyNamed](body)
	if err != nil {
		return nil, err
	}
	if err := c.policyWrite(acl.DelPol, in.Policy); err != nil {
		return nil, err
	}
	if err := s.Store.DeletePolicy(
		ctx, in.Policy); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": in.Policy}, nil
}

// policyWrite is the ACL gate for the three writing policy
// operations.
//
// The self module does not come into it: a principal may read its own
// policy and may not write it (auth_self.c:48-55 permits GetPol and
// nothing else), which is the difference between knowing the rules
// and setting them.
func (c *Caller) policyWrite(op acl.Op, policy string) error {
	if policy == "" {
		return ErrBadRequest
	}
	if _, ok := c.ACL.Check(op, c.Name(), policy); !ok {
		return &Refusal{Op: op, Target: policy}
	}
	return nil
}

// applyPolicy copies a request's set fields onto a policy and then
// validates the whole thing.
//
// Validating after rather than per field is upstream's order
// (svr_policy.c:57-200 checks a completed record), and it has to be:
// the one rule that spans two fields -- a minimum password life above
// the maximum -- cannot be checked while only one of them has been
// read.
func applyPolicy(
	pol *store.Policy,
	in *PolicyWrite,
) error {
	if err := policyDurations(pol, in); err != nil {
		return err
	}
	for _, f := range []struct {
		in  *int32
		out *int32
	}{
		{in.PWMinLength, &pol.PWMinLength},
		{in.PWMinClasses, &pol.PWMinClasses},
		{in.PWHistoryNum, &pol.PWHistoryNum},
		{in.PWMaxFail, &pol.PWMaxFail},
	} {
		if f.in != nil {
			*f.out = *f.in
		}
	}
	if err := pol.Validate(); err != nil {
		return err
	}
	return nil
}

// policyDurations reads the three fields that are durations.
func policyDurations(
	pol *store.Policy,
	in *PolicyWrite,
) error {
	for _, f := range []struct {
		in  *string
		out *int32
	}{
		{in.PWMinLife, &pol.PWMinLife},
		{in.PWMaxLife, &pol.PWMaxLife},
		{in.FailCntInterval,
			&pol.PWFailCountInterval},
		{in.LockoutDuration, &pol.PWLockoutDuration},
	} {
		if f.in == nil {
			continue
		}
		d, err := durationField(f.in)
		if err != nil {
			return errors.Join(ErrBadRequest, err)
		}
		*f.out = int32(d.Seconds())
	}
	return nil
}
