package kadm5

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/deltat"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// PrincWrite is the argument shape of addprinc and modprinc.
//
// **Every optional field is a pointer, and that is the kadm5 modify
// mask** (admin.h:88-113). A key present in the JSON object is a
// field being set; a key absent is one being left alone. Nothing else
// is needed to express the mask, which is why there is no separate
// list of field names in a request: the object *is* the mask.
//
// It also fixes what the local subcommands get wrong, which the plan
// recorded: there, zero means unchanged, so an operator cannot set a
// maximum life *to* zero -- and zero is the value that means
// unlimited.
type PrincWrite struct {
	Principal string `json:"principal"`

	// Password and Randkey are exclusive. Randkey is kadmin's
	// -randkey, which escapes the history and quality checks
	// because upstream's randkey_3 runs neither
	// (svr_principal.c:1388-1505) -- behaviour reproduced rather
	// than improved.
	Password *string `json:"password"`
	Randkey  *bool   `json:"randkey"`
	KeepOld  *bool   `json:"keepold"`

	// Policy and ClearPolicy are exclusive, which upstream
	// refuses explicitly on both create and modify (:319-321,
	// :577-579).
	Policy      *string `json:"policy"`
	ClearPolicy *bool   `json:"clearpolicy"`

	// The lifetimes, in kadmin's own duration format rather than
	// Go's: `1d' is a day and `24h' is the same day, and a bare
	// number is seconds.
	MaxLife          *string `json:"max_life"`
	MaxRenewableLife *string `json:"max_renewable_life"`

	// The two deadlines, RFC 3339 or the word "never".
	Expiration   *string `json:"expiration"`
	PWExpiration *string `json:"pw_expiration"`

	// Attributes is kadmin's -attr specifier, so that what
	// getprinc reports is what this accepts.
	Attributes *string `json:"attributes"`

	// FailAuthCount **may only be set to zero**, which is the
	// unlock path and the only use upstream allows (:668-681).
	// Any other value is an error rather than a counter an
	// administrator can forge.
	FailAuthCount *int32 `json:"fail_auth_count"`
}

// addPrinc creates a principal.
func (s *Server) addPrinc(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[PrincWrite](body)
	if err != nil {
		return nil, err
	}
	name := c.qualify(in.Principal)
	r, err := c.permit(acl.AddPrinc, name)
	if err != nil {
		return nil, err
	}
	if in.FailAuthCount != nil {
		return nil, badMask("fail_auth_count", "addprinc")
	}
	components, realm, err := store.ParseName(name)
	if err != nil {
		return nil, ErrBadRequest
	}
	p := store.NewPrincipal(realm, components)
	if err := s.apply(ctx, c, p, &in, r); err != nil {
		return nil, err
	}
	if err := s.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return principalInfo(p), nil
}

// modPrinc changes one.
func (s *Server) modPrinc(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[PrincWrite](body)
	if err != nil {
		return nil, err
	}
	name := c.qualify(in.Principal)
	r, err := c.permit(acl.ModPrinc, name)
	if err != nil {
		return nil, err
	}
	if in.FailAuthCount != nil && *in.FailAuthCount != 0 {
		return nil, badMask("a nonzero fail_auth_count",
			"modprinc")
	}
	p, err := s.Store.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := s.apply(ctx, c, p, &in, r); err != nil {
		return nil, err
	}
	if err := s.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return s.afterModify(ctx, c, p, &in)
}

// afterModify handles the one field that is not a column: clearing
// the failure count is the administrative unlock, and it has to run
// after the save because that is where the counter lives.
func (s *Server) afterModify(
	ctx context.Context,
	c *Caller,
	p *store.Principal,
	in *PrincWrite,
) (any, error) {
	if in.FailAuthCount == nil {
		return principalInfo(p), nil
	}
	if err := s.Store.Unlock(ctx, p); err != nil {
		return nil, err
	}
	return principalInfo(p), nil
}

// badMask is upstream's KADM5_BAD_MASK, which it answers for a
// request naming a field that operation may not set (:311-321 for
// create, :567-579 for modify).
func badMask(field, op string) error {
	return fmt.Errorf("%w: %s cannot be set by %s",
		ErrBadRequest, field, op)
}

// durationField reads one of kadmin's durations.
func durationField(v *string) (time.Duration, error) {
	if v == nil {
		return 0, nil
	}
	return deltat.Parse(*v)
}

// timeField reads one of the two deadlines. "never" is the zero time,
// which is what kadmin prints for it and so what it should accept.
func timeField(v *string) (time.Time, error) {
	if v == nil || *v == "" || *v == "never" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, *v)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: %q is not an RFC 3339 time or \"never\"",
			ErrBadRequest, *v)
	}
	return t.UTC(), nil
}
