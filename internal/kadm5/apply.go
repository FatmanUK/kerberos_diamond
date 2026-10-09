package kadm5

import (
	"context"
	"errors"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// apply writes a request's fields onto a principal, imposes the ACL's
// restrictions and stamps the modification.
//
// The order matters and is upstream's: the request is read first, the
// restrictions are imposed on top (impose_restrictions,
// kadmin/server/auth.c:203-271), and only then is anything checked
// against a policy. An administrator capped at an hour who asks for a
// day gets an hour rather than an error, which is the difference
// between a restriction and a rule.
func (s *Server) apply(
	ctx context.Context,
	c *Caller,
	p *store.Principal,
	in *PrincWrite,
	r *acl.Restrictions,
) error {
	if in.Policy != nil && in.ClearPolicy != nil &&
		*in.ClearPolicy {
		return badMask("policy with clearpolicy", "a write")
	}
	if err := applyFields(p, in); err != nil {
		return err
	}
	life := time.Duration(p.MaxLife) * time.Second
	renew := time.Duration(p.MaxRenewableLife) * time.Second
	r.Impose(&p.Attributes, &life, &renew)
	p.MaxLife = int32(life / time.Second)
	p.MaxRenewableLife = int32(renew / time.Second)
	applyPolicyRestriction(p, r)
	stampModified(c, p)
	return s.applyKeys(ctx, p, in)
}

// applyFields copies the request's set fields onto the principal.
func applyFields(p *store.Principal, in *PrincWrite) error {
	if in.Policy != nil {
		p.Policy = *in.Policy
	}
	if in.ClearPolicy != nil && *in.ClearPolicy {
		p.Policy = ""
	}
	if err := applyLifetimes(p, in); err != nil {
		return err
	}
	if in.Attributes != nil {
		a, err := store.ApplyAttr(p.Attributes,
			*in.Attributes)
		if err != nil {
			return errors.Join(ErrBadRequest, err)
		}
		p.Attributes = a
	}
	return nil
}

// applyLifetimes reads the two durations and the two deadlines.
func applyLifetimes(
	p *store.Principal,
	in *PrincWrite,
) error {
	if in.MaxLife != nil {
		d, err := durationField(in.MaxLife)
		if err != nil {
			return errors.Join(ErrBadRequest, err)
		}
		p.MaxLife = int32(d / time.Second)
	}
	if in.MaxRenewableLife != nil {
		d, err := durationField(in.MaxRenewableLife)
		if err != nil {
			return errors.Join(ErrBadRequest, err)
		}
		p.MaxRenewableLife = int32(d / time.Second)
	}
	for _, f := range []struct {
		in  *string
		out *time.Time
	}{
		{in.Expiration, &p.Expiration},
		{in.PWExpiration, &p.PWExpiration},
	} {
		if f.in == nil {
			continue
		}
		t, err := timeField(f.in)
		if err != nil {
			return err
		}
		*f.out = t
	}
	return nil
}

// applyPolicyRestriction forces the policy an ACL entry names.
//
// It runs after the request's own policy field, because a restriction
// overrides a request rather than being overridden by it
// (auth.c:228-240).
func applyPolicyRestriction(
	p *store.Principal,
	r *acl.Restrictions,
) {
	switch {
	case r == nil:
	case r.ClearPolicy:
		p.Policy = ""
	case r.Policy != "":
		p.Policy = r.Policy
	}
}

// stampModified records who wrote this and when.
//
// Upstream does it on **every** write, inside kdb_put_entry
// (server_kdb.c:361-377 calls krb5_dbe_update_mod_princ_data with the
// current time and handle->current_caller), so getprinc always has an
// audit trail. This project wrote neither field until now, which left
// a blank where kadmin shows a name.
func stampModified(c *Caller, p *store.Principal) {
	p.ModBy = c.Name()
	p.ModTime = time.Now().UTC().Truncate(time.Second)
}

// applyKeys sets a password or a random key, in the order upstream
// checks things.
//
// Two differences from a plain password change, both upstream's:
// **randkey runs neither the quality check nor the history check**
// (randkey_3, svr_principal.c:1388-1505 calls neither passwd_check
// nor check_pw_reuse), which is why `cpw -randkey' escapes a minimum
// password life; and a password set administratively is not subject
// to the minimum life either, because check_min_life is only reached
// from the self-service path (misc.c:88-89).
func (s *Server) applyKeys(
	ctx context.Context,
	p *store.Principal,
	in *PrincWrite,
) error {
	random := in.Randkey != nil && *in.Randkey
	if random && in.Password != nil {
		return badMask("password with randkey", "a write")
	}
	keepOld := in.KeepOld != nil && *in.KeepOld
	switch {
	case random:
		return s.randomKeys(ctx, p, keepOld)
	case in.Password != nil:
		return s.passwordKeys(ctx, p, *in.Password, keepOld)
	}
	return nil
}

// randomKeys re-keys a principal at the next version.
func (s *Server) randomKeys(
	ctx context.Context,
	p *store.Principal,
	keepOld bool,
) error {
	_, err := s.Store.SetRandomPassword(ctx, p, keepOld)
	return err
}

// passwordKeys sets a password through the store's own ordering,
// which the local subcommands share: quality, reuse, history, keys,
// expiry (store.ChangePassword).
func (s *Server) passwordKeys(
	ctx context.Context,
	p *store.Principal,
	password string,
	keepOld bool,
) error {
	_, err := s.Store.ChangePassword(ctx, p, password, keepOld)
	return err
}
