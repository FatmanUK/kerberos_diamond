package kadm5

import (
	"context"
	"encoding/json"

	"github.com/FatmanUK/diamond_krb/internal/acl"
	"github.com/FatmanUK/diamond_krb/internal/store"
)

// delPrinc removes a principal.
func (s *Server) delPrinc(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[named](body)
	if err != nil {
		return nil, err
	}
	// delprinc does **not** canonicalise, and here that is more
	// than an ACL detail: the name is also what gets deleted, and
	// an alias deletes the alias rather than the principal behind
	// it (t_alias.py:12-16, t_kadmin_acl.py:172-176).
	name := c.qualify(in.Principal)
	if _, err := c.permit(acl.DelPrinc, name); err != nil {
		return nil, err
	}
	if err := s.Store.Delete(ctx, name); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": name}, nil
}

// renameReq is renprinc's arguments.
type renameReq struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// renPrinc renames one.
//
// The ACL check is its own, because a rename is two targets and
// upstream needs the privilege on **both** -- and it is one of the
// two operations that **refuses** rather than imposing a restriction,
// because there is no sensible way to impose a lifetime cap on a name
// change (auth_acl.c:632-641).
func (s *Server) renPrinc(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[renameReq](body)
	if err != nil {
		return nil, err
	}
	from, to := c.qualify(in.From), c.qualify(in.To)
	if !c.ACL.PermitsRename(c.Name(), from, to) {
		return nil, &Refusal{Op: acl.RenPrinc, Target: from}
	}
	if err := s.Store.Rename(ctx, from, to); err != nil {
		return nil, err
	}
	return map[string]any{"from": from, "to": to}, nil
}

// purgeKeys drops every key version below the current one.
func (s *Server) purgeKeys(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[named](body)
	if err != nil {
		return nil, err
	}
	p, _, err := s.canonical(ctx, c, acl.PurgeKeys,
		in.Principal)
	if err != nil {
		return nil, err
	}
	removed := p.PurgeOldKeys()
	if removed > 0 {
		stampModified(c, p)
		if err := s.Store.Save(ctx, p); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"principal": p.Name,
		"removed":   removed,
		"kvno":      p.HighestKVNO(),
	}, nil
}

// strReq is setstr's and delstr's arguments. An absent value is a
// deletion, which is how kadmin's own setstr works -- `setstr princ
// key' with no value removes the attribute.
type strReq struct {
	Principal string  `json:"principal"`
	Key       string  `json:"key"`
	Value     *string `json:"value"`
}

// setStr sets or removes a string attribute.
func (s *Server) setStr(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[strReq](body)
	if err != nil {
		return nil, err
	}
	if in.Key == "" {
		return nil, ErrBadRequest
	}
	p, _, err := s.canonical(ctx, c, acl.SetStr,
		in.Principal)
	if err != nil {
		return nil, err
	}
	setStringAttr(p, in.Key, in.Value)
	stampModified(c, p)
	if err := s.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return map[string]any{"principal": p.Name,
		"key": in.Key}, nil
}

// setStringAttr sets, replaces or removes one string attribute.
//
// A nil value removes it, which is kadmin's own convention: `setstr
// principal key' with no value deletes the attribute rather than
// setting it to the empty string (kadmin's setstr takes an optional
// third argument). The distinction matters because the KDC reads some
// of these for their presence.
func setStringAttr(
	p *store.Principal,
	key string,
	value *string,
) {
	out := make([]store.StringAttr, 0, len(p.StringAttrs)+1)
	for _, a := range p.StringAttrs {
		if a.Key != key {
			out = append(out, a)
		}
	}
	if value != nil {
		out = append(out, store.StringAttr{
			PrincipalName: p.Name,
			Key:           key,
			Value:         *value,
		})
	}
	p.StringAttrs = out
}

// cpw changes a password, which is modprinc's key half on its own.
//
// It is a separate verb because the privilege is different: changing
// a password is `c' and changing anything else is `m', and upstream's
// self module permits the first on oneself with no ACL line at all
// (auth_self.c:40-46) where it permits none of the second.
func (s *Server) cpw(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[PrincWrite](body)
	if err != nil {
		return nil, err
	}
	op := acl.CPW
	if in.Randkey != nil && *in.Randkey {
		op = acl.ChRand
	}
	p, _, err := s.canonical(ctx, c, op, in.Principal)
	if err != nil {
		return nil, err
	}
	return s.doCPW(ctx, c, p, &in)
}

// doCPW is the half of cpw that touches the database.
func (s *Server) doCPW(
	ctx context.Context,
	c *Caller,
	p *store.Principal,
	in *PrincWrite,
) (any, error) {
	if err := s.applyKeys(ctx, p, in); err != nil {
		return nil, err
	}
	stampModified(c, p)
	if err := s.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return map[string]any{
		"principal": p.Name,
		"kvno":      p.HighestKVNO(),
	}, nil
}
