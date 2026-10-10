package kadm5

import (
	"context"
	"encoding/json"

	"github.com/FatmanUK/diamond_krb/internal/acl"
)

// aliasReq is the alias verb's arguments.
type aliasReq struct {
	Alias  string `json:"alias"`
	Target string `json:"target"`
}

// addAlias creates an alias, which is kadmin's `alias'.
//
// **Its authorisation is unlike every other operation's**, and
// upstream's own module is the shortest statement of it
// (acl_addalias, auth_acl.c:723-734): add on the *alias name*, modify
// on the *target*, and the add entry must carry **no restrictions at
// all**.
//
// The restriction rule is the surprising one and the reasoning is
// sound: a restriction says what attributes and lifetimes a created
// principal must have, and an alias creates no principal to apply
// them to. So rather than impose nothing and pretend, upstream
// refuses -- which is the same choice renprinc makes
// (auth_acl.c:632-641), and the only two places in the ACL where a
// restriction is a refusal instead of a cap.
func (s *Server) addAlias(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[aliasReq](body)
	if err != nil {
		return nil, err
	}
	alias := c.qualify(in.Alias)
	target := c.qualify(in.Target)
	if err := c.permitAlias(alias, target); err != nil {
		return nil, err
	}
	if err := s.Store.CreateAlias(
		ctx, alias, target); err != nil {
		return nil, err
	}
	return map[string]any{
		"alias": alias, "target": target,
	}, nil
}

// permitAlias is acl_addalias's three conditions.
func (c *Caller) permitAlias(alias, target string) error {
	r, ok := c.ACL.Check(acl.AddAlias, c.Name(), alias)
	if !ok || r != nil {
		return &Refusal{Op: acl.AddAlias, Target: alias}
	}
	if _, ok := c.ACL.Check(
		acl.ModPrinc, c.Name(), target); !ok {
		return &Refusal{Op: acl.AddAlias, Target: target}
	}
	return nil
}
