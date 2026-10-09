package kadm5

import (
	"context"
	"encoding/json"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// PrincInfo is what getprinc reports, which is kadm5_principal_ent
// (admin.h:48-80) with the fields this store keeps.
//
// Times are RFC 3339 and a zero time is omitted entirely rather than
// sent as the epoch, because kadmin prints "[never]" for it and a
// client that received 1970 would have to know to say the same.
type PrincInfo struct {
	Principal        string `json:"principal"`
	Policy           string `json:"policy,omitempty"`
	KVNO             int32  `json:"kvno"`
	MaxLife          int32  `json:"max_life"`
	MaxRenewableLife int32  `json:"max_renewable_life"`
	FailAuthCount    int32  `json:"fail_auth_count"`

	Expiration   *time.Time `json:"expiration,omitempty"`
	PWExpiration *time.Time `json:"pw_expiration,omitempty"`
	LastPWChange *time.Time `json:"last_pwd_change,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastFailed   *time.Time `json:"last_failed,omitempty"`
	ModTime      *time.Time `json:"mod_date,omitempty"`

	ModBy string `json:"mod_name,omitempty"`

	// Attributes is the flag set in kadmin's own spelling, so
	// that what getprinc reports is what modprinc -attr accepts.
	Attributes []string `json:"attributes"`

	// Keys lists the enctype and salt of each key *without the
	// key*, which is what kadmin's getprinc prints. Handing out
	// key material is a separate operation behind a separate
	// privilege.
	Keys []KeyInfo `json:"keys"`

	// Locked reports whether an AS exchange would be refused
	// right now, resolved against the policy. kadmin cannot
	// report this -- it would have to know the lockout rules,
	// which live in the database back end -- and here they are in
	// one place, so it can.
	Locked bool `json:"locked"`
}

// KeyInfo is one key version and enctype.
type KeyInfo struct {
	KVNO     int32 `json:"kvno"`
	EType    int32 `json:"enctype"`
	SaltType int32 `json:"salttype"`
}

// getPrinc reports one principal.
func (s *Server) getPrinc(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[named](body)
	if err != nil {
		return nil, err
	}
	name := c.qualify(in.Principal)
	if _, err := c.permit(acl.GetPrinc, name); err != nil {
		return nil, err
	}
	p, err := s.Store.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	out := principalInfo(p)
	lock, err := s.Store.LockoutFor(ctx, p, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out.Locked = lock.Locked
	return out, nil
}

// principalInfo renders a principal.
func principalInfo(p *store.Principal) *PrincInfo {
	out := &PrincInfo{
		Principal:        p.Name,
		Policy:           p.Policy,
		KVNO:             p.HighestKVNO(),
		MaxLife:          p.MaxLife,
		MaxRenewableLife: p.MaxRenewableLife,
		FailAuthCount:    p.FailAuthCount,
		ModBy:            p.ModBy,
		Attributes:       store.AttrNames(p.Attributes),
		Expiration:       whenSet(p.Expiration),
		PWExpiration:     whenSet(p.PWExpiration),
		LastPWChange:     whenSet(p.LastPWChange),
		LastSuccess:      whenSet(p.LastSuccess),
		LastFailed:       whenSet(p.LastFailed),
		ModTime:          whenSet(p.ModTime),
	}
	out.Keys = make([]KeyInfo, 0, len(p.Keys))
	for _, k := range p.Keys {
		out.Keys = append(out.Keys, KeyInfo{
			KVNO:     k.KVNO,
			EType:    k.EType,
			SaltType: k.SaltType,
		})
	}
	return out
}

// whenSet omits a zero time rather than sending the epoch.
func whenSet(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// listPrincs lists every principal name.
func (s *Server) listPrincs(
	ctx context.Context,
	c *Caller,
	_ json.RawMessage,
) (any, error) {
	if err := c.permitGlobal(acl.ListPrincs); err != nil {
		return nil, err
	}
	names, err := s.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"principals": names}, nil
}

// getStrs reports a principal's string attributes.
func (s *Server) getStrs(
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error) {
	in, err := args[named](body)
	if err != nil {
		return nil, err
	}
	name := c.qualify(in.Principal)
	if _, err := c.permit(acl.GetStrs, name); err != nil {
		return nil, err
	}
	p, err := s.Store.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, a := range p.StringAttrs {
		out[a.Key] = a.Value
	}
	return map[string]any{"strings": out}, nil
}
