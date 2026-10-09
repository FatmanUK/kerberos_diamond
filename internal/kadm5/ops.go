package kadm5

import (
	"context"
	"encoding/json"
)

// operation is one administrative verb.
//
// The body arrives as raw JSON rather than decoded, because each
// operation's arguments differ and because the *presence* of a key is
// load-bearing -- which is what the kadm5 modify mask is
// (admin.h:88-113) and which a shared decode would flatten.
type operation func(
	s *Server,
	ctx context.Context,
	c *Caller,
	body json.RawMessage,
) (any, error)

// operations is the route table, keyed by the verb in the path.
//
// The names are kadmin's, including the abbreviations an operator
// types, because the whole point of keeping its vocabulary is that
// what somebody knows transfers. Where kadmin has an alias this has
// the same alias.
var operations = map[string]operation{
	"getprinc":       (*Server).getPrinc,
	"get_principal":  (*Server).getPrinc,
	"listprincs":     (*Server).listPrincs,
	"get_principals": (*Server).listPrincs,
	"getstrs":        (*Server).getStrs,
	"get_strings":    (*Server).getStrs,
	"getpol":         (*Server).getPol,
	"get_policy":     (*Server).getPol,
	"getpols":        (*Server).listPols,
	"get_policies":   (*Server).listPols,
	"getprivs":       (*Server).getPrivs,
	"get_privs":      (*Server).getPrivs,

	"addprinc":         (*Server).addPrinc,
	"ank":              (*Server).addPrinc,
	"add_principal":    (*Server).addPrinc,
	"modprinc":         (*Server).modPrinc,
	"modify_principal": (*Server).modPrinc,
	"delprinc":         (*Server).delPrinc,
	"delete_principal": (*Server).delPrinc,
	"renprinc":         (*Server).renPrinc,
	"rename_principal": (*Server).renPrinc,
	"cpw":              (*Server).cpw,
	"change_password":  (*Server).cpw,
	"purgekeys":        (*Server).purgeKeys,
	"purge_keys":       (*Server).purgeKeys,
	"setstr":           (*Server).setStr,
	"set_string":       (*Server).setStr,
	"delstr":           (*Server).setStr,
	"del_string":       (*Server).setStr,

	"addpol":        (*Server).addPol,
	"add_policy":    (*Server).addPol,
	"modpol":        (*Server).modPol,
	"modify_policy": (*Server).modPol,
	"delpol":        (*Server).delPol,
	"delete_policy": (*Server).delPol,

	"alias":     (*Server).addAlias,
	"add_alias": (*Server).addAlias,
}

// named is the argument shape of every operation that acts on one
// principal.
type named struct {
	Principal string `json:"principal"`
}

// policyNamed is the same for a policy.
type policyNamed struct {
	Policy string `json:"policy"`
}

// args decodes an operation's body.
//
// An empty body decodes as the zero value rather than as an error, so
// that an operation taking no arguments needs none sent.
func args[T any](body json.RawMessage) (T, error) {
	var out T
	if len(body) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, ErrBadRequest
	}
	return out, nil
}
