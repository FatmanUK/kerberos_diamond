package main

import (
	"flag"
	"strings"

	"github.com/FatmanUK/diamond_krb/internal/store"
)

// attrList collects repeated +name / -name attribute specifiers.
//
// It is a flag.Value rather than a single string because the order
// matters: "+allow_tix -allow_tix" and the reverse are different
// requests, and a map or a set would lose that.
type attrList []string

func (a *attrList) String() string {
	return strings.Join(*a, " ")
}

func (a *attrList) Set(v string) error {
	*a = append(*a, v)
	return nil
}

// attrFlag registers -attr, which may be repeated.
//
// kadmin takes its attributes as bare arguments, which cannot work
// here: Go's flag package stops parsing at the first non-flag
// argument, so a bare "+requires_preauth" before the principal name
// would swallow everything after it. Naming the flag is the honest
// fix; the specifier vocabulary is kadmin's unchanged.
func attrFlag(fs *flag.FlagSet) *attrList {
	a := &attrList{}
	fs.Var(a, "attr",
		"attribute specifier such as +requires_preauth or "+
			"-allow_tix; may be repeated")
	return a
}

// applyAll applies every specifier in order.
func applyAll(p *store.Principal, specs attrList) error {
	for _, spec := range specs {
		next, err := store.ApplyAttr(p.Attributes, spec)
		if err != nil {
			return err
		}
		p.Attributes = next
	}
	return nil
}
