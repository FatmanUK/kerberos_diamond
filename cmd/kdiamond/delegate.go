package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/store"
)

// delegate records a traditional constrained-delegation grant: which
// services an impersonator may obtain tickets to on a user's behalf.
//
// **kadmin has no such verb**, and that absence is the whole reason
// this exists. Upstream's flat-file database cannot express the
// relation at all -- its KDB module has no check_allowed_to_delegate
// method, so every traditional S4U2Proxy request against a stock
// realm is refused -- and its real answer is an LDAP attribute,
// `krbAllowedToDelegateTo', administered with whatever tool
// administers the directory. There is no kadmin vocabulary to follow
// here, so these four verbs are this project's own and say so.
func delegate(args []string) error {
	return grantVerb(args, "delegate",
		"usage: kdiamond delegate IMPERSONATOR TARGET",
		func(s *store.Store, a, b string) error {
			return s.GrantDelegation(
				context.Background(), a, b)
		},
		"%q may now obtain tickets to %q for anyone.\n")
}

// undelegate removes one.
func undelegate(args []string) error {
	return grantVerb(args, "undelegate",
		"usage: kdiamond undelegate IMPERSONATOR TARGET",
		func(s *store.Store, a, b string) error {
			return s.RevokeDelegation(
				context.Background(), a, b)
		},
		"%q may no longer obtain tickets to %q.\n")
}

// rbcd records a resource-based grant, which runs the other way
// round: the *resource* names the impersonators it accepts.
//
// The inversion is administrative rather than technical. A
// traditional grant is made by whoever administers the impersonator,
// so a front-end service's operator decides which back ends it may
// reach; a resource-based grant is made by whoever administers the
// resource, so the back end decides who may reach it. The second is
// the one a resource's owner can audit, which is why Microsoft added
// it and why both exist.
func rbcd(args []string) error {
	return grantVerb(args, "rbcd",
		"usage: kdiamond rbcd RESOURCE IMPERSONATOR",
		func(s *store.Store, a, b string) error {
			return s.GrantRBCD(context.Background(), a, b)
		},
		"%q now accepts delegation from %q.\n")
}

// unrbcd removes one.
func unrbcd(args []string) error {
	return grantVerb(args, "unrbcd",
		"usage: kdiamond unrbcd RESOURCE IMPERSONATOR",
		func(s *store.Store, a, b string) error {
			return s.RevokeRBCD(
				context.Background(), a, b)
		},
		"%q no longer accepts delegation from %q.\n")
}

// grantVerb is the shape all four share: two principal names,
// qualified with the realm, and one store call.
//
// Neither name is looked up first, deliberately. A grant is a
// statement about names and it is useful to make one before the
// principal exists -- a realm being built from a script has no
// ordering between creating a service and authorising it -- which is
// also how a dangling alias is allowed to exist (see alias.go).
func grantVerb(
	args []string,
	name, usage string,
	apply func(*store.Store, string, string) error,
	format string,
) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New(usage)
	}
	s, c, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	a, err := qualify(fs.Arg(0), c.Realm)
	if err != nil {
		return err
	}
	b, err := qualify(fs.Arg(1), c.Realm)
	if err != nil {
		return err
	}
	if err := apply(s, a, b); err != nil {
		return err
	}
	fmt.Printf(format, a, b)
	return nil
}

// getdelegations prints both relations for a principal, because a
// principal can be on either side of one and an operator asking "what
// can this service do" means both.
func getdelegations(args []string) error {
	fs := flag.NewFlagSet("getdelegations",
		flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(
			"usage: kdiamond getdelegations PRINCIPAL")
	}
	s, c, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	name, err := qualify(fs.Arg(0), c.Realm)
	if err != nil {
		return err
	}
	return printDelegations(s, name)
}

// printDelegations lists what the principal may reach and who may
// reach it.
func printDelegations(s *store.Store, name string) error {
	ctx := context.Background()
	out, err := s.Delegations(ctx, name)
	if err != nil {
		return err
	}
	fmt.Printf("Principal: %s\n", name)
	fmt.Printf("May obtain tickets to: %s\n", list(out))
	in, err := s.RBCDGrants(ctx, name)
	if err != nil {
		return err
	}
	fmt.Printf("Accepts delegation from: %s\n", list(in))
	return nil
}

// list renders a possibly-empty list the way getprinc renders an
// absent field.
func list(ss []string) string {
	if len(ss) == 0 {
		return "[none]"
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += " " + s
	}
	return out
}
