package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/store"
)

// alias points one principal name at another, which is kadmin's
// `alias'.
//
// Two refusals, both upstream's and both worth knowing before use:
// the target must be in the same realm (an alias is resolved by a
// second lookup in the same database), and the alias name must not
// already resolve to anything.
//
// What an alias is *not* is a copy. Every operation that acts on the
// principal behind the name -- modprinc, cpw, purgekeys, setstr --
// acts on the target, and only delprinc acts on the alias itself.
func alias(args []string) error {
	fs := flag.NewFlagSet("alias", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New(
			"usage: kdiamond alias ALIAS TARGET")
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
	t, err := qualify(fs.Arg(1), c.Realm)
	if err != nil {
		return err
	}
	if err := s.CreateAlias(
		context.Background(), a, t); err != nil {
		return err
	}
	fmt.Printf("Alias %q now names %q.\n", a, t)
	return nil
}

// unalias removes an alias and leaves its target alone.
//
// kadmin has no such command -- there an alias is a database entry
// and `delprinc' removes it -- and `kdiamond delprinc' on an alias
// does the same thing here. This exists because the asymmetry is
// surprising enough to be worth a name: `delprinc' on an alias sounds
// like it would delete the principal.
func unalias(args []string) error {
	fs := flag.NewFlagSet("unalias", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, c, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	name, err := principalArg(fs, c.Realm)
	if err != nil {
		return err
	}
	ctx := context.Background()
	is, err := s.IsAlias(ctx, name)
	if err != nil {
		return err
	}
	if !is {
		return fmt.Errorf("%w: %s is not an alias",
			store.ErrNotFound, name)
	}
	if err := s.DeleteAlias(ctx, name); err != nil {
		return err
	}
	fmt.Printf("Alias %q removed.\n", name)
	return nil
}
