package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/store"
)

// The policy subcommands, which are kadmin's addpol, modpol, delpol,
// getpol and getpols.
//
// A policy constrains passwords -- how long they must be, how many
// character classes they must use, how long they must be kept and how
// many may not be reused -- and a principal names one by name rather
// than carrying a copy, so that changing a policy changes what it
// constrains.

// policyFlags are the fields addpol and modpol share, named as kadmin
// names them.
type policyFlags struct {
	fs *flag.FlagSet

	minLife    *time.Duration
	maxLife    *time.Duration
	minLength  *int
	minClasses *int
	history    *int
}

// newPolicyFlags registers them. The durations are Go's, which is the
// same wart `-maxlife` has on addprinc: kadmin takes a deltat, so
// `1d` works there and `24h` is needed here.
func newPolicyFlags(name string) *policyFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return &policyFlags{
		fs: fs,
		minLife: fs.Duration("minlife", 0,
			"how long a password must be kept"),
		maxLife: fs.Duration("maxlife", 0,
			"how long a password may be kept"),
		minLength: fs.Int("minlength", 0,
			"the fewest characters a password may have"),
		minClasses: fs.Int("minclasses", 0,
			"the fewest character classes, 1 to 5"),
		history: fs.Int("history", 0,
			"how many old passwords may not be reused"),
	}
}

// apply sets the fields that were given, leaving the rest alone.
//
// "Given" means non-zero, which is the same convention the principal
// commands use and has the same limitation: a field cannot be cleared
// back to its default once set. Upstream expresses it with a mask
// instead, which the admin protocol will want.
func (f *policyFlags) apply(p *store.Policy) {
	if *f.minLife != 0 {
		p.PWMinLife = int32(f.minLife.Seconds())
	}
	if *f.maxLife != 0 {
		p.PWMaxLife = int32(f.maxLife.Seconds())
	}
	if *f.minLength != 0 {
		p.PWMinLength = int32(*f.minLength)
	}
	if *f.minClasses != 0 {
		p.PWMinClasses = int32(*f.minClasses)
	}
	if *f.history != 0 {
		p.PWHistoryNum = int32(*f.history)
	}
}

// addpol creates a policy.
func addpol(args []string) error {
	f := newPolicyFlags("addpol")
	if err := f.fs.Parse(args); err != nil {
		return err
	}
	name, err := policyArg(f.fs)
	if err != nil {
		return err
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.LookupPolicy(ctx, name); err == nil {
		return fmt.Errorf("policy %q already exists", name)
	}
	p := store.NewPolicy(name)
	f.apply(p)
	if err := s.SavePolicy(ctx, p); err != nil {
		return err
	}
	fmt.Printf("Policy %q created.\n", name)
	return nil
}

// modpol changes one.
func modpol(args []string) error {
	f := newPolicyFlags("modpol")
	if err := f.fs.Parse(args); err != nil {
		return err
	}
	name, err := policyArg(f.fs)
	if err != nil {
		return err
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	ctx := context.Background()
	p, err := s.LookupPolicy(ctx, name)
	if err != nil {
		return err
	}
	f.apply(p)
	if err := s.SavePolicy(ctx, p); err != nil {
		return err
	}
	fmt.Printf("Policy %q modified.\n", name)
	return nil
}

// delpol removes one, which is refused while a principal names it.
func delpol(args []string) error {
	fs := flag.NewFlagSet("delpol", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	name, err := policyArg(fs)
	if err != nil {
		return err
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	err = s.DeletePolicy(context.Background(), name)
	if err != nil {
		return err
	}
	fmt.Printf("Policy %q deleted.\n", name)
	return nil
}

// getpol prints one, in kadmin's field order.
func getpol(args []string) error {
	fs := flag.NewFlagSet("getpol", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	name, err := policyArg(fs)
	if err != nil {
		return err
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	p, err := s.LookupPolicy(context.Background(), name)
	if err != nil {
		return err
	}
	printPolicy(p)
	return nil
}

// getpols names every policy.
func getpols(args []string) error {
	fs := flag.NewFlagSet("getpols", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	names, err := s.ListPolicies(context.Background())
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func printPolicy(p *store.Policy) {
	fmt.Printf("Policy: %s\n", p.Name)
	fmt.Printf("Maximum password life: %s\n",
		lifeString(p.PWMaxLife))
	fmt.Printf("Minimum password life: %s\n",
		lifeString(p.PWMinLife))
	fmt.Printf("Minimum password length: %d\n", p.PWMinLength)
	fmt.Printf("Minimum number of password character classes: "+
		"%d\n", p.PWMinClasses)
	fmt.Printf("Number of old keys kept: %d\n", p.PWHistoryNum)
}

// policyArg takes the one positional argument, which is a policy name
// and not a principal: it carries no realm.
func policyArg(fs *flag.FlagSet) (string, error) {
	if fs.NArg() != 1 {
		return "", errors.New(
			"expected exactly one policy name")
	}
	return fs.Arg(0), nil
}
