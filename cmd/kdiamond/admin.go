package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/config"
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
)

// The administration subcommands stand in for kadmin.
//
// They are subcommands of the KDC rather than a protocol of their
// own, which is the deliberate departure: kadmin exists because a
// flat-file database can only be edited by a process on the same
// host, and a relational one can be edited by anything that can reach
// it. Until something external needs to provision principals, SQL
// plus these commands is the whole of the interface -- and `kdiamond
// getprinc` is the thing an operator reaches for when a client says
// "password incorrect".
//
// The vocabulary is kadmin's on purpose: addprinc, modprinc, cpw,
// delprinc, getprinc, listprincs, and the same +/- attribute
// specifiers, aliases included. An operator should not have to learn
// a second set of words to do the same job.

// openStore connects using the process's own configuration, so an
// administrative command cannot be pointed at a different database
// than the KDC serves by accident.
func openStore() (*store.Store, *config.Config, error) {
	c, err := config.Load(config.Admin)
	if err != nil {
		return nil, nil, err
	}
	mkey, err := store.DeriveMasterKeyWith(c.MasterKDF,
		c.Realm, c.MasterPassword,
		store.DefaultMasterKeyType)
	if err != nil {
		return nil, nil, err
	}
	s, err := store.Open(c.DatabaseURL, mkey)
	if err != nil {
		return nil, nil, err
	}
	s.SetEnctypes(c.Enctypes)
	return s, c, nil
}

// principalArg splits a trailing principal name from a command's
// arguments, supplying the realm when the name omits it.
//
// A bare name is completed with the KDC's own realm, which is what
// kadmin does with its default realm. Accepting a *different* realm
// would be worse than refusing it: this KDC serves one, and a
// principal filed under another would simply never be found.
func principalArg(
	fs *flag.FlagSet,
	realm string,
) (string, error) {
	if fs.NArg() != 1 {
		return "", errors.New("name exactly one principal")
	}
	return qualify(fs.Arg(0), realm)
}

// qualify completes a bare name with this KDC's realm and refuses any
// other, which is what stops a command meant for one realm landing in
// another's rows.
func qualify(name, realm string) (string, error) {
	if !strings.Contains(name, "@") {
		return name + "@" + realm, nil
	}
	if !strings.HasSuffix(name, "@"+realm) {
		return "", fmt.Errorf(
			"%q is not in this KDC's realm %s",
			name, realm)
	}
	return name, nil
}

// addprinc creates a principal.
func addprinc(args []string) error {
	fs := flag.NewFlagSet("addprinc", flag.ContinueOnError)
	pw := fs.String("pw", "", "password to derive keys from")
	kvno := fs.Int("kvno", 1, "key version number")
	maxLife := fs.Duration("maxlife", 0,
		"maximum ticket life; zero takes the default")
	maxRenew := fs.Duration("maxrenewlife", 0,
		"maximum renewable life")
	attrs := attrFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pw == "" {
		return errors.New("-pw is required")
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
	p, err := buildPrincipal(s, name, c.Realm, addOpts{
		pw:       *pw,
		kvno:     int32(*kvno),
		maxLife:  *maxLife,
		maxRenew: *maxRenew,
		attrs:    *attrs,
	})
	if err != nil {
		return err
	}
	if err := s.Save(context.Background(), p); err != nil {
		return err
	}
	fmt.Printf("Principal %q created.\n", name)
	return nil
}

// addOpts is what addprinc was asked for.
type addOpts struct {
	pw       string
	kvno     int32
	maxLife  time.Duration
	maxRenew time.Duration
	attrs    attrList
}

// buildPrincipal creates the principal, refusing to overwrite one
// that already exists.
//
// Refusing rather than updating matters: addprinc on an existing name
// would otherwise replace its key list silently, invalidating every
// ticket already issued for it. modprinc and cpw are the commands
// that change one.
func buildPrincipal(
	s *store.Store,
	name, realm string,
	o addOpts,
) (*store.Principal, error) {
	ctx := context.Background()
	if _, err := s.Lookup(ctx, name); err == nil {
		return nil, fmt.Errorf("%s already exists", name)
	}
	p, err := newPrincipal(s, name, realm, o.pw, o.kvno)
	if err != nil {
		return nil, err
	}
	if err := applyAll(p, o.attrs); err != nil {
		return nil, err
	}
	setLifetimes(p, o.maxLife, o.maxRenew)
	return p, nil
}

// newPrincipal builds a principal with kadmin's defaults and a
// password set.
func newPrincipal(
	s *store.Store,
	name, realm, pw string,
	kvno int32,
) (*store.Principal, error) {
	components, _, err := store.ParseName(name)
	if err != nil {
		return nil, err
	}
	p := store.NewPrincipal(realm, components)
	err = s.SetPassword(p, pw, kvno)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// setLifetimes applies the two lifetime flags, leaving the defaults
// in place when a flag was not given.
func setLifetimes(
	p *store.Principal,
	maxLife, maxRenew time.Duration,
) {
	if maxLife > 0 {
		p.MaxLife = int32(maxLife / time.Second)
	}
	if maxRenew > 0 {
		p.MaxRenewableLife = int32(maxRenew / time.Second)
	}
}

// modprinc changes a principal's attributes and lifetimes.
func modprinc(args []string) error {
	f := newModFlags()
	if err := f.fs.Parse(args); err != nil {
		return err
	}
	s, c, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	name, err := principalArg(f.fs, c.Realm)
	if err != nil {
		return err
	}
	ctx := context.Background()
	p, err := s.Lookup(ctx, name)
	if err != nil {
		return err
	}
	if err := f.apply(ctx, s, p); err != nil {
		return err
	}
	if err := s.Save(ctx, p); err != nil {
		return err
	}
	// The unlock comes after the save, because it writes only the
	// three lockout counters: before it, Save would write the
	// stale ones straight back over it.
	if *f.unlock {
		if err := s.Unlock(ctx, p); err != nil {
			return err
		}
	}
	fmt.Printf("Principal %q modified.\n", name)
	return nil
}

// modFlags is everything modprinc takes.
type modFlags struct {
	fs *flag.FlagSet

	maxLife     *time.Duration
	maxRenew    *time.Duration
	attrs       *attrList
	policy      *string
	clearPolicy *bool
	unlock      *bool
}

func newModFlags() *modFlags {
	fs := flag.NewFlagSet("modprinc", flag.ContinueOnError)
	return &modFlags{
		fs: fs,
		maxLife: fs.Duration("maxlife", 0,
			"maximum ticket life"),
		maxRenew: fs.Duration("maxrenewlife", 0,
			"maximum renewable life"),
		attrs: attrFlag(fs),
		policy: fs.String("policy", "",
			"the password policy this principal follows"),
		clearPolicy: fs.Bool("clearpolicy", false,
			"stop following any policy"),
		unlock: fs.Bool("unlock", false,
			"clear a lockout's failure count"),
	}
}

// apply is everything but the unlock, which has to wait for the save.
func (f *modFlags) apply(
	ctx context.Context,
	s *store.Store,
	p *store.Principal,
) error {
	return modifyPrincipal(ctx, s, p, *f.attrs, *f.policy,
		*f.clearPolicy, *f.maxLife, *f.maxRenew)
}

// modifyPrincipal applies everything modprinc can change.
func modifyPrincipal(
	ctx context.Context,
	s *store.Store,
	p *store.Principal,
	attrs []string,
	policy string,
	clearPolicy bool,
	maxLife, maxRenew time.Duration,
) error {
	if err := applyAll(p, attrs); err != nil {
		return err
	}
	err := setPolicy(ctx, s, p, policy, clearPolicy)
	if err != nil {
		return err
	}
	setLifetimes(p, maxLife, maxRenew)
	return nil
}

// cpw changes a principal's password, bumping its key version.
//
// The version has to move, and silently reusing it would be the
// dangerous thing: a client holding a ticket encrypted under the old
// key identifies it by kvno, so a new key at the same version makes
// that ticket undecryptable with nothing to say why.
func cpw(args []string) error {
	fs := flag.NewFlagSet("cpw", flag.ContinueOnError)
	pw := fs.String("pw", "", "the new password")
	keepOld := fs.Bool("keepold", false,
		"keep the previous key version as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pw == "" {
		return errors.New("-pw is required")
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
	p, err := s.Lookup(ctx, name)
	if err != nil {
		return err
	}
	kvno, err := s.ChangePassword(ctx, p, *pw,
		*keepOld)
	if err != nil {
		return err
	}
	if err := s.Save(ctx, p); err != nil {
		return err
	}
	fmt.Printf("Password for %q changed, now key version %d.\n",
		name, kvno)
	return nil
}

// delprinc removes a principal.
func delprinc(args []string) error {
	fs := flag.NewFlagSet("delprinc", flag.ContinueOnError)
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
	if _, err := s.Lookup(ctx, name); err != nil {
		return err
	}
	if err := s.Delete(ctx, name); err != nil {
		return err
	}
	fmt.Printf("Principal %q deleted.\n", name)
	return nil
}

// listprincs prints every principal's name.
func listprincs(args []string) error {
	fs := flag.NewFlagSet("listprincs", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("listprincs takes no arguments")
	}
	s, _, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	names, err := s.List(context.Background())
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

// getprinc prints what the KDC knows about a principal.
//
// This is the command an operator reaches for when a client reports
// "password incorrect", which is why the *salt* is printed beside
// each key: a wrong salt is the usual cause and is invisible
// everywhere else.
func getprinc(args []string) error {
	fs := flag.NewFlagSet("getprinc", flag.ContinueOnError)
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
	p, err := s.Lookup(context.Background(), name)
	if err != nil {
		return err
	}
	printPrincipal(p)
	return nil
}

func printPrincipal(p *store.Principal) {
	fmt.Printf("Principal: %s\n", p.Name)
	fmt.Printf("Expiration date: %s\n", orNever(p.Expiration))
	fmt.Printf("Last password change: %s\n",
		orNever(p.LastPWChange))
	fmt.Printf("Password expiration date: %s\n",
		orNever(p.PWExpiration))
	fmt.Printf("Maximum ticket life: %s\n",
		lifeString(p.MaxLife))
	fmt.Printf("Maximum renewable life: %s\n",
		lifeString(p.MaxRenewableLife))
	fmt.Printf("Key version number: %d\n", p.HighestKVNO())
	fmt.Printf("Attributes: %s\n",
		strings.Join(store.AttrNames(p.Attributes), " "))
	fmt.Printf("Number of keys: %d\n", len(p.Keys))
	for _, k := range p.Keys {
		fmt.Printf("Key: vno %d, %s, salt %q\n",
			k.KVNO, enctypeName(k.EType), keySalt(p, k))
	}
	for _, d := range p.TLData {
		fmt.Printf("Tl-data: type %d, %d bytes\n",
			d.Type, len(d.Contents))
	}
}

// keySalt is the salt a client must run string-to-key with.
//
// An empty salt column means the principal's default salt, which is
// recomputed rather than stored (lib/kdb/decrypt_key.c:111-123), so
// it is computed here too rather than printed as empty.
func keySalt(p *store.Principal, k store.Key) string {
	if len(k.Salt) > 0 {
		return string(k.Salt)
	}
	components, realm, err := store.ParseName(p.Name)
	if err != nil {
		return ""
	}
	return string(crypto.Salt(realm, components))
}

func enctypeName(etype int32) string {
	prof, err := crypto.Profile(crypto.EncType(etype))
	if err != nil {
		return fmt.Sprintf("enctype %d (unsupported)", etype)
	}
	return prof.Name
}

func orNever(t time.Time) string {
	if t.IsZero() {
		return "[never]"
	}
	return t.UTC().Format("2006-01-02 15:04:05 MST")
}

// lifeString renders a lifetime the way getprinc does, and says what
// a zero means rather than printing "0 days".
//
// The two zeroes mean different things, which is exactly the sort of
// thing an operator should not have to remember: a zero maximum
// ticket life is unlimited, and a zero renewable life is none at all.
func lifeString(secs int32) string {
	if secs == 0 {
		return "0 (see BOOTSTRAP.md: unlimited for ticket " +
			"life, none for renewable life)"
	}
	d := time.Duration(secs) * time.Second
	return fmt.Sprintf("%d days %02d:%02d:%02d",
		secs/86400, int(d.Hours())%24,
		int(d.Minutes())%60, secs%60)
}

// setPolicy attaches or detaches a password policy.
//
// Attaching one recomputes the password expiry from its maximum life,
// which upstream does in the same place (svr_principal.c:613-634),
// and detaching one clears the expiry (:628-634). Without that a
// principal moved off an expiring policy would keep the deadline it
// no longer has a reason for.
//
// A policy that does not exist is refused here, where a *stored*
// reference to a missing policy is tolerated at password-change time.
// The asymmetry is deliberate and is upstream's: naming a typo is a
// mistake worth catching, while a policy deleted out from under a
// principal is a state that has to be survivable.
func setPolicy(
	ctx context.Context,
	s *store.Store,
	p *store.Principal,
	name string,
	clear bool,
) error {
	if clear && name != "" {
		return errors.New(
			"-policy and -clearpolicy are exclusive")
	}
	switch {
	case clear:
		p.Policy = ""
	case name != "":
		if _, err := s.LookupPolicy(ctx, name); err != nil {
			return err
		}
		p.Policy = name
	default:
		return nil
	}
	return s.SetPasswordExpiry(ctx, p, time.Now())
}

// renprinc renames a principal, which is kadmin's renprinc.
//
// The name is the primary key of five relations, so this is the most
// expensive write there is -- and the salt has to be pinned before
// anything moves, because the default salt is derived from the name
// and every password-derived key would otherwise stop working.
func renprinc(args []string) error {
	fs := flag.NewFlagSet("renprinc", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New(
			"expected an old and a new principal name")
	}
	s, c, err := openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	from, err := qualify(fs.Arg(0), c.Realm)
	if err != nil {
		return err
	}
	to, err := qualify(fs.Arg(1), c.Realm)
	if err != nil {
		return err
	}
	err = s.Rename(context.Background(), from, to)
	if err != nil {
		return err
	}
	fmt.Printf("Principal %q renamed to %q.\n", from, to)
	return nil
}
