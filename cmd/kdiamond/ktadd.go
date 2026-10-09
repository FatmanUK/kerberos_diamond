package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/keytab"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// ktadd writes a principal's keys into a keytab, which is kadmin's
// ktadd (and its alias xst).
//
// Two things about it are worth knowing before reading the code.
//
// First, it **re-keys the principal by default**, and that is not a
// side effect to be tidied away: a keytab is a copy of a secret, and
// handing one out without changing the key would mean every previous
// copy still worked. kadmin does the same, which is why `ktadd` twice
// in a row locks out whatever read the first file. -norandkey is the
// escape hatch, and upstream guards it with a privilege of its own --
// the `e` in an ACL, which is deliberately *not* included in the "all
// privileges" letters x and * because extracting an existing key is
// strictly more dangerous than replacing it (auth_acl.c:49-56).
//
// Second, keys are appended rather than written over. A keytab holds
// every version a service might still be presented a ticket under,
// and a reader picks by key version and enctype.
func ktadd(args []string) error {
	fs := flag.NewFlagSet("ktadd", flag.ContinueOnError)
	file := fs.String("k", "", "the keytab file to write")
	norandkey := fs.Bool("norandkey", false,
		"extract the current keys instead of new ones")
	keepOld := fs.Bool("keepold", false,
		"keep the previous key version as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("-k is required")
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
	return addToKeytab(s, *file, name, *norandkey,
		*keepOld)
}

// addToKeytab does the work: re-key unless told not to, then append.
func addToKeytab(
	s *store.Store,
	file, name string,
	norandkey, keepOld bool,
) error {
	ctx := context.Background()
	p, err := s.Lookup(ctx, name)
	if err != nil {
		return err
	}
	if !norandkey {
		kvno := p.HighestKVNO() + 1
		if keepOld {
			err = s.SetRandomKeyKeepOld(p, kvno)
		} else {
			err = s.SetRandomKey(p, kvno)
		}
		if err != nil {
			return err
		}
		if err := s.Save(ctx, p); err != nil {
			return err
		}
	}
	entries, err := keytabEntries(s, p)
	if err != nil {
		return err
	}
	if err := appendKeytab(file, entries); err != nil {
		return err
	}
	fmt.Printf("Added %d key(s) for %q to %s at "+
		"key version %d.\n",
		len(entries), name, file, p.HighestKVNO())
	return nil
}

// keytabEntries decrypts every key a principal holds at its highest
// version.
//
// Only the highest: an older version is of no use to a service being
// set up now, and writing one out would put a key the database has
// already replaced into a file somebody copies around. kadmin writes
// only the current keys too.
func keytabEntries(
	s *store.Store,
	p *store.Principal,
) ([]keytab.Entry, error) {
	components, realm, err := store.ParseName(p.Name)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	var out []keytab.Entry
	start := 0
	for {
		row, key, err := s.Key(p, &start, store.AnyEType,
			store.AnySaltType, store.HighestKVNO)
		// Only "no more keys" ends the walk. Anything else is
		// a key that exists and could not be read -- a master
		// key of the wrong version, most likely -- and
		// swallowing it would write a short keytab that
		// looked complete.
		if errors.Is(err, store.ErrNoMatchingKey) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, keytab.Entry{
			Realm: realm, Components: components,
			NameType:  nameTypeFor(components),
			Timestamp: now, KVNO: row.KVNO,
			EncType: row.EType, Key: key,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"%q has no keys to extract", p.Name)
	}
	return out, nil
}

// nameTypeFor is the name type a keytab entry carries.
//
// A two-component name is a host-based service and gets NT-SRV-HST,
// which is what krb5_sname_to_principal builds on the client side and
// so what a service looks itself up as; anything else is
// NT-PRINCIPAL. kadmin writes whatever the database holds, and this
// project's store does not keep a name type -- so it is derived, and
// the derivation is the convention rather than a guess.
func nameTypeFor(components []string) int32 {
	if len(components) == 2 {
		return ntSrvHst
	}
	return ntPrincipal
}

// The two name types a keytab entry can carry here, from
// internal/wire's table. They are repeated rather than imported
// because cmd/kdiamond has no other reason to depend on the wire
// package.
const (
	ntPrincipal int32 = 1
	ntSrvHst    int32 = 3
)

// appendKeytab adds entries to a keytab, creating it if it is not
// there.
//
// Read-modify-write rather than an append to the file, because the
// two-octet version header belongs to the whole file and not to each
// record. Upstream writes in place and reuses holes
// (krb5_ktfileint_find_slot); nothing here deletes, so there are no
// holes to reuse and the simpler thing is also the correct one.
//
// The file is written through a temporary and renamed, so a keytab a
// service is already reading is never half-written. Mode 0600: it
// holds keys.
func appendKeytab(file string, add []keytab.Entry) error {
	var entries []keytab.Entry
	switch old, err := os.ReadFile(file); {
	case err == nil:
		entries, err = keytab.Unmarshal(old)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	out, err := keytab.Marshal(append(entries, add...))
	if err != nil {
		return err
	}
	tmp := file + ".new"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// purgekeys drops every key version below the current one, which is
// kadmin's purgekeys.
//
// It is the other half of keepold: a previous version is kept so that
// tickets already issued under it keep verifying, and removed once
// none can still be in use -- which is a judgement about ticket
// lifetimes and so an operator's to make, not the KDC's.
func purgekeys(args []string) error {
	fs := flag.NewFlagSet("purgekeys", flag.ContinueOnError)
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
	p, err := s.Lookup(ctx, name)
	if err != nil {
		return err
	}
	removed := p.PurgeOldKeys()
	if removed == 0 {
		fmt.Printf("%q has only its current keys.\n", name)
		return nil
	}
	if err := s.Save(ctx, p); err != nil {
		return err
	}
	fmt.Printf("Removed %d old key(s) from %q, leaving key "+
		"version %d.\n", removed, name, p.HighestKVNO())
	return nil
}
