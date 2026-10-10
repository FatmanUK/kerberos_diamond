package kdc

import (
	"context"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// addAlias points one name at another in the test realm.
func addAlias(t *testing.T, k *KDC, alias, target string) {
	t.Helper()
	err := k.Store.CreateAlias(context.Background(),
		alias+"@"+testRealm, target+"@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
}

// An alias authenticates, and **the ticket names the alias** rather
// than the principal behind it.
//
// That is the default and it is what upstream's own test asserts:
// `kinit -k alias' then `klist' shows alias@KRBTEST.COM
// (t_alias.py:30-31). Canonicalising without being asked would change
// the name a client sees for no reason it could predict.
func TestAnAliasAuthenticatesUnderItsOwnName(t *testing.T) {
	k := testKDC(t)
	addAlias(t, k, "alias", "user")
	rep, kerr := as(t, k, asRequest([]string{"alias"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.Components[0]; got != "alias" {
		t.Errorf("the reply names %q, want the alias", got)
	}
	tkt := decodeTicket(t, k, rep)
	if got := tkt.CName.Components[0]; got != "alias" {
		t.Errorf("the ticket names %q", got)
	}
}

// With KDC_OPT_CANONICALIZE the client name becomes the database's,
// which is do_as_req.c:680-682 -- and the half of D2 that could not
// be reached until there were aliases, because the found entry's name
// can only differ from the requested one through one.
//
// Upstream asserts it from the outside: `kinit -k -C alias' then
// klist shows canon@KRBTEST.COM (t_alias.py:32-33).
func TestCanonicalizeNamesTheCanonicalClient(t *testing.T) {
	k := testKDC(t)
	addAlias(t, k, "alias", "user")
	req := asRequest([]string{"alias"})
	req.Body.Options |= wire.OptCanonicalize
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.Components[0]; got != "user" {
		t.Errorf("the reply names %q, want the canonical "+
			"principal", got)
	}
	tkt := decodeTicket(t, k, rep)
	if got := tkt.CName.Components[0]; got != "user" {
		t.Errorf("the ticket names %q", got)
	}
}

// The *server* name is canonicalised only when CANONICALIZE is set
// **and** both the requested and the found server are ticket-granting
// services (:659-663), which upstream's own comment limits to Windows
// short-realm aliases and "nothing more".
//
// So an alias of an ordinary service keeps the requested name even
// with CANONICALIZE, which is the case this asserts: it is the rule
// that is easy to over-apply, and over-applying it would rename a
// service in every ticket issued for it.
func TestAServiceAliasKeepsTheRequestedName(t *testing.T) {
	k := testKDC(t)
	addPrincipal(t, k.Store, localMasterKey(t),
		[]string{"host", "real.kdiamond.test"},
		"servicepassword", 0)
	addAlias(t, k, "host/alias.kdiamond.test",
		"host/real.kdiamond.test")
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptCanonicalize
	req.Body.SName = &wire.PrincipalName{
		Type: wire.NTSrvHst,
		Components: []string{"host",
			"alias.kdiamond.test"},
	}
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	got := rep.Ticket.SName.Components[1]
	if got != "alias.kdiamond.test" {
		t.Errorf("the ticket names %q, want the alias", got)
	}
}

// And the key the reply is sealed with is the **canonical
// principal's**, derived under the canonical name's salt -- which is
// what makes a password login through an alias work at all.
//
// It is the trap in this whole step. The default salt is the realm
// followed by the principal's own name components, so deriving it
// from the name the client typed gives a key neither side agrees
// about, and the failure a client reports for that is "password
// incorrect" with nothing to say why. Decrypting the reply with a key
// derived from `user' and not from `alias' is the assertion.
func TestAnAliasLoginUsesTheCanonicalSalt(t *testing.T) {
	k := testKDC(t)
	addAlias(t, k, "alias", "user")
	rep, kerr := as(t, k, asRequest([]string{"alias"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, []string{"user"}, userPassword, e)
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("the canonical key did not open it: %v",
			err)
	}
	if _, err := wire.UnmarshalEncKDCRepPart(
		plain); err != nil {
		t.Fatal(err)
	}
	// And the alias's own name derives a key that does not.
	wrong := clientKey(t, []string{"alias"}, userPassword, e)
	if _, err := p.Decrypt(wrong, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart); err == nil {
		t.Error("the alias's salt opened it too, so the " +
			"test proves nothing")
	}
}

// A dangling alias is not a principal, and the refusal is the
// ordinary one: a client asking for a name that resolves nowhere is
// told the client is unknown, not told about aliases.
func TestADanglingAliasIsUnknown(t *testing.T) {
	k := testKDC(t)
	addAlias(t, k, "dangling", "nobody")
	_, kerr := as(t, k, asRequest([]string{"dangling"}))
	if kerr == nil {
		t.Fatal("accepted")
	}
	if kerr.ErrorCode != wire.ErrCodeCPrincipalUnknown {
		t.Errorf("code %d", kerr.ErrorCode)
	}
	// And the store agrees it is not an alias of anything, which
	// is what makes it overwritable.
	is, err := k.Store.IsAlias(context.Background(),
		"dangling@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if is {
		t.Error("a dangling alias reported as an alias")
	}
}
