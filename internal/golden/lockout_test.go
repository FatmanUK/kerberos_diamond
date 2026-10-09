package golden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// TestStockKinitLocksOut is lockout end to end: a stock kinit with
// the wrong password three times, and the fourth attempt refused even
// with the *right* one.
//
// The last part is what the feature is for, and it is also the only
// assertion that cannot be faked by a KDC that simply counts: being
// refused a correct password is the observable difference between
// "wrong password" and "locked out".
func TestStockKinitLocksOut(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "lockout",
		clientConf)
	attachLockout(t, ctx, 3)

	// The preauth principal is the one that can be locked out at
	// all: without a pre-authentication requirement a client
	// never proves anything, so there is no failure to count.
	for i := 0; i < 3; i++ {
		out, err := o.ExecEnv(ctx, env, "wrong-password\n",
			"kinit", PreauthName+"@"+Realm)
		if err == nil {
			t.Fatalf("a wrong password was accepted:\n%s",
				out)
		}
	}
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", PreauthName+"@"+Realm)
	if err == nil {
		t.Fatalf("the right password still worked:\n%s", out)
	}
	if !strings.Contains(out, "revoked") &&
		!strings.Contains(out, "Client's credentials") {
		t.Errorf("kinit did not report a lockout:\n%s", out)
	}
	assertUnlockRestores(t, ctx, o, env)
}

// assertUnlockRestores clears the counter the way modprinc -unlock
// does and checks the principal works again -- which is the other
// half of a lockout being useful rather than permanent.
func assertUnlockRestores(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
) {
	t.Helper()
	d := diamondOf(t)
	p, err := d.Store.Lookup(ctx, PreauthName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	if p.FailAuthCount < 3 {
		t.Errorf("only %d failures were counted",
			p.FailAuthCount)
	}
	if err := d.Store.Unlock(ctx, p); err != nil {
		t.Fatal(err)
	}
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("the unlock did not take: %v\n%s", err, out)
	}
}

// Nothing here drives the shared-counter property, and the reason is
// worth a line: it is the store's and is asserted there
// (internal/store's lockout tests read the count back through a fresh
// Lookup, which *is* two KDCs sharing it). Standing a second KDC up
// here would prove the same thing more slowly.

// attachLockout gives the preauth principal a lockout policy,
// reaching past the KDC because nothing in the protocol can ask for
// one.
func attachLockout(
	t *testing.T, ctx context.Context, maxFail int32,
) {
	t.Helper()
	d := diamondOf(t)
	pol := store.NewPolicy("locking")
	pol.PWMaxFail = maxFail
	if err := d.Store.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	p, err := d.Store.Lookup(ctx, PreauthName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = "locking"
	if err := d.Store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
}
