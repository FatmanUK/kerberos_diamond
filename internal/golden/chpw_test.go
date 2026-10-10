package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/store"
)

// TestStockKpasswdAgainstTheGoKDC is the end-to-end check for the
// password-change protocol, and the only evidence that a real client
// can change a real password here.
//
// It matters more than its size suggests. Changing a password is the
// one administrative operation ordinary users perform, and a realm
// where they cannot do it without a shell on the KDC's host is not an
// administrable realm -- which is why the argument for deferring a
// kadmin protocol does not transfer to this: administrators can be
// given database credentials and users cannot.
//
// An unmodified kpasswd authenticates with the old password, changes
// it, and an unmodified kinit then proves the new one works and the
// old one does not. Every byte of the frame, the AP-REQ, the KRB-PRIV
// and the AP-REP in the reply is the client's own doing.
func TestStockKpasswdAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "kpasswd",
		changePWConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")
	const newPW = "a-replacement-password"

	// kpasswd prompts for the current password once and the new
	// one twice.
	in := UserPassword + "\n" + newPW + "\n" + newPW + "\n"
	out, err := o.ExecEnv(ctx, env, in, "kpasswd",
		UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kpasswd failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Password changed") {
		t.Errorf("kpasswd did not report a change:\n%s", out)
	}
	assertChangeWentThroughTheShim(t, out)
	assertKinitPassword(t, ctx, o, env, newPW, true)
	assertKinitPassword(t, ctx, o, env, UserPassword, false)
}

// changePWConf points both the KDC and the password-change service at
// the Go KDC through the shim.
//
// kpasswd_server is the key that matters and it resolves through the
// same profile machinery as kdc (locate_kdc.c:565-568), which is what
// makes `https://host/path` work for a client built with a TLS module
// -- the spelling a real deployment would use, and the one Phase C's
// client will exercise. Here it is the shim's address for the same
// reason every other end-to-end case uses the shim: the oracle's
// client has no TLS module.
//
// The admin_server spelling is deliberately not tested.
// locate_kpasswd falls back to it and then *rewrites the port to 464*
// (changepw.c:59-88), and the shim listens on a port chosen at run
// time, so the fallback cannot be pointed anywhere useful from here.
func changePWConf(port int) string {
	return fmt.Sprintf(`[libdefaults]
	default_realm = %[1]s
	dns_lookup_kdc = false
	dns_lookup_realm = false
	dns_canonicalize_hostname = false
	rdns = false
	qualify_shortname = ""
	udp_preference_limit = 1
	noaddresses = true

[realms]
	%[1]s = {
		kdc = %[2]s:%[3]d
		kpasswd_server = %[2]s:%[3]d
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, Realm, HostAlias, port)
}

// assertChangeWentThroughTheShim reads the client's own trace. The
// hazard is the same one every end-to-end case here has: the C KDC is
// in the same container, and a case that did not check would pass
// with the C doing the work.
//
// The second assertion is the interesting one. A password change is
// two exchanges -- an AS exchange for kadmin/changepw and then the
// change itself -- and the client logs the second as a plain send
// with no Kerberos message type, because it is not one.
func assertChangeWentThroughTheShim(
	t *testing.T, trace string,
) {
	t.Helper()
	if !strings.Contains(trace,
		"Resolving hostname "+HostAlias) {
		t.Errorf("no shim in the trace:\n%s", trace)
	}
	want := "Getting initial credentials for " + UserName +
		"@" + Realm
	if !strings.Contains(trace, want) {
		t.Errorf("no initial credentials in the trace:\n%s",
			trace)
	}
	if !strings.Contains(trace, "kadmin/changepw@"+Realm) {
		t.Errorf("the change did not go to kadmin/changepw"+
			":\n%s", trace)
	}
}

// assertKinitPassword runs a stock kinit and says whether it should
// work. Both directions are asserted, because a change that *added* a
// key rather than replacing it would leave the old password working
// and look like a success from the client's side.
func assertKinitPassword(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	password string,
	want bool,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, password+"\n",
		"kinit", UserName+"@"+Realm)
	if want && err != nil {
		t.Errorf("kinit with the new password failed: "+
			"%v\n%s", err, out)
	}
	if !want && err == nil {
		t.Errorf("kinit with the old password still "+
			"worked:\n%s", out)
	}
}

// TestStockKinitChangesAnExpiredPassword is the other half of the
// password-change story, and the half a user actually meets: not
// running kpasswd deliberately, but being made to change a password
// at login.
//
// A principal marked +needchange cannot get an ordinary ticket --
// KDC_ERR_KEY_EXP -- but *can* get one for the password-changing
// service, because that service carries PWCHANGE_SERVICE and the
// policy excuses the expiry for it. kinit notices, prompts for a new
// password, runs the change itself, and then retries the login. All
// of it is the client's own logic; this project only has to answer
// the three exchanges correctly.
//
// It is upstream's own first case in tests/t_changepw.py:13-17, with
// +needchange rather than -pwexpire for the same reason its second
// case uses it: the bit is the unambiguous one.
func TestStockKinitChangesAnExpiredPassword(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "needchange",
		changePWConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")
	requirePasswordChange(t, ctx)

	const newPW = "chosen-at-the-prompt"
	in := UserPassword + "\n" + newPW + "\n" + newPW + "\n"
	out, err := o.ExecEnv(ctx, env, in, "kinit",
		UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit did not change the password: "+
			"%v\n%s", err, out)
	}
	// The trace names both halves: the ticket for the
	// password-changing service, which the expiry is excused for,
	// and then the login that follows the change.
	for _, want := range []string{
		"Setting initial creds service to kadmin/changepw",
		"Getting initial credentials for " + UserName +
			"@" + Realm,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the trace has no %q:\n%s",
				want, out)
		}
	}
	assertTicket(t, ctx, o, env, UserName)
	assertKinitPassword(t, ctx, o, env, newPW, true)
}

// requirePasswordChange sets REQUIRES_PWCHANGE on the user, which is
// kadmin's +needchange. It reaches past the KDC to the store, because
// nothing in the protocol can ask for it.
func requirePasswordChange(t *testing.T, ctx context.Context) {
	t.Helper()
	d := diamondOf(t)
	p, err := d.Store.Lookup(ctx, UserName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	p.Attributes |= store.AttrRequiresPWChange
	if err := d.Store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
}

// TestStockKpasswdHonoursAPolicy is the policy's end-to-end case, and
// the assertion is on what the *user* sees: a password change refused
// with a sentence explaining why.
//
// The result code carries the explanation, which is the point of
// having one. Upstream maps every quality failure to
// KRB5_KPASSWD_SOFTERROR (schpw.c:246-273), which tells a client the
// password was rejected rather than that something went wrong, and
// kpasswd prints the string beside it -- so the sentence is the only
// thing telling the user what to type instead.
func TestStockKpasswdHonoursAPolicy(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "policy",
		changePWConf)
	attachPolicy(t, ctx, 12)

	// Too short, so the change is refused and the old password
	// still works.
	out, err := o.ExecEnv(ctx, env,
		UserPassword+"\nshort\nshort\n", "kpasswd",
		UserName+"@"+Realm)
	if err == nil {
		t.Errorf("a short password was accepted:\n%s", out)
	}
	if !strings.Contains(out, "too short") {
		t.Errorf("kpasswd did not say why:\n%s", out)
	}
	assertKinitPassword(t, ctx, o, env, UserPassword, true)

	// Long enough, and it goes through -- which is what says the
	// policy was consulted rather than the change being broken.
	long := "long-enough-to-pass"
	out, err = o.ExecEnv(ctx, env,
		UserPassword+"\n"+long+"\n"+long+"\n", "kpasswd",
		UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("a long password was refused: %v\n%s",
			err, out)
	}
	assertKinitPassword(t, ctx, o, env, long, true)
}

// attachPolicy creates a policy with a minimum length and points the
// user at it, reaching past the KDC because nothing in the protocol
// can ask for either.
func attachPolicy(
	t *testing.T, ctx context.Context, minLength int32,
) {
	t.Helper()
	d := diamondOf(t)
	pol := store.NewPolicy("golden")
	pol.PWMinLength = minLength
	if err := d.Store.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	p, err := d.Store.Lookup(ctx, UserName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = "golden"
	if err := d.Store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
}

// TestStockKpasswdRefusesAReusedPassword is password history end to
// end, and the message is what a user sees: "Cannot reuse password",
// which is upstream's own wording for the condition
// (tests/t_policy.py:108-109 asserts it).
//
// The comparison is of key material rather than of passwords, which
// is the only way it can work -- nothing stored is reversible. That
// also makes it exact: a password that derives the same key under the
// same salt is the same password.
func TestStockKpasswdRefusesAReusedPassword(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "history",
		changePWConf)
	attachHistory(t, ctx, 2)

	// The current password cannot be set again, which is what a
	// history of one would already give.
	out, err := o.ExecEnv(ctx, env,
		UserPassword+"\n"+UserPassword+"\n"+UserPassword+
			"\n", "kpasswd", UserName+"@"+Realm)
	if err == nil {
		t.Errorf("the same password was accepted:\n%s", out)
	}
	// Change it twice, and the first one is still remembered -- a
	// history of two being the current password and the one
	// before it.
	first, second := "first-replacement", "second-replacement"
	changePassword(t, ctx, o, env, UserPassword, first)
	changePassword(t, ctx, o, env, first, second)

	out, err = o.ExecEnv(ctx, env,
		second+"\n"+first+"\n"+first+"\n", "kpasswd",
		UserName+"@"+Realm)
	if err == nil {
		t.Errorf("a remembered password was accepted:\n%s",
			out)
	}
	// And the one before that has been forgotten, so it may come
	// back round.
	changePassword(t, ctx, o, env, second, UserPassword)
}

// changePassword runs a stock kpasswd and insists it worked.
func changePassword(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	old, new string,
) {
	t.Helper()
	in := old + "\n" + new + "\n" + new + "\n"
	out, err := o.ExecEnv(ctx, env, in, "kpasswd",
		UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("changing to %q failed: %v\n%s",
			new, err, out)
	}
}

// attachHistory creates a policy that remembers that many passwords
// and points the user at it.
func attachHistory(
	t *testing.T, ctx context.Context, keep int32,
) {
	t.Helper()
	d := diamondOf(t)
	pol := store.NewPolicy("remembering")
	pol.PWHistoryNum = keep
	if err := d.Store.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	p, err := d.Store.Lookup(ctx, UserName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = "remembering"
	if err := d.Store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
}

// TestStockKpasswdNamesWhosePasswordItChanges records what `kpasswd
// <principal>` actually does, which is not what it looks like and
// which the first draft of this test got wrong.
//
// It is a *self* change for the principal named: kpasswd gets initial
// credentials for that principal, prompting for its current password,
// and then changes it. The argument says whose password to change,
// not who is doing the changing -- so an administrator cannot use it
// to set somebody else's.
//
// **RFC 3244 set-password therefore has no stock client to test
// against, anywhere.** kpasswd only ever calls krb5_change_password,
// which is version 1 (clients/kpasswd/kpasswd.c:152), and nothing in
// upstream's whole tree calls krb5_set_password -- it is a library
// entry point for third parties, with the server side shipped and no
// caller. The 0xff80 path here is implemented from the specification
// and anchored by internal/kdc's own cases, and that is worth saying
// plainly rather than leaving a test that appeared to cover it.
//
// The first draft of this test appeared to pass for a worse reason
// still: the fixture gives `user` and `preauth` the same password, so
// a self change for one looked like an administrative change by the
// other.
func TestStockKpasswdNamesWhosePasswordItChanges(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "setpw",
		changePWConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")

	const newPW = "changed-by-its-owner"
	in := UserPassword + "\n" + newPW + "\n" + newPW + "\n"
	out, err := o.ExecEnv(ctx, env, in, "kpasswd",
		PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("kpasswd failed: %v\n%s", err, out)
	}
	// The trace names the principal it authenticated *as*, which
	// is the one on the command line.
	want := "Getting initial credentials for " +
		PreauthName + "@" + Realm
	if !strings.Contains(out, want) {
		t.Errorf("the trace has no %q:\n%s", want, out)
	}
	// And it is version 1, not RFC 3244's: the client chose.
	if strings.Contains(out, "Setting password for") {
		t.Errorf("kpasswd used set-password:\n%s", out)
	}
	assertPreauthPassword(t, ctx, o, env, newPW)
}

// assertPreauthPassword checks the preauth principal's password by
// using it, which needs the pre-authentication round trip a stock
// kinit does for us.
func assertPreauthPassword(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	password string,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, password+"\n", "kinit",
		PreauthName+"@"+Realm)
	if err != nil {
		t.Errorf("kinit with %q failed: %v\n%s",
			password, err, out)
	}
}
