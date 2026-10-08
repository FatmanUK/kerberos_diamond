package golden

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildKdiamond compiles the KDC binary once per run.
//
// The administrative commands are the one part of this project an
// operator drives directly, so they are exercised as a *binary* with
// arguments rather than by calling the functions behind them. A test
// that called addprinc() would not notice a flag that was never
// registered or a subcommand missing from the dispatch.
func buildKdiamond(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kdiamond")
	cmd := exec.Command("go", "build", "-o", bin,
		"github.com/FatmanUK/kerberos_diamond/cmd/kdiamond")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building kdiamond: %v\n%s", err, out)
	}
	return bin
}

// adminEnv is the environment the administrative commands read.
//
// They load the process's own configuration rather than taking a
// database flag, so a command cannot be pointed at a different
// database than the KDC serves by accident -- which means a test has
// to hand them the same environment a deployment would.
//
// And that is the whole of it: these commands open no socket, so they
// ask for no TLS material. They used to be handed /unused/cert.pem
// and a key beside it, paths that were never opened and existed only
// to get past a requirement belonging to the listener. config.Admin
// is what makes that unnecessary.
func adminEnv(url string) []string {
	return append(os.Environ(),
		"KD_DATABASE_URL="+url,
		"KD_REALM="+Realm,
		"KD_MASTER_PASSWORD="+MasterPass,
	)
}

// kdiamond runs one administrative command and returns its output.
func kdiamond(
	t *testing.T,
	bin, url string,
	args ...string,
) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = adminEnv(url)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mustRun insists a command succeeded.
func mustRun(
	t *testing.T,
	bin, url string,
	args ...string,
) string {
	t.Helper()
	out, err := kdiamond(t, bin, url, args...)
	if err != nil {
		t.Fatalf("kdiamond %s: %v\n%s",
			strings.Join(args, " "), err, out)
	}
	return out
}

// adminScratch gives the administrative commands an empty schema of
// their own and returns the URL to reach it by.
//
// It goes through StartDiamond so the schema is created and migrated
// the same way every other test's is, then drops the three principals
// that provisions: the point of these cases is that `kdiamond
// addprinc` can build a realm from nothing.
func adminScratch(t *testing.T, schema string) (string, string) {
	t.Helper()
	base := os.Getenv(TestDatabaseURL)
	if base == "" {
		t.Skip(TestDatabaseURL + " is unset")
	}
	d, err := StartDiamond(context.Background(), schema,
		time.Now().UTC)
	if err != nil {
		t.Skipf("no Go KDC: %v", err)
	}
	t.Cleanup(d.Close)
	ctx := context.Background()
	names, err := d.Store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, n := range names {
		if err := d.Store.Delete(ctx, n); err != nil {
			t.Fatalf("Delete %s: %v", n, err)
		}
	}
	return searchPath(base, schema), schema
}

// A realm built from nothing with addprinc, then read back with
// getprinc and listprincs.
func TestAdminBuildsARealm(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_build")

	mustRun(t, bin, url, "addprinc", "-pw", UserPassword,
		UserName)
	mustRun(t, bin, url, "addprinc", "-pw", TgtPassword,
		"krbtgt/"+Realm)

	list := mustRun(t, bin, url, "listprincs")
	for _, want := range []string{
		UserName + "@" + Realm,
		"krbtgt/" + Realm + "@" + Realm,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("listprincs omits %s:\n%s",
				want, list)
		}
	}

	got := mustRun(t, bin, url, "getprinc", UserName)
	// The salt is printed because a wrong salt is the usual cause
	// of "password incorrect" and is invisible everywhere else.
	wantSalt := Realm + UserName
	if !strings.Contains(got, wantSalt) {
		t.Errorf("getprinc omits the salt %q:\n%s",
			wantSalt, got)
	}
	if !strings.Contains(got, "aes256-cts-hmac-sha1-96") {
		t.Errorf("getprinc names no enctype:\n%s", got)
	}
}

// addprinc refuses to overwrite an existing principal. Replacing its
// keys silently would invalidate every ticket already issued for it.
func TestAdminAddprincWillNotOverwrite(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_twice")

	mustRun(t, bin, url, "addprinc", "-pw", "first", UserName)
	out, err := kdiamond(t, bin, url, "addprinc", "-pw", "second",
		UserName)
	if err == nil {
		t.Fatalf("addprinc overwrote a principal:\n%s", out)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("refused for the wrong reason:\n%s", out)
	}
}

// The attribute specifiers are kadmin's, inverted senses included:
// +requires_preauth sets a bit and +allow_tix clears one.
func TestAdminAttributes(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_attrs")

	mustRun(t, bin, url, "addprinc", "-pw", UserPassword,
		"-attr", "+requires_preauth", UserName)
	got := mustRun(t, bin, url, "getprinc", UserName)
	if !strings.Contains(got, "REQUIRES_PRE_AUTH") {
		t.Errorf("the attribute did not stick:\n%s", got)
	}

	// -allow_tix *sets* DISALLOW_ALL_TIX, which is the inverted
	// sense an operator most needs to get right: it locks the
	// principal out.
	mustRun(t, bin, url, "modprinc",
		"-attr", "-allow_tix", UserName)
	got = mustRun(t, bin, url, "getprinc", UserName)
	if !strings.Contains(got, "DISALLOW_ALL_TIX") {
		t.Errorf("-allow_tix did not lock the principal:\n%s",
			got)
	}
	// And putting it back clears it again.
	mustRun(t, bin, url, "modprinc",
		"-attr", "+allow_tix", UserName)
	got = mustRun(t, bin, url, "getprinc", UserName)
	if strings.Contains(got, "DISALLOW_ALL_TIX") {
		t.Errorf("+allow_tix did not unlock it:\n%s", got)
	}
}

// cpw bumps the key version, which it has to: a new key at the same
// version makes every outstanding ticket undecryptable with nothing
// to say why.
func TestAdminCpwBumpsTheKVNO(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_cpw")

	mustRun(t, bin, url, "addprinc", "-pw", "first", UserName)
	got := mustRun(t, bin, url, "getprinc", UserName)
	if !strings.Contains(got, "Key version number: 1") {
		t.Fatalf("a new principal is not at kvno 1:\n%s", got)
	}
	out := mustRun(t, bin, url, "cpw", "-pw", "second", UserName)
	if !strings.Contains(out, "key version 2") {
		t.Errorf("cpw did not name the new version:\n%s",
			out)
	}
	got = mustRun(t, bin, url, "getprinc", UserName)
	if !strings.Contains(got, "Key version number: 2") {
		t.Errorf("the key version did not move:\n%s", got)
	}
}

// delprinc removes a principal, and refuses a name that is not there
// rather than reporting success for a no-op.
func TestAdminDelprinc(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_del")

	mustRun(t, bin, url, "addprinc", "-pw", "pw", UserName)
	mustRun(t, bin, url, "delprinc", UserName)
	list := mustRun(t, bin, url, "listprincs")
	if strings.Contains(list, UserName+"@"+Realm) {
		t.Errorf("the principal survived:\n%s", list)
	}
	if _, err := kdiamond(t, bin, url, "delprinc",
		UserName); err == nil {
		t.Error("deleting a missing principal succeeded")
	}
}

// A principal in another realm is refused rather than filed where it
// would never be found. A bare name takes this KDC's realm.
func TestAdminRefusesAForeignRealm(t *testing.T) {
	bin := buildKdiamond(t)
	url, _ := adminScratch(t, "kd_admin_realm")

	out, err := kdiamond(t, bin, url, "addprinc", "-pw", "pw",
		"someone@ELSEWHERE.TEST")
	if err == nil {
		t.Fatalf("accepted a foreign realm:\n%s", out)
	}
	if !strings.Contains(out, "ELSEWHERE.TEST") {
		t.Errorf("refused without naming the realm:\n%s", out)
	}
	mustRun(t, bin, url, "addprinc", "-pw", "pw",
		"someone@"+Realm)
	got := mustRun(t, bin, url, "getprinc", "someone")
	if !strings.Contains(got, "someone@"+Realm) {
		t.Errorf("a qualified name was misfiled:\n%s", got)
	}
}

// The lifetimes an operator sets have to reach the KDC's decisions,
// not just the database. This provisions a realm entirely with
// kdiamond and then has a stock kinit use it.
func TestAdminProvisionedRealmServesAStockKinit(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "admin", true)
	d := diamondOf(t)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_admin")
	wipe(t, ctx, d)

	mustRun(t, bin, url, "addprinc", "-pw", UserPassword,
		"-maxlife", "2h", UserName)
	mustRun(t, bin, url, "addprinc", "-pw", TgtPassword,
		"-kvno", "2", "krbtgt/"+Realm)

	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-l", "8h", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)
	assertTicket(t, ctx, o, env, UserName)
	// -maxlife 2h has to beat the client's -l 8h, or the
	// operator's policy is only in the database and not in the
	// KDC.
	assertTicketLife(t, ctx, o, env, 2*time.Hour)
}

// wipe empties a realm so the administrative commands can build it.
func wipe(t *testing.T, ctx context.Context, d *Diamond) {
	t.Helper()
	names, err := d.Store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, n := range names {
		if err := d.Store.Delete(ctx, n); err != nil {
			t.Fatalf("Delete %s: %v", n, err)
		}
	}
}

// assertTicketLife reads the ticket's own times out of klist and
// checks the span, which is the operator-visible end of the policy.
func assertTicketLife(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	want time.Duration,
) {
	t.Helper()
	list, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, list)
	}
	start, end, ok := ticketSpan(list)
	if !ok {
		t.Fatalf("klist shows no ticket times:\n%s", list)
	}
	got := end.Sub(start)
	if got != want {
		t.Errorf("ticket life is %v, want %v\n%s",
			got, want, list)
	}
}

// ticketSpan parses the valid-starting and expires columns klist
// prints. LC_ALL and TZ are pinned in the oracle image, so the format
// is stable.
func ticketSpan(list string) (time.Time, time.Time, bool) {
	const layout = "01/02/06 15:04:05"
	for _, line := range strings.Split(list, "\n") {
		if !strings.Contains(line, "krbtgt/") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		start, err := time.Parse(layout, f[0]+" "+f[1])
		if err != nil {
			continue
		}
		end, err := time.Parse(layout, f[2]+" "+f[3])
		if err != nil {
			continue
		}
		return start, end, true
	}
	return time.Time{}, time.Time{}, false
}
