package golden

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStockKinitReadsAKeytabWeWrote is the anchor for the keytab
// format, and it is a better one than it looks.
//
// There is no published reference encoding for a keytab -- it is not
// ASN.1 and upstream's test programs emit none -- so the only way to
// know the bytes are right is to have a Kerberos library read them.
// This writes one with `kdiamond ktadd`, drops it into the oracle,
// and has the oracle's own unmodified kinit authenticate from it
// against the Go KDC.
//
// What that proves end to end: a random key was generated, sealed
// under the master key, stored, read back, written in MIT's format,
// parsed by MIT's code, and used in an AS exchange this KDC answered.
// Any one of those going wrong fails here and nowhere else.
func TestStockKinitReadsAKeytabWeWrote(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "keytab", true)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_keytab")
	svc := strings.Join(ServiceName, "/")

	kt := putKeytab(t, ctx, o, bin, url, "keytab", svc)
	out, err := o.ExecEnv(ctx, env, "", "kinit", "-k",
		"-t", kt, svc+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -k failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)
	assertTicket(t, ctx, o, env, svc)
}

// ktadd re-keys by default, and that is load-bearing rather than
// incidental: a keytab is a copy of a secret, so handing one out
// without changing the key leaves every previous copy working. kadmin
// does the same.
//
// The pair of assertions is what says so. After a plain ktadd the
// service's old password no longer works, and after -norandkey it
// still does -- which is also the whole difference between the `e`
// privilege and the rest, and why upstream leaves `e` out of the
// letters that mean "everything" (auth_acl.c:49-56).
func TestKtaddRekeysUnlessToldNotTo(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "ktnorand", false)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_ktnorand")
	svc := strings.Join(ServiceName, "/")

	// Extracting without re-keying leaves the password working.
	putKeytab(t, ctx, o, bin, url, "ktnorand", svc,
		"-norandkey")
	assertServicePassword(t, ctx, o, env, svc, true)

	// And then a plain ktadd replaces the key, so it does not.
	putKeytab(t, ctx, o, bin, url, "ktnorand2", svc)
	assertServicePassword(t, ctx, o, env, svc, false)
}

// putKeytab runs ktadd on the host and copies the result into the
// container, returning the path there.
//
// The file has to cross because kinit reads it with its own library
// in its own filesystem -- which is the point of the test, and the
// reason a unit test cannot stand in for it.
func putKeytab(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	bin, url, tag, princ string,
	extra ...string,
) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "service.keytab")
	args := append([]string{"ktadd", "-k", host}, extra...)
	mustRun(t, bin, url, append(args, princ)...)

	data, err := os.ReadFile(host)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0x05 || data[1] != 0x02 {
		t.Fatalf("not a version 2 keytab: % x",
			data[:min(8, len(data))])
	}
	path := "/realm/" + tag + ".keytab"
	if err := o.WriteFile(ctx, path, string(data)); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertServicePassword says whether the service's original password
// still gets a ticket, which is how a re-key shows from the outside.
func assertServicePassword(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	svc string,
	want bool,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, ServicePassword+"\n",
		"kinit", svc+"@"+Realm)
	if want && err != nil {
		t.Errorf("the password stopped working: %v\n%s",
			err, out)
	}
	if !want && err == nil {
		t.Errorf("the password still works after a "+
			"re-key:\n%s", out)
	}
}
