package golden

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// shared is one C KDC for the whole package.
//
// Starting a container per test would dominate the run time, and
// sharing one is safe: the KDC never writes to its database during an
// exchange, so no test can disturb another's realm. Tests must not be
// marked parallel, because they share the container's credential
// cache.
var shared *Oracle

func TestMain(m *testing.M) {
	if !imageExists() {
		// Skipping rather than failing keeps `make test'
		// green on a machine that has not run `make
		// golden-build', which is a long Kerberos 5 compile.
		os.Exit(m.Run())
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), 2*time.Minute)
	o, err := startOracle(ctx)
	cancel()
	if err != nil {
		os.Stderr.WriteString(
			"starting the oracle: " + err.Error() + "\n")
		os.Exit(1)
	}
	shared = o
	code := m.Run()
	shared = nil
	o.stop()
	os.Exit(code)
}

func imageExists() bool {
	err := exec.Command(
		"podman", "image", "exists", OracleImage).Run()
	return err == nil
}

// oracle returns the shared C KDC, skipping the test when the image
// has not been built.
func oracle(t *testing.T) *Oracle {
	t.Helper()
	if !imageExists() {
		t.Skipf("run 'make golden-build' to build %s",
			OracleImage)
	}
	if shared == nil {
		ctx, cancel := context.WithTimeout(
			context.Background(), 2*time.Minute)
		defer cancel()
		o, err := startOracle(ctx)
		if err != nil {
			t.Fatalf("starting the oracle: %v", err)
		}
		t.Cleanup(o.stop)
		return o
	}
	return shared
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The C KDC answers a declared length it cannot honour with a
// KRB-ERROR. This is the cheapest proof that the oracle is alive, is
// speaking Kerberos over TCP, and has its realm -- and it needs no
// encoder of our own, which is the point: it can run before
// internal/wire exists.
func TestOracleAnswersMalformedRequest(t *testing.T) {
	o := oracle(t)

	reply, err := o.SendFramed(testContext(t), tooLongFrame)
	if err != nil {
		t.Fatalf("SendFramed: %v", err)
	}
	if len(reply) == 0 {
		t.Fatal("empty reply")
	}
	if reply[0] != tagKrbError {
		t.Errorf("reply starts %#02x, want %#02x (KRB-ERROR)",
			reply[0], tagKrbError)
	}
}

// The principal without +requires_preauth must authenticate, and must
// do it in one round trip with no padata. Both halves matter: the
// second is what makes this the most deterministic exchange available
// to compare against, and it would break silently if the fixture ever
// gained a default preauth requirement.
func TestOracleKinitWithoutPreauth(t *testing.T) {
	o := oracle(t)
	ctx := testContext(t)

	out, err := o.KinitTraced(ctx, UserName, UserPassword)
	if err != nil {
		t.Fatalf("kinit %s: %v\n%s", UserName, err, out)
	}
	if !strings.Contains(out, "Sending unauthenticated request") {
		t.Errorf("no unauthenticated request in the trace;"+
			" has %s gained a preauth requirement?\n%s",
			UserName, out)
	}
	const viaPreauth = "Preauthenticating using KDC method"
	if strings.Contains(out, viaPreauth) {
		t.Errorf("%s pre-authenticated, and should not\n%s",
			UserName, out)
	}
}

// The transport must be TCP, not UDP. udp_preference_limit alone does
// not guarantee it -- both are tried if the first fails -- so the
// realm also disables the KDC's UDP listener, and this is what proves
// the combination worked.
func TestOracleUsesTCP(t *testing.T) {
	o := oracle(t)
	ctx := testContext(t)

	out, err := o.KinitTraced(ctx, UserName, UserPassword)
	if err != nil {
		t.Fatalf("kinit: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Sending TCP request") {
		t.Errorf("no TCP request in the trace\n%s", out)
	}
	if strings.Contains(out, "Sending initial UDP request") {
		t.Errorf("the client used UDP\n%s", out)
	}
}

// The principal that does require pre-authentication must be refused
// once and then succeed, which is the PA-ENC-TIMESTAMP path.
func TestOracleKinitWithPreauth(t *testing.T) {
	o := oracle(t)
	ctx := testContext(t)

	out, err := o.KinitTraced(ctx, PreauthName, UserPassword)
	if err != nil {
		t.Fatalf("kinit %s: %v\n%s", PreauthName, err, out)
	}
	// The KDC's refusal, in the client's own words. Asserting the
	// error code's name would not work: the trace prints the
	// message, not the macro.
	const refused = "Additional pre-authentication required"
	if !strings.Contains(out, refused) {
		t.Errorf("%s was not asked to pre-authenticate\n%s",
			PreauthName, out)
	}
	// And the mechanism, not just the refusal: the second request
	// must actually carry an encrypted timestamp.
	if !strings.Contains(out, "PA-ENC-TIMESTAMP") {
		t.Errorf("no PA-ENC-TIMESTAMP in the exchange\n%s",
			out)
	}
}

// A ticket is only useful if it is a TGT for the realm's own krbtgt,
// so klist is checked rather than trusting kinit's exit status.
func TestOracleKlistShowsATGT(t *testing.T) {
	o := oracle(t)
	ctx := testContext(t)

	if out, err := o.Kinit(
		ctx, UserName, UserPassword); err != nil {
		t.Fatalf("kinit: %v\n%s", err, out)
	}
	out, err := o.Exec(ctx, "klist")
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, out)
	}
	want := []string{
		"Default principal: " + UserName + "@" + Realm,
		"krbtgt/" + Realm + "@" + Realm,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("klist lacks %q\n%s", w, out)
		}
	}
}

// A wrong password must fail, and must fail *because the password was
// wrong*.
//
// Asserting only a non-zero exit is not enough, and this test proved
// it: an earlier version passed while the client could not reach the
// KDC at all, reporting "Cannot find KDC for realm". A negative test
// satisfied by any failure is satisfied by the harness being broken,
// which is the one circumstance it most needs to catch.
func TestOracleRejectsAWrongPassword(t *testing.T) {
	o := oracle(t)

	out, err := o.Kinit(
		testContext(t), UserName, "not-the-password")
	if err == nil {
		t.Fatalf("kinit accepted a wrong password\n%s", out)
	}
	// The principal needs no pre-authentication, so the KDC
	// answers with an AS-REP regardless and the client discovers
	// the bad password when its reply key will not decrypt the
	// enc-part.
	if !strings.Contains(out, "Password incorrect") {
		t.Errorf("failed, but not on the password\n%s", out)
	}
}
