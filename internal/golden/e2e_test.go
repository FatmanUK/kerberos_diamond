package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// clientConf is a krb5.conf pointing a client at the Go KDC's shim
// rather than at the C KDC in the same container.
//
// udp_preference_limit = 1 puts TCP first, and the shim speaks only
// TCP, so UDP would fail and be retried rather than simply not used
// -- which is why it matters even though there is nothing listening
// on UDP at all.
func clientConf(port int) string {
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
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, Realm, HostAlias, port)
}

// TestStockKinitGetsATGTFromTheGoKDC is the end-to-end check, and the
// only evidence in the project that "behaviour-compatible" means
// anything in practice.
//
// The client is a stock, unpatched kinit built from the kerberos
// submodule. It is pointed at kdiamond-proxy, which forwards each
// message to the Go KDC as MS-KKDCP over TLS. Nothing about the
// client is modified and nothing about the exchange is simulated: if
// it exits zero and klist shows a TGT, an unmodified Kerberos 5
// client interoperates with this KDC.
//
// What it does not prove: the client-to-shim hop is cleartext, so the
// TLS leg is exercised by the shim and not by the client. A client
// built with a TLS module reaches the KDC's HTTPS listener directly;
// until one is available that half is covered only by
// internal/transport's own tests.
func TestStockKinitGetsATGTFromTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "plain", true)
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit against the Go KDC failed: %v\n%s",
			err, out)
	}
	assertWentToTheShim(t, out)
	assertTicket(t, ctx, o, env, UserName)
}

// pointAtDiamond starts a Go KDC behind a shim, writes a krb5.conf
// into the container naming it, and returns the environment a client
// needs.
//
// Each case gets a credential cache of its own, so a ticket left
// behind by another test cannot be what makes this one pass.
func pointAtDiamond(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	tag string,
	trace bool,
) []string {
	t.Helper()
	env := pointAtDiamondWith(t, ctx, o, tag, clientConf)
	if trace {
		env = append(env, "KRB5_TRACE=/dev/stderr")
	}
	return env
}

// pointAtDiamondWith is pointAtDiamond with the configuration left to
// the caller, which the cross-realm case needs: its client's own
// realm is served by the C KDC and only the service's realm goes
// through the shim.
func pointAtDiamondWith(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	tag string,
	conf func(port int) string,
) []string {
	t.Helper()
	d := diamond(t, "kd_golden_e2e_"+tag, time.Now().UTC)
	lastDiamond = d
	s, err := Serve(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(s.Close)

	path := "/realm/diamond-" + tag + ".conf"
	if err := o.WriteFile(
		ctx, path, conf(s.ShimPort)); err != nil {
		t.Fatal(err)
	}
	return []string{
		"KRB5_CONFIG=" + path,
		"KRB5CCNAME=/realm/diamond-" + tag + ".ccache",
	}
}

// lastDiamond is the Go KDC pointAtDiamond most recently started.
//
// A test that needs to reach past the KDC and adjust a principal
// directly has no other handle on it: pointAtDiamond returns the
// client's environment, not the server. Tests here never run in
// parallel, so one slot is enough.
var lastDiamond *Diamond

// diamondOf returns that KDC.
func diamondOf(t *testing.T) *Diamond {
	t.Helper()
	if lastDiamond == nil {
		t.Fatal("no Go KDC has been started")
	}
	return lastDiamond
}

// assertTicket checks klist actually shows a TGT for the right
// client.
//
// kinit exiting zero is necessary and not sufficient: the ticket has
// to be in the cache, for the right service, named for the right
// principal. LC_ALL and TZ are pinned in the image, because klist
// formats times through localtime_r with a %c format and would
// otherwise render differently on every host.
func assertTicket(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	client string,
) {
	t.Helper()
	list, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, list)
	}
	want := "krbtgt/" + Realm + "@" + Realm
	if !strings.Contains(list, want) {
		t.Errorf("klist shows no %s:\n%s", want, list)
	}
	if !strings.Contains(list, client+"@"+Realm) {
		t.Errorf("klist names the wrong client:\n%s", list)
	}
}

// assertWentToTheShim checks the client dialled the Go KDC's shim and
// not the C KDC sharing its container.
//
// Without it a stale ticket, or a fallback to 127.0.0.1:8088 where
// the oracle listens, would pass every assertion above while proving
// nothing about this implementation at all.
func assertWentToTheShim(t *testing.T, trace string) {
	t.Helper()
	want := "Resolving hostname " + HostAlias
	if !strings.Contains(trace, want) {
		t.Errorf("the trace does not name the shim:\n%s",
			trace)
	}
	if strings.Contains(trace, "127.0.0.1:8088") {
		t.Errorf("the client reached the C KDC:\n%s", trace)
	}
}

// A principal that requires pre-authentication exercises the
// two-round trip path through the same shim, which is the case a
// single-exchange test would miss entirely.
func TestStockKinitPreauthsAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "pa", true)
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("preauth kinit failed: %v\n%s", err, out)
	}
	// The trace has to show the handshake, not just a success:
	// otherwise a KDC that ignored the requirement would pass.
	if !strings.Contains(out,
		"Additional pre-authentication required") {
		t.Errorf("no preauth round trip in the trace:\n%s",
			out)
	}
	if !strings.Contains(out, "PA-ENC-TIMESTAMP") {
		t.Errorf("the client did not send a timestamp:\n%s",
			out)
	}
	assertWentToTheShim(t, out)
	assertTicket(t, ctx, o, env, PreauthName)
}

// A wrong password must be refused. Without this, a KDC that handed
// out tickets to anyone would pass every test above.
func TestStockKinitRejectsAWrongPassword(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "bad", false)
	out, err := o.ExecEnv(ctx, env, "wrongpassword\n",
		"kinit", PreauthName+"@"+Realm)
	if err == nil {
		t.Fatalf("kinit accepted a wrong password:\n%s", out)
	}
	// The *reason* matters. A non-zero exit on its own would also
	// be produced by a client that could not reach the KDC at
	// all, which is exactly the hazard this harness guards
	// against.
	if !strings.Contains(out, "Password incorrect") &&
		!strings.Contains(out, "Preauthentication failed") {
		t.Errorf("refused for the wrong reason:\n%s", out)
	}
}
