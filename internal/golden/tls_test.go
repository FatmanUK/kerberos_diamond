package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// directConf points a client straight at the Go KDC's own HTTPS
// listener, with no kdiamond-proxy anywhere.
//
// Two lines do it, and both are ordinary Kerberos 5 configuration
// with nothing special about this project in them:
//
//   - `kdc = https://host:port/path', which parse_uri_if_https
//     recognises (locate_kdc.c:216-231) and which is the whole of
//     the client-side cost of MS-KKDCP;
//   - `http_anchors = FILE:...', read per realm
//     (setup_tls, sendto_kdc.c:1238-1243) and loaded by the TLS
//     module (openssl.c:391-409).
//
// udp_preference_limit is gone, not forgotten: there is no UDP
// transport for an https:// entry to fall back to, so the setting has
// nothing to apply to.
func directConf(port int, anchor string) string {
	return fmt.Sprintf(`[libdefaults]
	default_realm = %[1]s
	dns_lookup_kdc = false
	dns_lookup_realm = false
	dns_canonicalize_hostname = false
	rdns = false
	qualify_shortname = ""
	noaddresses = true

[realms]
	%[1]s = {
		kdc = https://%[2]s:%[3]d/%[4]s
		http_anchors = FILE:%[5]s
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, Realm, HostAlias, port, ProxyPath, anchor)
}

// TestStockKinitNegotiatesTLSItself is Phase C, and it proves the one
// thing section 6 previously had to admit it could not: that an
// unmodified Kerberos 5 client negotiates the TLS to this KDC itself.
//
// Every other end-to-end case goes through kdiamond-proxy, which is
// the right topology for a client with no TLS module -- but it means
// the client-to-shim hop is cleartext and the TLS leg is the shim's
// work. Here there is no shim at all: the client dials the KDC's own
// HTTPS listener, verifies the certificate against an anchor it was
// given, and runs an AS exchange over it.
//
// The client comes from a second, clearly-labelled image built
// --with-tls-impl=openssl. The ordinary oracle stays OpenSSL-free and
// every differential case keeps running against it, so the no-OpenSSL
// rule still holds of everything this project ships and of every
// other test. deploy/golden/Containerfile.krb5-tls has the reasoning.
func TestStockKinitNegotiatesTLSItself(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	c, err := StartTLSClient(ctx)
	if err != nil {
		t.Skipf("no TLS-capable client: %v", err)
	}
	t.Cleanup(c.Close)

	d := diamond(t, "kd_golden_tls", time.Now().UTC)
	direct, err := ServeDirect(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(direct.Close)

	env := configureTLSClient(t, ctx, c, direct)
	out, err := c.Exec(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	assertTLSWasTheClients(t, out)
	assertDirectTicket(t, ctx, c, env)
}

// configureTLSClient writes the configuration and the anchor into the
// container and returns the environment pointing at them.
func configureTLSClient(
	t *testing.T,
	ctx context.Context,
	c *TLSClient,
	direct *Direct,
) []string {
	t.Helper()
	const (
		confPath   = "/realm/krb5.conf"
		anchorPath = "/realm/kdc-anchor.pem"
		ccache     = "/realm/ccache"
	)
	if err := c.WriteFile(
		ctx, anchorPath, direct.CertPEM); err != nil {
		t.Fatal(err)
	}
	conf := directConf(direct.Port, anchorPath)
	if err := c.WriteFile(ctx, confPath, conf); err != nil {
		t.Fatal(err)
	}
	return []string{
		"KRB5_CONFIG=" + confPath,
		"KRB5CCNAME=" + ccache,
		"KRB5_TRACE=/dev/stderr",
	}
}

// assertTLSWasTheClients reads the client's own trace to confirm who
// negotiated the TLS.
//
// This is the assertion that makes the test worth having rather than
// a second way of saying kinit works. "Sending HTTPS request to" is
// TRACE_SENDTO_KDC_HTTPS_SEND (k5-trace.h:400-401), emitted from
// service_https_write *after* setup_tls has returned true -- so the
// line only appears when the client's own TLS module came up and
// completed a handshake. It is the client reporting what it did
// rather than this test inferring it from a ticket appearing.
func assertTLSWasTheClients(t *testing.T, trace string) {
	t.Helper()
	if !strings.Contains(trace,
		"Sending HTTPS request to") {
		t.Errorf("the client sent no HTTPS request:\n%s",
			trace)
	}
	// And no TLS error on the way, which is the other thing the
	// module traces (:394-398).
	for _, bad := range []string{
		"HTTPS error connecting to",
		"HTTPS error sending to",
		"HTTPS error receiving from",
		"HTTPS error:",
	} {
		if strings.Contains(trace, bad) {
			t.Errorf("the trace reports %q:\n%s", bad,
				trace)
		}
	}
	// With --with-tls-impl=no the module loads and does nothing,
	// and the client reports a generic "cannot contact any KDC"
	// with no trace of a TLS error at all (notls.c:40-51 and
	// sendto_kdc.c:1266-1269). Asserting the absence of that
	// message is what distinguishes this image from the ordinary
	// oracle.
	if strings.Contains(trace, "Cannot contact any KDC") {
		t.Errorf("the client could not reach the KDC -- is "+
			"this image really built with "+
			"--with-tls-impl=openssl?\n%s", trace)
	}
}

// assertDirectTicket checks klist shows a TGT, so that the exchange
// is known to have succeeded and not merely to have happened.
func assertDirectTicket(
	t *testing.T,
	ctx context.Context,
	c *TLSClient,
	env []string,
) {
	t.Helper()
	out, err := c.Exec(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, out)
	}
	want := UserName + "@" + Realm
	if !strings.Contains(out, want) {
		t.Errorf("klist does not show %s:\n%s", want, out)
	}
	if !strings.Contains(out, "krbtgt/"+Realm) {
		t.Errorf("klist shows no TGT:\n%s", out)
	}
}

// TestAClientWithNoTLSModuleFailsSilently is the control for the case
// above, and it is the more interesting half.
//
// The *ordinary* oracle's client -- built --with-tls-impl=no -- is
// given exactly the same configuration and cannot use it. What it
// reports is the point: not a missing TLS module, not a handshake
// failure, not a plugin that would not load, but
//
//	Terminating TCP connection to https <addr>
//	kinit: Cannot contact any KDC for realm '...'
//
// and the string "TLS" appears nowhere in the trace at all.
//
// The cause is that --with-tls-impl=no still produces a module that
// **loads successfully**: notls.c:40-51 compiles the init symbol and
// leaves the vtable nulled, so no load error is traced; setup == NULL
// then makes setup_tls return false and service_https_write kills the
// connection (sendto_kdc.c:1266-1269) without tracing anything
// either.
//
// Two reasons this is worth a test of its own. It proves the case
// above is not passing for some unrelated reason -- the only
// difference between the two is the TLS module. And it records an
// operational fact an administrator would otherwise have to discover:
// a client that cannot do HTTPS looks exactly like a KDC that is not
// there, and the only place the difference is visible is the
// *server's* log, which sees the connection opened and closed with no
// handshake.
func TestAClientWithNoTLSModuleFailsSilently(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	d := diamond(t, "kd_golden_notls", time.Now().UTC)
	direct, err := ServeDirect(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(direct.Close)

	env := configureOracleClient(t, ctx, o, direct)
	out, _ := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm)
	assertFailedWithoutSayingWhy(t, out)
}

// configureOracleClient writes the same direct configuration into the
// ordinary oracle's container.
func configureOracleClient(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	direct *Direct,
) []string {
	t.Helper()
	const (
		confPath   = "/realm/direct.conf"
		anchorPath = "/realm/direct-anchor.pem"
	)
	if err := o.WriteFile(
		ctx, anchorPath, direct.CertPEM); err != nil {
		t.Fatal(err)
	}
	conf := directConf(direct.Port, anchorPath)
	if err := o.WriteFile(ctx, confPath, conf); err != nil {
		t.Fatal(err)
	}
	return []string{
		"KRB5_CONFIG=" + confPath,
		"KRB5CCNAME=/realm/direct.ccache",
		"KRB5_TRACE=/dev/stderr",
	}
}

// assertFailedWithoutSayingWhy pins the silence.
func assertFailedWithoutSayingWhy(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "Cannot contact any KDC") {
		t.Errorf("expected the generic failure:\n%s", out)
	}
	// The three things a reader would look for, none of which
	// appear.
	for _, absent := range []string{
		"Sending HTTPS request", "HTTPS error", "TLS",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("the trace mentions %q, so this "+
				"client may have a TLS module after "+
				"all:\n%s", absent, out)
		}
	}
	// And it did reach the point of opening a connection, which
	// is what makes the silence misleading rather than merely
	// unhelpful.
	if !strings.Contains(out, "Terminating TCP connection") {
		t.Errorf("no connection was opened at all:\n%s",
			out)
	}
}
