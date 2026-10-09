package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// enterpriseConf points the *default* realm at the Go KDC and leaves
// the foreign realm with the C KDC, which is the topology a client
// referral needs: the client asks here, is told to ask there, and has
// to already know where there is.
func enterpriseConf(oracleAddr string) func(int) string {
	return func(port int) string {
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
	%[4]s = {
		kdc = %[5]s
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, Realm, HostAlias, port, ForeignRealm, oracleAddr)
	}
}

// TestStockKinitFollowsAnEnterpriseReferral is D3's anchor, and the
// strongest kind in upstream's own suite: a client trace where every
// line is the client's own report of what it did.
//
// `kinit -E remote@FOREIGN.TEST' with a default realm of
// KDIAMOND.TEST sends an AS-REQ **to this KDC** whose body realm is
// KDIAMOND.TEST and whose client name is a user principal name in one
// component. The Go KDC splits it, sees a realm that is not its own,
// and answers KDC_ERR_WRONG_REALM carrying a cname in FOREIGN.TEST.
// The client then rewrites its request's client realm from the error
// and starts again at the C KDC.
//
// Three things have to be right together or the client ignores the
// error entirely (is_referral, get_in_tkt.c:1659-1667): the code, the
// presence of a cname, and **its realm differing from the client's
// own**. Nothing but a real client checks all three.
//
// **The second hop then fails, and that is the finding rather than a
// defect here.** A stock krb5kdc over db2 cannot resolve an
// enterprise name at all: the KDC hands the whole name to the
// database with KRB5_KDB_FLAG_REFERRAL_OK set (do_as_req.c:573-578),
// and of the modules upstream ships **only the test one reads that
// flag** (kdb_test.c:411-419 is its sole reader). So the C KDC
// answers "Client not found" for `remote\@FOREIGN.TEST@FOREIGN.TEST',
// which is upstream's real behaviour and is asserted here so that the
// limitation is recorded rather than rediscovered. The referral --
// this KDC's half -- is complete; what no db2 realm can do is be
// referred *to*.
func TestStockKinitFollowsAnEnterpriseReferral(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "enterprise",
		enterpriseConf("127.0.0.1:"+oraclePortInside()))
	env = append(env, "KRB5_TRACE=/dev/stderr")

	out, _ := o.ExecEnv(ctx, env, RemotePassword+"\n",
		"kinit", "-E", RemoteName+"@"+ForeignRealm)
	assertFollowedClientReferral(t, out)
	assertTheCKDCCannotResolveAUPN(t, out)
}

// assertTheCKDCCannotResolveAUPN pins upstream's db2 limitation, so
// that the test says what happened rather than merely passing.
func assertTheCKDCCannotResolveAUPN(t *testing.T, trace string) {
	t.Helper()
	if !strings.Contains(trace, "Client not found") {
		t.Errorf("expected the C KDC to refuse the UPN:"+
			"\n%s", trace)
	}
	// And the refusal came from the realm it was referred to,
	// which is what shows the referral was acted on rather than
	// merely received.
	if !strings.Contains(trace,
		"Sending request (199 bytes) to "+ForeignRealm) &&
		!strings.Contains(trace,
			"to "+ForeignRealm) {
		t.Errorf("the second request did not go to %s:\n%s",
			ForeignRealm, trace)
	}
}

// And the local half completes: an enterprise name naming **this**
// realm logs in, which is the case a Windows workstation actually
// sends and the reason the name type exists.
func TestStockKinitWithALocalEnterpriseName(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "upnlocal",
		clientConf)
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-E", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -E failed: %v\n%s", err, out)
	}
	// The ticket names the ordinary principal, because the
	// enterprise name was rewritten before anything looked it up
	// -- and the client accepted that without being told to
	// canonicalise, which it does because an enterprise name
	// implies canonicalisation (get_in_tkt.c:1688-1690).
	assertTicketIn(t, ctx, o, env, UserName, Realm)
}

// oraclePortInside is the port the C KDC listens on *inside* its own
// container, which is where the client runs.
func oraclePortInside() string {
	return fmt.Sprint(OraclePort)
}

// assertFollowedClientReferral reads the client's trace.
//
// "Following referral" is TRACE_INIT_CREDS_REFERRAL (k5-trace.h:256),
// emitted from the one branch that treats an error as a client realm
// referral -- so the line appears only if the client believed the
// error, and it names the realm it believed.
func assertFollowedClientReferral(t *testing.T, trace string) {
	t.Helper()
	if !strings.Contains(trace, "Following referral") {
		t.Errorf("the client did not follow a referral:"+
			"\n%s", trace)
	}
	if !strings.Contains(trace, ForeignRealm) {
		t.Errorf("the trace never mentions %s:\n%s",
			ForeignRealm, trace)
	}
	// And the first request really did go to the Go KDC, which is
	// what makes this a referral *from here*.
	if !strings.Contains(trace, HostAlias) {
		t.Errorf("the client never asked this KDC:\n%s",
			trace)
	}
}

// assertTicketIn checks klist shows a ticket for a principal in a
// named realm.
func assertTicketIn(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	name, realm string,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, out)
	}
	want := name + "@" + realm
	if !strings.Contains(out, want) {
		t.Errorf("klist does not show %s:\n%s", want, out)
	}
	if !strings.Contains(out, "krbtgt/"+realm) {
		t.Errorf("klist shows no TGT for %s:\n%s", realm,
			out)
	}
}
