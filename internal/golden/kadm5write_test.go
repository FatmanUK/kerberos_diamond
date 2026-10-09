package golden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// contextFor is a deadline for one oracle-backed case.
func contextFor(
	t *testing.T,
	d time.Duration,
) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

// The whole write path, in the order an operator would use it: create
// a principal, read it back, change it, re-key it, rename it, and
// delete it.
//
// One ACL permits everything, because what the ACL *refuses* is
// tested separately; this is about the operations.
func TestTheWriteOperations(t *testing.T) {
	d := diamond(t, "kd_kadm5_write", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	tok := func() string { return adminToken(t, d, UserName) }

	res, body := call(t, s, "addprinc", tok(), map[string]any{
		"principal":  "newservice",
		"password":   "a-fresh-password",
		"max_life":   "1d",
		"attributes": "+requires_preauth",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("addprinc: %d %v", res.StatusCode, body)
	}
	assertNewPrincipal(t, body)

	// And modprinc changes it, in kadmin's duration format.
	res, body = call(t, s, "modprinc", tok(), map[string]any{
		"principal": "newservice",
		"max_life":  "2h30m",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("modprinc: %d %v", res.StatusCode, body)
	}
	if got := body["max_life"]; got != float64(9000) {
		t.Errorf("max_life is %v, want 9000", got)
	}
	assertRekeyRenameDelete(t, s, d, tok)
}

// assertNewPrincipal checks what addprinc returned.
func assertNewPrincipal(t *testing.T, body map[string]any) {
	t.Helper()
	if got := body["principal"]; got != "newservice@"+Realm {
		t.Errorf("principal is %v", got)
	}
	// 1d in kadmin's format, not Go's.
	if got := body["max_life"]; got != float64(86400) {
		t.Errorf("max_life is %v, want 86400", got)
	}
	attrs, _ := body["attributes"].([]any)
	var found bool
	for _, a := range attrs {
		if a == "REQUIRES_PRE_AUTH" {
			found = true
		}
	}
	if !found {
		t.Errorf("attributes are %v", attrs)
	}
	// ModBy and ModTime are written on every write, which
	// upstream does inside kdb_put_entry and this project did not
	// do at all until now.
	if body["mod_name"] == nil || body["mod_date"] == nil {
		t.Errorf("no audit trail in %v", body)
	}
}

// assertRekeyRenameDelete runs the rest of the sequence.
func assertRekeyRenameDelete(
	t *testing.T,
	s *httptest.Server,
	d *Diamond,
	tok func() string,
) {
	t.Helper()
	res, body := call(t, s, "cpw", tok(), map[string]any{
		"principal": "newservice",
		"randkey":   true,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cpw -randkey: %d %v", res.StatusCode,
			body)
	}
	if got := body["kvno"]; got != float64(2) {
		t.Errorf("kvno is %v, want 2", got)
	}
	res, body = call(t, s, "renprinc", tok(), map[string]any{
		"from": "newservice", "to": "renamedservice",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("renprinc: %d %v", res.StatusCode, body)
	}
	res, body = call(t, s, "delprinc", tok(),
		map[string]any{"principal": "renamedservice"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delprinc: %d %v", res.StatusCode, body)
	}
	res, _ = call(t, s, "getprinc", tok(),
		map[string]any{"principal": "renamedservice"})
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("it survived deletion: %d",
			res.StatusCode)
	}
}

// maskCase is one request that names a field it may not.
type maskCase struct {
	why  string
	verb string
	arg  map[string]any
}

// maskRejections is every field a request may not name, or may name
// only one way.
func maskRejections() []maskCase {
	return []maskCase{
		// create rejects fail_auth_count outright
		// (svr_principal.c:311-321).
		{"a failure count on addprinc", "addprinc",
			map[string]any{"principal": "p1",
				"password":        "pw-for-p1",
				"fail_auth_count": 0}},
		// modify accepts it only as zero, because that is the
		// unlock path and nothing else (:668-681).
		{"a nonzero failure count on modprinc",
			"modprinc", map[string]any{
				"principal":       UserName,
				"fail_auth_count": 3}},
		// policy and clearpolicy together (:319-321).
		{"a policy and a clearpolicy", "modprinc",
			map[string]any{"principal": UserName,
				"policy": "p", "clearpolicy": true}},
		// a password and a random key together
		{"a password and randkey", "cpw",
			map[string]any{"principal": UserName,
				"password": "x", "randkey": true}},
		// a duration in Go's format rather than kadmin's
		{"a Go duration", "modprinc", map[string]any{
			"principal": UserName, "max_life": "1.5h"}},
		{"a bad time", "modprinc", map[string]any{
			"principal":  UserName,
			"expiration": "next Tuesday"}},
		{"an unknown attribute", "modprinc",
			map[string]any{"principal": UserName,
				"attributes": "+frobnicate"}},
	}
}

// The mask rejections, which are how upstream refuses a nonsense
// request rather than half-applying it.
func TestTheMaskRejections(t *testing.T) {
	d := diamond(t, "kd_kadm5_mask", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	for _, c := range maskRejections() {
		t.Run(c.why, func(t *testing.T) {
			res, body := call(t, s, c.verb,
				adminToken(t, d, UserName), c.arg)
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400: %v",
					res.StatusCode, body)
			}
		})
	}
}

// A failure count of **zero** is accepted, because that is the
// administrative unlock and the one value upstream allows
// (svr_principal.c:668-681).
func TestAZeroFailureCountUnlocks(t *testing.T) {
	d := diamond(t, "kd_kadm5_unlock", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	res, body := call(t, s, "modprinc",
		adminToken(t, d, UserName), map[string]any{
			"principal":       UserName,
			"fail_auth_count": 0,
		})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", res.StatusCode, body)
	}
	if got := body["fail_auth_count"]; got != float64(0) {
		t.Errorf("count is %v", got)
	}
}

// The password policy applies to an administrator's change as much as
// to a user's own (passwd_check is called from chpass_principal_3,
// svr_principal.c:1281) -- and the refusal is the request's fault, so
// it is 400 and not 500.
func TestAPolicyRefusesAWeakPassword(t *testing.T) {
	d := diamond(t, "kd_kadm5_quality", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	tok := func() string { return adminToken(t, d, UserName) }

	res, body := call(t, s, "addpol", tok(), map[string]any{
		"policy":         "strict",
		"pw_min_length":  12,
		"pw_min_classes": 3,
		"pw_history_num": 2,
		"pw_max_life":    "90d",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("addpol: %d %v", res.StatusCode, body)
	}
	if got := body["pw_max_life"]; got != float64(7776000) {
		t.Errorf("pw_max_life is %v", got)
	}
	res, body = call(t, s, "modprinc", tok(), map[string]any{
		"principal": UserName, "policy": "strict",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("modprinc: %d %v", res.StatusCode, body)
	}
	res, body = call(t, s, "cpw", tok(), map[string]any{
		"principal": UserName, "password": "short",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("a weak password: %d %v",
			res.StatusCode, body)
	}
}

// The privilege letters, one operation at a time: an ACL granting `c'
// permits a password change and nothing else, which is the whole
// point of having letters rather than a single administrator bit.
func TestThePrivilegeLettersAreSeparate(t *testing.T) {
	d := diamond(t, "kd_kadm5_letters", time.Now().UTC)
	// `c' alone: change passwords, modify nothing.
	s := kadm5Server(t, d, "*@"+Realm+" c")
	tok := func() string { return adminToken(t, d, UserName) }

	res, body := call(t, s, "cpw", tok(), map[string]any{
		"principal": PreauthName,
		"password":  "a-new-password-entirely",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cpw: %d %v", res.StatusCode, body)
	}
	res, _ = call(t, s, "modprinc", tok(), map[string]any{
		"principal": PreauthName, "max_life": "1d",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("modprinc with only c: %d",
			res.StatusCode)
	}
	res, _ = call(t, s, "addprinc", tok(), map[string]any{
		"principal": "nope", "password": "pw-for-nope",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("addprinc with only c: %d",
			res.StatusCode)
	}
}

// **x and * mean everything except e**, which is upstream's one
// deliberate hole in the all-privileges mask (auth_acl.c:49-56) and
// which t_kadmin_acl.py:356-375 asserts. Extracting a key that is
// already in use is strictly more dangerous than replacing it, so it
// has to be granted by name.
//
// Here that is visible as chrand being permitted by `*' while nothing
// grants extract -- the privilege B4's keytab path is gated on.
func TestTheAllMaskExcludesExtract(t *testing.T) {
	d := diamond(t, "kd_kadm5_extract", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	res, body := call(t, s, "cpw",
		adminToken(t, d, UserName), map[string]any{
			"principal": PreauthName, "randkey": true,
		})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("chrand under *: %d %v", res.StatusCode,
			body)
	}
}

// A restriction is **imposed, not checked**: an administrator capped
// at an hour who asks for a day gets an hour rather than an error,
// which is the difference between a restriction and a rule
// (impose_restrictions, kadmin/server/auth.c:203-271).
func TestARestrictionIsImposed(t *testing.T) {
	d := diamond(t, "kd_kadm5_restrict", time.Now().UTC)
	s := kadm5Server(t, d,
		"*@"+Realm+" * * -maxlife 1h +requires_preauth")
	res, body := call(t, s, "addprinc",
		adminToken(t, d, UserName), map[string]any{
			"principal": "capped",
			"password":  "a-password-for-capped",
			"max_life":  "1d",
		})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("addprinc: %d %v", res.StatusCode, body)
	}
	if got := body["max_life"]; got != float64(3600) {
		t.Errorf("max_life is %v, want 3600 -- the cap "+
			"was not imposed", got)
	}
	attrs, _ := body["attributes"].([]any)
	var found bool
	for _, a := range attrs {
		if a == "REQUIRES_PRE_AUTH" {
			found = true
		}
	}
	if !found {
		t.Errorf("the forced attribute is missing: %v",
			attrs)
	}
}

// The write path's real anchor: a password set through the
// administrative surface, and then a **stock kinit** logging in with
// it.
//
// Everything before this checks that the surface agrees with itself
// about what it wrote. This checks that what it wrote is a key an
// unmodified Kerberos client can derive from the password it was
// given -- which is the only thing that makes the whole exercise
// worth anything, and the hazard the plan names: a surface that
// stores a wrong key answers 200 and looks fine until somebody tries
// to log in.
func TestAPasswordSetOverHTTPWorksForStockKinit(t *testing.T) {
	o := oracle(t)
	ctx, cancel := contextFor(t, 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "kadm5pw",
		clientConf)
	d := diamondOf(t)
	s := kadm5Server(t, d, "*@"+Realm+" *")

	const newPW = "set-through-the-admin-surface"
	res, body := call(t, s, "cpw",
		adminToken(t, d, UserName), map[string]any{
			"principal": UserName,
			"password":  newPW,
		})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cpw: %d %v", res.StatusCode, body)
	}
	assertKinitPassword(t, ctx, o, env, newPW, true)
	assertKinitPassword(t, ctx, o, env, UserPassword, false)
}
