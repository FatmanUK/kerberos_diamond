package acl

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const realm = "KDIAMOND.TEST"

func q(name string) string { return name + "@" + realm }

// x and * mean everything *except* extract, which is upstream's
// deliberate omission from its all-privileges mask (:49-56) and which
// it tests separately (tests/t_kadmin_acl.py:356-375).
//
// The reason is in the asymmetry: every other privilege at most
// *replaces* a key, and extract hands out a copy of one already in
// use.
func TestTheAllMaskExcludesExtract(t *testing.T) {
	a, err := Parse(q("admin") + " *")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []Op{
		AddPrinc, DelPrinc, ModPrinc, CPW, GetPrinc,
		ListPrincs, SetKey, IProp,
	} {
		if _, ok := a.Check(op, q("admin"),
			q("someone")); !ok {
			t.Errorf("* refused operation %d", op)
		}
	}
	if _, ok := a.Check(Extract, q("admin"),
		q("someone")); ok {
		t.Error("* allowed extract")
	}
	// And e on its own allows it.
	b, err := Parse(q("admin") + " e")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Check(Extract, q("admin"),
		q("someone")); !ok {
		t.Error("e refused extract")
	}
}

// An upper-case letter denies rather than grants, so the order of
// letters within an opstring matters (:270-284).
func TestUpperCaseDenies(t *testing.T) {
	a, err := Parse(q("admin") + " xD")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(AddPrinc, q("admin"),
		q("x")); !ok {
		t.Error("xD refused add")
	}
	if _, ok := a.Check(DelPrinc, q("admin"),
		q("x")); ok {
		t.Error("xD allowed delete")
	}
}

// The first matching entry decides, and only then is the operation
// tested -- so a later, more permissive entry is never reached
// (:496-543). An access-control list is not a union, and this is the
// rule most likely to surprise whoever writes one.
func TestTheFirstMatchWinsEvenWhenItRefuses(t *testing.T) {
	a, err := Parse(q("admin") + " i;" + q("admin") + " x")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(GetPrinc, q("admin"),
		q("x")); !ok {
		t.Error("the first entry refused its own privilege")
	}
	if _, ok := a.Check(AddPrinc, q("admin"),
		q("x")); ok {
		t.Error("the second entry was reached")
	}
}

// Wildcards match a whole component and nothing less, so component
// counts have to be equal: a pattern is not a prefix.
func TestWildcardsMatchWholeComponents(t *testing.T) {
	a, err := Parse("*/admin@" + realm + " x")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		client string
		want   bool
	}{
		{q("alice/admin"), true},
		{q("bob/admin"), true},
		{q("alice"), false},
		{q("alice/admin/extra"), false},
		{"alice/admin@OTHER.TEST", false},
	} {
		_, ok := a.Check(AddPrinc, c.client, q("x"))
		if ok != c.want {
			t.Errorf("%s: got %v, want %v",
				c.client, ok, c.want)
		}
	}
}

// Backreferences let a target depend on what the client pattern
// captured, and upstream's own example is the test: */* d *2/*1 lets
// a/b delete b/a (tests/t_kadmin_acl.py:85,333-334).
func TestBackreferencesInTheTarget(t *testing.T) {
	a, err := Parse("*/*@" + realm + " d *2/*1@" + realm)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(DelPrinc, q("a/b"), q("b/a")); !ok {
		t.Error("a/b could not delete b/a")
	}
	if _, ok := a.Check(DelPrinc, q("a/b"), q("a/b")); ok {
		t.Error("a/b could delete itself")
	}
	// A reference to a capture that was not made matches nothing
	// rather than everything.
	b, err := Parse(q("admin") + " d *1@" + realm)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Check(DelPrinc, q("admin"), q("x")); ok {
		t.Error("an unmade backreference matched")
	}
}

// A target of * or none means any, which is how an unrestricted
// administrator is written.
func TestAnAbsentTargetMeansAny(t *testing.T) {
	for _, spec := range []string{
		q("admin") + " x",
		q("admin") + " x *",
	} {
		a, err := Parse(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Check(DelPrinc, q("admin"),
			q("anybody")); !ok {
			t.Errorf("%q refused a target", spec)
		}
	}
}

// Operations with no target at all -- listing principals, the policy
// operations -- are checked against the client alone, which upstream
// does by passing a NULL target (:671-713).
func TestTargetlessOperations(t *testing.T) {
	a, err := Parse(q("admin") + " l")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Check(ListPrincs, q("admin"), ""); !ok {
		t.Error("listprincs was refused")
	}
	// But an entry with a target does not answer a targetless
	// operation, because there is nothing for the target to
	// match.
	b, err := Parse(q("admin") + " l " + q("someone"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Check(ListPrincs, q("admin"), ""); ok {
		t.Error("a targeted entry answered listprincs")
	}
}

// A malformed entry is fatal rather than skipped, which is upstream's
// behaviour: a syntax error anywhere stops kadmind from starting
// (:409-419). An access-control list that silently dropped a line
// would grant or deny something nobody intended.
func TestMalformedEntriesAreRefused(t *testing.T) {
	for _, in := range []string{
		q("admin"),
		q("admin") + " z",
		q("admin") + " x " + q("t") + " -nonsense",
		q("admin") + " x " + q("t") + " -maxlife",
		q("admin") + " x " + q("t") + " -maxlife notatime",
		q("admin") + " x " + q("t") + " -policy",
	} {
		if _, err := Parse(in); !errors.Is(
			err, ErrMalformed) {
			t.Errorf("%q was accepted", in)
		}
	}
}

// Comments and empty entries are skipped, so a transcribed kadm5.acl
// keeps its comments.
func TestCommentsAndBlanksAreSkipped(t *testing.T) {
	a, err := Parse("# a comment;;" + q("admin") + " x;")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 {
		t.Fatalf("%d entries, want 1", len(a))
	}
}

// An empty list permits nothing, which is the right default for a
// surface that provisions principals -- and the self rules are what
// still let a user change their own password.
func TestAnEmptyListPermitsNothingButSelf(t *testing.T) {
	var a ACL
	if _, ok := a.Permits(DelPrinc, q("alice"),
		q("alice")); ok {
		t.Error("an empty list allowed a delete")
	}
	if _, ok := a.Permits(CPW, q("alice"),
		q("alice")); !ok {
		t.Error("a self password change was refused")
	}
	if _, ok := a.Permits(CPW, q("alice"),
		q("bob")); ok {
		t.Error("alice could change bob's password")
	}
}

// The self rules are five operations and no more. What is left off is
// the point: a principal that could modify itself could clear its own
// DISALLOW bits, and one that could extract its own key could take a
// copy of a credential it is only meant to use.
func TestTheSelfRulesAreExactlyFive(t *testing.T) {
	allowed := map[Op]bool{
		CPW: true, ChRand: true, PurgeKeys: true,
		GetPrinc: true, GetStrs: true,
	}
	for op := AddPrinc; op <= AddAlias; op++ {
		got := Self(op, q("alice"), q("alice"))
		if got != allowed[op] {
			t.Errorf("operation %d: self = %v", op, got)
		}
	}
}

// Reading the policy you are constrained by is allowed; reading
// somebody else's is not (self_getpol, auth_self.c:50-58).
func TestSelfPolicyOnlyReadsItsOwn(t *testing.T) {
	if !SelfPolicy(GetPol, "mine", "mine") {
		t.Error("a principal could not read its own policy")
	}
	if SelfPolicy(GetPol, "theirs", "mine") {
		t.Error("a principal read another policy")
	}
	if SelfPolicy(GetPol, "", "") {
		t.Error("an empty policy matched")
	}
}

// A rename needs two decisions, and the add must come with no
// restrictions at all -- which upstream insists on explicitly
// (:737-748). A restriction is something to impose at creation, and a
// rename creates nothing to impose it on, so an administrator whose
// add privilege is restricted may not rename rather than renaming and
// escaping the restriction.
func TestRenameNeedsBothAndNoRestrictions(t *testing.T) {
	ok, err := Parse(q("admin") + " ad")
	if err != nil {
		t.Fatal(err)
	}
	if !ok.PermitsRename(q("admin"), q("a"), q("b")) {
		t.Error("ad could not rename")
	}
	// Delete alone is not enough.
	half, err := Parse(q("admin") + " d")
	if err != nil {
		t.Fatal(err)
	}
	if half.PermitsRename(q("admin"), q("a"), q("b")) {
		t.Error("d alone renamed")
	}
	// And a restricted add refuses outright.
	SetAttrFunc(testAttrs)
	res, err := Parse(q("admin") + " ad * -maxlife 1h")
	if err != nil {
		t.Fatal(err)
	}
	if res.PermitsRename(q("admin"), q("a"), q("b")) {
		t.Error("a restricted add renamed")
	}
}

// Restrictions are imposed rather than checked: the smaller of the
// request and the cap wins, and an administrator capped at an hour
// who asks for a day gets an hour (impose_restrictions,
// auth.c:203-271).
func TestRestrictionsAreImposed(t *testing.T) {
	SetAttrFunc(testAttrs)
	a, err := Parse(q("admin") + " x * +requires_preauth " +
		"-maxlife 1h")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := a.Check(AddPrinc, q("admin"), q("someone"))
	if !ok || r == nil {
		t.Fatalf("no restrictions came back: %v %v", r, ok)
	}
	var attrs uint32
	day, renew := 24*time.Hour, time.Duration(0)
	r.Impose(&attrs, &day, &renew)
	if day != time.Hour {
		t.Errorf("maxlife is %v, want 1h", day)
	}
	if attrs != 1 {
		t.Errorf("attributes are %#x", attrs)
	}
	// An unset request takes the cap outright, because zero means
	// "the default" and not "no life".
	zero := time.Duration(0)
	r.Impose(&attrs, &zero, &renew)
	if zero != time.Hour {
		t.Errorf("an unset request became %v", zero)
	}
}

// testAttrs is a stand-in for internal/store's specifier table, which
// this package deliberately does not import.
func testAttrs(spec string) (uint32, uint32, error) {
	if strings.HasSuffix(spec, "requires_preauth") {
		if spec[0] == '+' {
			return 1, 0, nil
		}
		return 0, 1, nil
	}
	return 0, 0, errors.New("unknown attribute")
}
