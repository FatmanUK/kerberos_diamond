package transit

import (
	"errors"
	"strings"
	"testing"
)

// Nothing upstream publishes an expected value for add_to_transited.
// kdc/rtest.c prints what it computed and asserts nothing, the way
// t_cts.c does for AES-CTS -- so these cases are derived from reading
// kdc_transit.c rather than anchored to its output, and they say so.
//
// The anchor that does exist is the golden harness: a path through
// three realms drives the C KDC and this one over the same hops, and
// the transited field either side wrote is compared. That is where
// this file's correctness is actually established. What these cases
// are for is localising a failure -- a wrong answer here names the
// compression rule that broke, where the harness only says the fields
// differ.
var addVectors = []struct {
	name                     string
	old, tgs, client, server string
	want                     string
}{
	{"an end realm is implied and not written",
		"", "A.TEST", "A.TEST", "B.TEST", ""},
	{"the server's realm is implied too",
		"", "B.TEST", "A.TEST", "B.TEST", ""},
	// The ordinary three-realm case: the realm in the middle is
	// neither end, so it is written in full into an empty field.
	{"a middle realm is written in full",
		"", "MID.TEST", "A.TEST", "B.TEST", "MID.TEST"},
	// Already present, in expanded form: nothing to add.
	{"a realm already in the field is not repeated",
		"MID.TEST", "MID.TEST", "A.TEST", "B.TEST",
		"MID.TEST"},
	// A subrealm of what is already there can be written relative
	// to it: EDU is in the field, MIT.EDU shares its suffix, so
	// only the "MIT." part is new.
	{"a subrealm is compressed against its parent",
		"EDU", "MIT.EDU", "A.TEST", "B.TEST", "EDU,MIT."},
	// The other direction: COM is a superrealm of BLORT.COM, so
	// COM goes in and BLORT.COM is rewritten relative to it.
	{"a superrealm replaces and compresses its child",
		"BLORT.COM", "COM", "A.TEST", "B.TEST",
		"COM,BLORT."},
	// X.500 names nest the other way round, by prefix, so the
	// relative part is the new suffix rather than the new prefix.
	{"an X.500 subrealm is compressed by prefix",
		"/COM", "/COM/HP", "A.TEST", "B.TEST", "/COM,/HP"},
	// An X.500 name appended after an unrelated component needs
	// the detaching space, or it would read as relative to it.
	{"an unrelated X.500 realm gets a leading space",
		"EDU", "/COM", "A.TEST", "B.TEST", "EDU, /COM"},
	// Nothing to compress against: the realm is appended whole.
	{"an unrelated realm is appended",
		"EDU", "MIT.ORG", "A.TEST", "B.TEST", "EDU,MIT.ORG"},
}

func TestAdd(t *testing.T) {
	for _, v := range addVectors {
		got, err := Add(v.old, v.tgs, v.client, v.server)
		if err != nil {
			t.Errorf("%s: %v", v.name, err)
			continue
		}
		if got != v.want {
			t.Errorf("%s:\n got %q\nwant %q",
				v.name, got, v.want)
		}
	}
}

// Whatever Add writes, Check has to be able to read: the two
// functions are the two ends of one wire format and a field only one
// of them understands is worse than no compression at all.
//
// The realms here are a genuine hierarchy, so Allowed admits them and
// the check is of the encoding rather than of the policy.
func TestAddRoundTripsThroughCheck(t *testing.T) {
	const client = "SUB.OTHER.EXAMPLE.TEST"
	const server = "EXAMPLE.TEST"
	field, err := Add("", "OTHER.EXAMPLE.TEST", client, server)
	if err != nil {
		t.Fatal(err)
	}
	if field == "" {
		t.Fatal("the middle realm was not recorded")
	}
	got, err := Expand(client, server, field)
	if err != nil {
		t.Fatalf("expanding %q: %v", field, err)
	}
	if len(got) != 1 || got[0] != "OTHER.EXAMPLE.TEST" {
		t.Errorf("%q expanded to %v", field, got)
	}
	if err := Check(field, client, server); err != nil {
		t.Errorf("Check refused %q: %v", field, err)
	}
}

// A realm outside the path between the two ends is refused. This is
// the whole point of the field: a service has to be able to tell a
// ticket that came through somewhere it trusts from one that did not.
func TestCheckRefusesARealmOffThePath(t *testing.T) {
	err := Check("ELSEWHERE.TEST", "SUB.EXAMPLE.TEST",
		"EXAMPLE.TEST")
	if !errors.Is(err, ErrIllegalPath) {
		t.Errorf("got %v, want ErrIllegalPath", err)
	}
}

// An empty field passes without consulting the path at all, which is
// the ordinary single-hop case -- and it has to pass even between two
// realms with no hierarchical relationship, where Allowed would
// answer ErrNoPath.
func TestCheckPassesAnEmptyField(t *testing.T) {
	if err := Check("", "A.TEST", "B.TEST"); err != nil {
		t.Errorf("an empty field was refused: %v", err)
	}
	if err := Check("", "ONE.TEST", "ONE.TEST"); err != nil {
		t.Errorf("a same-realm empty field: %v", err)
	}
}

// Adding a realm twice must not write it twice. A field that grew on
// every hop through the same realm would eventually overflow, and
// until it did it would say the ticket crossed more boundaries than
// it had.
func TestAddIsIdempotent(t *testing.T) {
	once, err := Add("", "MID.TEST", "A.TEST", "B.TEST")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Add(once, "MID.TEST", "A.TEST", "B.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if twice != once {
		t.Errorf("got %q, want %q unchanged", twice, once)
	}
}

// A field at the size limit is refused rather than truncated: a
// truncated realm name is a different realm name, and quite possibly
// one the allowed list contains.
func TestAddRefusesAnOverlongField(t *testing.T) {
	long := strings.Repeat("R.TEST,", 90)
	_, err := Add(long, "MID.TEST", "A.TEST", "B.TEST")
	if !errors.Is(err, ErrIllegalPath) {
		t.Errorf("a long field gave %v", err)
	}
	// A single component over the limit is refused as it is read,
	// before any compression is attempted.
	_, err = Add(strings.Repeat("X", maxLen+1),
		"MID.TEST", "A.TEST", "B.TEST")
	if !errors.Is(err, ErrIllegalPath) {
		t.Errorf("a long component gave %v", err)
	}
}
