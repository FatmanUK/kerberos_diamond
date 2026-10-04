package golden

import (
	"regexp"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// etypeInfo pulls the enctype and salt out of the client's trace line
// reporting what it took from PA-ETYPE-INFO2.
var etypeInfo = regexp.MustCompile(
	`Selected etype info: etype (\S+), salt "([^"]*)"`)

// The C computes a principal's default salt and prints it; this
// asserts internal/crypto computes the same string.
//
// It is a small check for a large risk. The salt is realm followed by
// name components with no separator, and a wrong salt does not fail
// as "wrong salt" -- it derives a different key and surfaces as "bad
// password", which is the hardest kind of mistake to attribute.
// Having the C state its answer removes the guesswork.
func TestSaltMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx := testContext(t)

	for _, princ := range []string{UserName, PreauthName} {
		out, err := o.KinitTraced(ctx, princ, UserPassword)
		if err != nil {
			t.Fatalf("kinit %s: %v\n%s", princ, err, out)
		}
		m := etypeInfo.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no etype info for %s\n%s",
				princ, out)
		}
		gotEtype, gotSalt := m[1], m[2]

		want := string(crypto.Salt(Realm, []string{princ}))
		if gotSalt != want {
			t.Errorf("%s: the C salts with %q,"+
				" crypto.Salt gives %q",
				princ, gotSalt, want)
		}
		// And the enctype it picked, which pins the
		// preference order the KDC offers against what we
		// would choose.
		if gotEtype != "aes256-cts" {
			t.Errorf("%s: the C chose %q, not aes256-cts",
				princ, gotEtype)
		}
	}
}
