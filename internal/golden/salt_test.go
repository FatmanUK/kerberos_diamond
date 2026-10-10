package golden

import (
	"regexp"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
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
		assertSaltAndEtype(t, princ, m[1], m[2])
	}
}

// assertSaltAndEtype checks one principal's trace line.
func assertSaltAndEtype(
	t *testing.T,
	princ, gotEtype, gotSalt string,
) {
	t.Helper()
	want := string(crypto.Salt(Realm, []string{princ}))
	if gotSalt != want {
		t.Errorf("%s: the C salts with %q,"+
			" crypto.Salt gives %q",
			princ, gotSalt, want)
	}
	// And the enctype it picked, which is aes256-cts even though
	// the realm now holds aes-sha2 keys and this KDC prefers
	// them.
	//
	// That is the *client's* order deciding, not the KDC's. MIT's
	// default_enctype_list puts the two RFC 3962 types ahead of
	// the aes-sha2 pair (lib/krb5/krb/init_ctx.c:59-66), and
	// select_client_key walks the request's list in the client's
	// order (do_as_req.c:111-128). So the KDC's own preference
	// decides the *session* key and which key seals the ticket,
	// and the client's decides which of its long-term keys the
	// reply is encrypted under. Two orders, two different jobs,
	// and conflating them is what the first draft of this
	// assertion did.
	if gotEtype != "aes256-cts" {
		t.Errorf("%s: the C chose %q, not aes256-cts",
			princ, gotEtype)
	}
}
