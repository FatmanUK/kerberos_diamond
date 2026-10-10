package store

import (
	"fmt"
	"strings"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
)

// SupportedEnctypes is which key/salt pairs addprinc and cpw
// *create*, which is kadmin's supported_enctypes
// (KRB5_DEFAULT_SUPPORTED_ENCTYPES, include/osconf.hin:109-111).
//
// **Three different lists get confused with each other** and this is
// only one of them:
//
//   - supported_enctypes, here, is what a principal gets keys *for*.
//   - permitted_enctypes is what a session may use, which is a
//     separate decision about what travels.
//   - and a client's own default_tkt_enctypes is what it asks for.
//
// Upstream's default is two entries, both sha1
// (aes256-cts-hmac-sha1-96 and aes128), and notably **not** the
// aes-sha2 pair even though it implements them -- so a stock realm
// creates no sha2 keys unless told to.
//
// **The order is load-bearing**, for a reason recorded elsewhere in
// this project: the KDC seals a ticket with the *first* key of a
// principal's highest key version, whatever its enctype. So the first
// entry here is the enctype every service ticket is encrypted with,
// and reordering the list changes that for every principal created
// afterwards.
type SupportedEnctypes []crypto.EncType

// DefaultSupportedEnctypes is upstream's default, in upstream's
// order.
func DefaultSupportedEnctypes() SupportedEnctypes {
	return SupportedEnctypes{
		crypto.AES256CTSHMACSHA196,
		crypto.AES128CTSHMACSHA196,
	}
}

// ParseEnctypes reads a space- or comma-separated list of enctype
// names, which is how krb5.conf spells one.
//
// The `:normal' salt-type suffix upstream accepts is taken and
// ignored, because `normal' is the only salt type this project
// creates keys with: a special salt is something rename *pins*
// afterwards (SpecializeSalt), never something an operator chooses up
// front, and the other upstream salt types are DES-era. Accepting the
// suffix means a krb5.conf value transcribes; silently accepting a
// *different* suffix would not, so anything else is refused.
func ParseEnctypes(s string) (SupportedEnctypes, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out SupportedEnctypes
	for _, f := range strings.FieldsFunc(s, isEnctypeSep) {
		e, err := parseEnctype(f)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isEnctypeSep splits on spaces and commas, as krb5.conf lists do.
func isEnctypeSep(r rune) bool {
	return r == ' ' || r == ',' || r == '\t' || r == '\n'
}

// parseEnctype reads one entry, with or without a salt suffix.
func parseEnctype(f string) (crypto.EncType, error) {
	name, salt := f, ""
	if i := strings.IndexByte(f, ':'); i >= 0 {
		name, salt = f[:i], f[i+1:]
	}
	if salt != "" && !strings.EqualFold(salt, "normal") {
		return 0, fmt.Errorf(
			"enctype %q: only the `normal' salt type is "+
				"created here", f)
	}
	e, ok := crypto.EncTypeByName(name)
	if !ok {
		return 0, fmt.Errorf("unknown enctype %q", name)
	}
	return e, nil
}

// String renders the list back, so that a configuration dump says
// what was parsed.
func (s SupportedEnctypes) String() string {
	names := make([]string, 0, len(s))
	for _, e := range s {
		p, err := crypto.Profile(e)
		if err != nil {
			names = append(names, fmt.Sprint(int32(e)))
			continue
		}
		names = append(names, p.Name)
	}
	return strings.Join(names, " ")
}

// types is the list to create keys for, falling back to the default
// when nothing was configured.
func (s SupportedEnctypes) types() []crypto.EncType {
	if len(s) == 0 {
		return DefaultSupportedEnctypes()
	}
	return s
}
