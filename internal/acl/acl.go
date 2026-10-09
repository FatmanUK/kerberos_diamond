// Package acl decides who may administer what, which is kadmin's
// kadm5.acl by another spelling.
//
// The whole of it is kadmin/server/auth_acl.c, and the grammar is
// upstream's own comment at :331-335:
//
//	entry ::= [ws] <principal> ws <opstring>
//	          [ws <target> [ws <restrictions> [ws]]]
//
// Folded onto one line as KD_ADMIN_ACL, entries separated by
// semicolons, the way KD_CAPATHS folds [capaths] -- so an existing
// kadm5.acl transcribes and its meaning can be looked up in
// upstream's documentation.
//
// Three rules in it are counter-intuitive, all three are tested
// upstream, and all three are reproduced:
//
//   - **x and * mean everything *except* e.** Extract is deliberately
//     outside the all-privileges mask (:49-56), because taking a copy
//     of an existing key is strictly more dangerous than replacing
//     it.
//   - **An upper-case letter denies** rather than grants (:270-284),
//     so the order of letters within an opstring matters.
//   - **The first matching entry wins, and only then is the operation
//     tested** (:496-543). A later, more permissive line is never
//     reached: an ACL is not a union.
package acl

import (
	"errors"
	"fmt"
	"strings"
)

// Op is an administrative operation, numbered as upstream numbers
// them (kadmin/server/auth.h:35-55) so that the two lists can be
// compared.
type Op int

const (
	AddPrinc Op = iota + 1
	ModPrinc
	SetStr
	CPW
	ChRand
	SetKey
	PurgeKeys
	DelPrinc
	RenPrinc
	GetPrinc
	GetStrs
	Extract
	ListPrincs
	AddPol
	ModPol
	DelPol
	GetPol
	ListPols
	IProp
	AddAlias
)

// Privilege is one letter's worth of permission.
type Privilege uint32

// The privilege bits (acl_op_table, auth_acl.c:70-83).
const (
	PrivAdd      Privilege = 1 << 0
	PrivDelete   Privilege = 1 << 1
	PrivModify   Privilege = 1 << 2
	PrivChangePW Privilege = 1 << 3
	PrivInquire  Privilege = 1 << 4
	PrivList     Privilege = 1 << 5
	PrivSetKey   Privilege = 1 << 6
	PrivExtract  Privilege = 1 << 7
	PrivIProp    Privilege = 1 << 8
)

// PrivAll is what x and * mean: everything but extract.
//
// Upstream leaves ACL_EXTRACT out of its all-privileges mask on
// purpose (:49-56) and tests the distinction
// (tests/t_kadmin_acl.py:356-375). Reading the comment is what
// explains it: `-e` hands out a copy of a key that is already in use,
// where every other privilege at most replaces one.
const PrivAll = PrivAdd | PrivDelete | PrivModify | PrivChangePW |
	PrivInquire | PrivList | PrivSetKey | PrivIProp

// letters maps an opstring letter to its privilege.
var letters = map[byte]Privilege{
	'a': PrivAdd,
	'd': PrivDelete,
	'm': PrivModify,
	'c': PrivChangePW,
	'i': PrivInquire,
	'l': PrivList,
	's': PrivSetKey,
	'e': PrivExtract,
	'p': PrivIProp,
	'x': PrivAll,
	'*': PrivAll,
}

// needs maps an operation to the privilege it requires, from the
// per-operation functions at auth_acl.c:577-733.
//
// Two of them need more than one and are handled by the caller:
// renprinc needs delete on the old name *and* add on the new
// (:737-748), and addalias needs add on the alias and modify on the
// target (:723-736).
var needs = map[Op]Privilege{
	AddPrinc:   PrivAdd,
	ModPrinc:   PrivModify,
	SetStr:     PrivModify,
	CPW:        PrivChangePW,
	ChRand:     PrivChangePW,
	SetKey:     PrivSetKey,
	PurgeKeys:  PrivModify,
	DelPrinc:   PrivDelete,
	GetPrinc:   PrivInquire,
	GetStrs:    PrivInquire,
	Extract:    PrivExtract,
	ListPrincs: PrivList,
	AddPol:     PrivAdd,
	ModPol:     PrivModify,
	DelPol:     PrivDelete,
	GetPol:     PrivInquire,
	ListPols:   PrivList,
	IProp:      PrivIProp,

	// AddAlias needs `a' on the alias name, and its caller needs
	// `m' on the target as well (acl_addalias,
	// auth_acl.c:723-734). Only the first is a privilege this
	// table can express; the second is a second check.
	AddAlias: PrivAdd,
}

// ErrMalformed reports an entry this package cannot read.
//
// A malformed entry is fatal rather than skipped, which is upstream's
// behaviour too: a syntax error anywhere stops kadmind from starting
// (:409-419). An ACL that silently dropped a line would grant or deny
// something nobody intended.
var ErrMalformed = errors.New("acl: malformed entry")

// Entry is one line of the list.
type Entry struct {
	// Client is the principal pattern this entry matches, with
	// "*" permitted as a whole component.
	Client string

	// Allow and Deny are the privileges the opstring granted and
	// revoked. Both are kept because the order of letters
	// matters: a lower-case letter adds and an upper-case one
	// takes away, left to right.
	Allow Privilege
	Deny  Privilege

	// Target is the principal pattern the operation's object must
	// match, empty meaning any. "*1" to "*9" in it refer to the
	// components "*" captured in Client.
	Target string

	// Restrict is what this entry imposes on an addprinc or a
	// modprinc, nil when it imposes nothing.
	Restrict *Restrictions
}

// ACL is the whole list, in order.
//
// A nil ACL permits nothing, which is the right default for a surface
// that provisions principals: upstream's kadmind refuses every
// operation when its ACL file is missing, and the self rules (see
// Self) are what still lets a user change its own password.
type ACL []Entry

// Parse reads the KD_ADMIN_ACL form.
func Parse(s string) (ACL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out ACL
	for _, raw := range strings.Split(s, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		e, err := parseEntry(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// parseEntry reads one entry: a principal, an opstring, and
// optionally a target and restrictions.
func parseEntry(raw string) (Entry, error) {
	f := strings.Fields(raw)
	if len(f) < 2 {
		return Entry{}, fmt.Errorf(
			"%w: %q wants a principal and privileges",
			ErrMalformed, raw)
	}
	allow, deny, err := parseOps(f[1], raw)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Client: f[0], Allow: allow, Deny: deny}
	if len(f) > 2 && f[2] != "*" {
		e.Target = f[2]
	}
	if len(f) > 3 {
		r, err := parseRestrictions(f[3:], raw)
		if err != nil {
			return Entry{}, err
		}
		e.Restrict = r
	}
	return e, nil
}

// parseOps reads an opstring, in which case decides direction.
func parseOps(
	ops, raw string,
) (allow, deny Privilege, err error) {
	for i := 0; i < len(ops); i++ {
		c := ops[i]
		lower := c
		if c >= 'A' && c <= 'Z' {
			lower = c + 32
		}
		p, ok := letters[lower]
		if !ok {
			return 0, 0, fmt.Errorf(
				"%w: %q has no privilege %q",
				ErrMalformed, raw, string(c))
		}
		if c == lower {
			allow |= p
		} else {
			deny |= p
		}
	}
	return allow, deny, nil
}

// Check reports whether a client may perform an operation on a
// target, and what the matching entry imposes.
//
// The first matching entry decides, and then the operation is tested
// against it -- so an entry that matches but lacks the privilege
// refuses, and a later entry that would have allowed it is never
// consulted (find_entry and acl_check, :496-543). That is the rule
// most likely to surprise someone writing an ACL, and it is
// upstream's.
func (a ACL) Check(
	op Op,
	client, target string,
) (*Restrictions, bool) {
	e := a.find(client, target)
	if e == nil {
		return nil, false
	}
	want, ok := needs[op]
	if !ok {
		return nil, false
	}
	if e.Deny&want != 0 || e.Allow&want == 0 {
		return nil, false
	}
	return e.Restrict, true
}

// find returns the first entry matching a client and target.
func (a ACL) find(client, target string) *Entry {
	for i := range a {
		e := &a[i]
		caps, ok := matchClient(e.Client, client)
		if !ok {
			continue
		}
		if e.Target == "" {
			return e
		}
		if target == "" {
			continue
		}
		if matchTarget(e.Target, target, caps) {
			return e
		}
	}
	return nil
}
