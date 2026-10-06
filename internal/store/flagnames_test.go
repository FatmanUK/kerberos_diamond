package store

import (
	"errors"
	"strings"
	"testing"
)

// Most attribute names are inverted, and this is the table that says
// so. "+forwardable" permits forwardable tickets, which means
// *clearing* DISALLOW_FORWARDABLE -- so a specifier that read as "set
// the named bit" would do the opposite of what an operator asked on
// eight of these fourteen attributes.
func TestInvertedAttributeNames(t *testing.T) {
	cases := []struct {
		spec  string
		from  uint32
		want  uint32
		named string
	}{
		{"+forwardable", AttrDisallowForwardable, 0,
			"permitting clears the DISALLOW bit"},
		{"-forwardable", 0, AttrDisallowForwardable,
			"forbidding sets it"},
		{"+disallow_forwardable", 0, AttrDisallowForwardable,
			"the uninverted spelling sets it"},
		{"-disallow_forwardable", AttrDisallowForwardable, 0,
			"and clears it"},
		{"+requires_preauth", 0, AttrRequiresPreAuth,
			"a REQUIRES bit is not inverted"},
		{"-requires_preauth", AttrRequiresPreAuth, 0,
			"and clears normally"},
		{"+allow_tix", AttrDisallowAllTix, 0,
			"allow_tix clears DISALLOW_ALL_TIX"},
		{"-allow_tix", 0, AttrDisallowAllTix,
			"and forbidding locks the principal out"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ApplyAttr(tc.from, tc.spec)
			if err != nil {
				t.Fatalf("ApplyAttr: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %08X, want %08X (%s)",
					got, tc.want, tc.named)
			}
		})
	}
}

// Every alias has to reach the same bit with the same sense, or an
// operator's muscle memory silently does something else.
func TestAttributeAliasesAgree(t *testing.T) {
	groups := [][]string{
		{"allow_postdated", "postdateable"},
		{"allow_forwardable", "forwardable"},
		{"allow_tgs_req", "tgt_based"},
		{"allow_renewable", "renewable"},
		{"allow_proxiable", "proxiable"},
		{"allow_dup_skey", "dup_skey"},
		{"allow_tickets", "allow_tix"},
		{"preauth", "requires_pre_auth", "requires_preauth"},
		{"hwauth", "requires_hw_auth", "requires_hwauth"},
		{"needchange", "pwchange", "requires_pwchange"},
		{"allow_svr", "service"},
		{"password_changing_service", "pwchange_service",
			"pwservice"},
	}
	for _, g := range groups {
		first, err := ApplyAttr(0, "+"+g[0])
		if err != nil {
			t.Fatalf("+%s: %v", g[0], err)
		}
		for _, alias := range g[1:] {
			got, err := ApplyAttr(0, "+"+alias)
			if err != nil {
				t.Fatalf("+%s: %v", alias, err)
			}
			if got != first {
				t.Errorf("+%s is %08X, +%s is %08X",
					g[0], first, alias, got)
			}
		}
	}
}

// Order matters, which is why the specifiers are a list and not a
// set.
func TestAttributesApplyInOrder(t *testing.T) {
	on, err := ApplyAttr(0, "-allow_tix")
	if err != nil {
		t.Fatal(err)
	}
	off, err := ApplyAttr(on, "+allow_tix")
	if err != nil {
		t.Fatal(err)
	}
	if off != 0 {
		t.Errorf("the later specifier lost: %08X", off)
	}
}

func TestApplyAttrRejectsRubbish(t *testing.T) {
	for _, spec := range []string{
		"", "+", "forwardable", "~forwardable",
		"+nosuchthing",
	} {
		if _, err := ApplyAttr(0, spec); err == nil {
			t.Errorf("accepted %q", spec)
		} else if !errors.Is(err, ErrBadAttr) {
			t.Errorf("%q gave %v, want ErrBadAttr",
				spec, err)
		}
	}
}

// A name's case should not matter; an operator typing it in a hurry
// should not have to care.
func TestApplyAttrIsCaseInsensitive(t *testing.T) {
	got, err := ApplyAttr(0, "+REQUIRES_PREAUTH")
	if err != nil {
		t.Fatalf("ApplyAttr: %v", err)
	}
	if got != AttrRequiresPreAuth {
		t.Errorf("got %08X", got)
	}
}

// Display uses the *stored* names, not the inverted spellings, which
// is what getprinc prints and what the KDB holds.
func TestAttrNamesUseTheStoredSense(t *testing.T) {
	got := strings.Join(AttrNames(
		AttrRequiresPreAuth|AttrDisallowForwardable), " ")
	want := "DISALLOW_FORWARDABLE REQUIRES_PRE_AUTH"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if n := AttrNames(0); len(n) != 0 {
		t.Errorf("a clear word named %v", n)
	}
}

// Every specifier the table accepts must be listed for the usage
// message, or an operator cannot discover the one they want.
func TestAttrSpecNamesCoversTheTable(t *testing.T) {
	names := AttrSpecNames()
	if len(names) != len(attrSpecs) {
		t.Errorf("listed %d of %d specifiers",
			len(names), len(attrSpecs))
	}
	for _, n := range names {
		if _, err := ApplyAttr(0, "+"+n); err != nil {
			t.Errorf("listed %q, cannot apply: %v",
				n, err)
		}
	}
}
