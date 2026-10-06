package wire

import "testing"

// The name type is a hint about how a name was spelled, not part of
// its identity: krb5_principal_compare never looks at it
// (princ_comp.c:70-136). The same principal arrives under different
// types from different clients, so comparing it would refuse a
// request that named exactly the right principal.
func TestEqualIgnoresTheNameType(t *testing.T) {
	inst := PrincipalName{
		Type:       NTSrvInst,
		Components: []string{"krbtgt", "EXAMPLE.ORG"},
	}
	host := PrincipalName{
		Type:       NTSrvHst,
		Components: []string{"krbtgt", "EXAMPLE.ORG"},
	}
	if !inst.Equal(host) {
		t.Error("one name under two types compared unequal")
	}
	other := PrincipalName{
		Type:       NTSrvInst,
		Components: []string{"krbtgt", "OTHER.ORG"},
	}
	if inst.Equal(other) {
		t.Error("two different names compared equal")
	}
	if inst.Equal(PrincipalName{Type: NTSrvInst,
		Components: []string{"krbtgt"}}) {
		t.Error("names of different lengths compared equal")
	}
}
