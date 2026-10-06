package transit

// Check decides whether a transited encoding names only realms a path
// between two realms is allowed to pass through.
//
// This is krb5_check_transited_list (chk_trans.c:437-466): expand the
// field, and refuse if any realm it names is not in the hierarchical
// path between the two ends. An empty field passes without any of
// that, which is the ordinary single-hop case and the reason most
// tickets never reach the expansion at all.
//
// What this does not do is [capaths]. Upstream consults it first and
// falls back to the hierarchy (rtree_capath_vals, walk_rtree.c:124),
// so a realm pair with no hierarchical relationship can still be
// given a path by configuration. Without it, this accepts exactly the
// paths the naming convention describes -- which is a real limitation
// and not a safe-by-default one: a legitimate path between two
// unrelated realms is refused.
func Check(encoded, crealm, srealm string) error {
	// A trailing NUL is tolerated. Upstream strips one
	// (chk_trans.c:447-448) because the field reaches it as a
	// krb5_data that some encoders terminate and some do not.
	encoded = trimNul(encoded)
	if encoded == "" {
		return nil
	}
	allowed, err := Allowed(crealm, srealm)
	if err != nil {
		return err
	}
	return foreachRealm(func(r string) error {
		if allowed[r] {
			return nil
		}
		return ErrIllegalPath
	}, crealm, srealm, encoded)
}

func trimNul(s string) string {
	if s != "" && s[len(s)-1] == 0 {
		return s[:len(s)-1]
	}
	return s
}
