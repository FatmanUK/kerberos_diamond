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
// Which paths are allowed comes from Paths: a configured one if there
// is one, and the realm hierarchy otherwise. Upstream decides it the
// same way round (rtree_capath_vals first, walk_rtree.c:124), and the
// order matters -- a configured path *replaces* the hierarchical
// guess rather than adding to it, so a realm pair that has an entry
// is decided entirely by that entry.
func (p Paths) Check(encoded, crealm, srealm string) error {
	// A trailing NUL is tolerated. Upstream strips one
	// (chk_trans.c:447-448) because the field reaches it as a
	// krb5_data that some encoders terminate and some do not.
	encoded = trimNul(encoded)
	if encoded == "" {
		return nil
	}
	allowed, err := p.Allowed(crealm, srealm)
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

// Check is Paths.Check with no configuration, which is the hierarchy
// alone.
func Check(encoded, crealm, srealm string) error {
	return Paths(nil).Check(encoded, crealm, srealm)
}

func trimNul(s string) string {
	if s != "" && s[len(s)-1] == 0 {
		return s[:len(s)-1]
	}
	return s
}
