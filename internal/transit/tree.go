package transit

// TGSName is one ticket-granting service in a realm path: the service
// Realm would issue a ticket for, named Service.
//
// Upstream builds these as full principals --
// krbtgt/<Service>@<Realm> (krb5int_tgtname) -- and the transited
// check looks only at Realm, because what it is deciding is which
// realms are allowed to appear in a path. The service half is kept
// because find_alternate_tgs wants the whole name.
type TGSName struct {
	Service string
	Realm   string
}

// Tree is the sequence of ticket-granting services between two realms
// (krb5_walk_realm_tree, lib/krb5/krb/walk_rtree.c:93-121).
//
// A configured path wins; otherwise the realm hierarchy is walked.
// The hierarchy is in the names: A.EXAMPLE.COM and B.EXAMPLE.COM are
// both below EXAMPLE.COM, so a path between them runs up to the
// common suffix and back down. That is a convention and not a fact
// about the realms, which is exactly why configuration has to be able
// to override it.
//
// There is no path from a realm to itself, which upstream reports as
// an error rather than an empty list.
func (p Paths) Tree(client, server string) ([]TGSName, error) {
	if client == "" || server == "" || client == server {
		return nil, ErrNoPath
	}
	if hops, ok := p.hops(client, server); ok {
		// rtree_capath_tree names the client's own realm
		// first, then each configured hop, then the server
		// (walk_rtree.c:252-274).
		dsts := make([]string, 0, len(hops)+2)
		dsts = append(dsts, client)
		dsts = append(dsts, hops...)
		return chain(client, append(dsts, server)), nil
	}
	// rtree_hier_realms already starts with the client's realm
	// and ends with the server's, so the whole list is the walk
	// (walk_rtree.c:368-377).
	return chain(client, hierRealms(client, server)), nil
}

// Tree is Paths.Tree with no configuration, which is the hierarchy
// alone.
func Tree(client, server string) ([]TGSName, error) {
	return Paths(nil).Tree(client, server)
}

// chain walks a list of destination realms from the client's own,
// naming the ticket-granting service each hop has to ask for: the
// service is where the hop is going and the realm is where it starts.
func chain(client string, dsts []string) []TGSName {
	out := make([]TGSName, 0, len(dsts))
	src := client
	for _, dst := range dsts {
		out = append(out, TGSName{Service: dst, Realm: src})
		src = dst
	}
	return out
}

// Allowed is the set of realms a path between two realms may name.
//
// It is the realms of Tree's entries, which is what
// check_realm_in_list compares against (chk_trans.c:290-303). Note
// which half that is: the realm a ticket-granting ticket was *issued
// by*, not the one it grants tickets for. A realm appears exactly
// when some hop in the path starts there.
func (p Paths) Allowed(
	client, server string,
) (map[string]bool, error) {
	tree, err := p.Tree(client, server)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(tree))
	for _, t := range tree {
		out[t.Realm] = true
	}
	return out, nil
}

// Allowed is Paths.Allowed with no configuration.
func Allowed(client, server string) (map[string]bool, error) {
	return Paths(nil).Allowed(client, server)
}

// hstate is upstream's struct hstate (walk_rtree.c:41-47), holding a
// realm name and two positions in it: tail, where its common suffix
// with the other realm begins, and dot, the nearest separator to the
// right of that. Both are -1 when there is none, where upstream uses
// a null pointer.
type hstate struct {
	str  string
	tail int
	dot  int
}

// hierRealms is rtree_hier_realms (walk_rtree.c:390-452): the realms
// between the client's and the server's, running up from the client
// to the common suffix and back down to the server.
func hierRealms(client, server string) []string {
	c := &hstate{str: client, tail: -1, dot: -1}
	s := &hstate{str: server, tail: -1, dot: -1}
	comtail(c, s)
	adjtail(c, s)
	// The client's own realm is included and the server's is not:
	// the walk starts where the client is and the last hop's
	// destination is the server, which is named by the request
	// rather than by the path.
	up := tweens(c, true)
	down := tweens(s, false)
	out := make([]string, 0, len(up)+len(down))
	out = append(out, up...)
	for i := len(down) - 1; i >= 0; i-- {
		out = append(out, down[i])
	}
	return out
}

// comtail finds the longest common suffix of two realm names
// (walk_rtree.c:567-611), and records where the last matching
// separator was.
func comtail(c, s *hstate) {
	if c.str == "" || s.str == "" {
		return
	}
	cdot, sdot := -1, -1
	cp, sp := len(c.str), len(s.str)
	for cp > 0 && sp > 0 {
		cp--
		sp--
		if c.str[cp] != s.str[sp] {
			cp++
			sp++
			break
		}
		if c.str[cp] == Separator {
			cdot, sdot = cp, sp
		}
	}
	if cp == len(c.str) {
		return
	}
	c.tail, s.tail, c.dot, s.dot = cp, sp, cdot, sdot
}

// adjtail moves each suffix forward to a component boundary
// (walk_rtree.c:520-557).
//
// Upstream's comment says exactly what this is for and it is worth
// repeating, because the bug it avoids looks like a feature: without
// it, "BC.EXAMPLE.COM" and "ABC.EXAMPLE.COM" share the suffix
// "BC.EXAMPLE.COM", and the shorter would be reported as a parent of
// the longer. A common suffix only means a shared ancestor when it
// starts where a component starts.
func adjtail(c, s *hstate) {
	if c.tail < 0 || s.tail < 0 {
		return
	}
	if full(c, c.tail) && full(s, s.tail) {
		return
	}
	// Not a whole component, so fall back to the last separator
	// inside the suffix. If either name has nothing after it --
	// which happens only with a trailing dot -- there is no
	// usable boundary and the realms are treated as unrelated.
	cp, sp := -1, -1
	if c.dot >= 0 && s.dot >= 0 &&
		c.dot+1 < len(c.str) && s.dot+1 < len(s.str) {
		cp, sp = c.dot+1, s.dot+1
	}
	c.tail, s.tail = cp, sp
}

// full reports whether a position begins a whole component: the start
// of the name, or just after a separator.
func full(h *hstate, at int) bool {
	return at == 0 || h.str[at-1] == Separator
}

// tweens lists the suffixes of a realm name at component boundaries,
// from the whole name down towards the common suffix
// (rtree_hier_tweens, walk_rtree.c:463-500).
//
// withTail decides whether the common suffix itself is included,
// which is how the two ends of a path differ: walking up from the
// client includes it, walking up from the server does not, so it
// appears once rather than twice.
func tweens(h *hstate, withTail bool) []string {
	var out []string
	lp := 0
	for p := 0; p < len(h.str); p++ {
		if h.str[p] != Separator && p+1 != len(h.str) {
			continue
		}
		if lp == h.tail && !withTail {
			break
		}
		out = append(out, h.str[lp:])
		if lp == h.tail {
			break
		}
		lp = p + 1
	}
	return out
}
