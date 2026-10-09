package acl

// Self reports whether a principal may perform an operation on itself
// with no access-control entry at all (auth_self.c:38-58).
//
// Five operations, and the list is exactly upstream's: cpw, chrand,
// purgekeys, getprinc and getstrs. It is what makes a realm with an
// empty ACL still usable -- a user can change their own password and
// read their own entry, and nothing else.
//
// Note what is *not* on it. A principal cannot modify itself, delete
// itself, rename itself or extract its own key, because each of those
// is a way to escalate: a principal that could modify itself could
// clear its own DISALLOW bits, and one that could extract its own key
// could take a copy of a service credential it is only supposed to
// use in place.
func Self(op Op, client, target string) bool {
	switch op {
	case CPW, ChRand, PurgeKeys, GetPrinc, GetStrs:
		return client != "" && client == target
	}
	return false
}

// SelfPolicy reports whether a principal may read a policy because it
// is its own (self_getpol, auth_self.c:50-58).
//
// Reading the policy you are constrained by is reasonable; reading
// somebody else's tells you how to attack them.
func SelfPolicy(op Op, policy, clientPolicy string) bool {
	return op == GetPol && clientPolicy != "" &&
		policy == clientPolicy
}

// Permits is the whole decision for an operation on a principal: the
// self rules or the list, whichever allows it.
//
// Upstream runs its modules in order and takes the first that
// authorises (auth, kadmin/server/auth.c:184-201), with the self
// module and the ACL module both installed by default. The self rules
// impose no restrictions, which is why they return nil here -- a
// restriction belongs to the entry that granted the operation, and
// the self rules are not an entry.
func (a ACL) Permits(
	op Op,
	client, target string,
) (*Restrictions, bool) {
	if Self(op, client, target) {
		return nil, true
	}
	return a.Check(op, client, target)
}

// PermitsRename is renprinc, which needs two decisions rather than
// one: delete on the old name and add on the new (acl_renprinc,
// auth_acl.c:737-748).
//
// And the add must come with **no** restrictions, which upstream
// insists on explicitly (`rs == NULL`). The reason is sound: a
// restriction is something to impose at creation, and a rename
// creates nothing to impose it on -- so an administrator whose add
// privilege is restricted may not rename at all, rather than renaming
// and quietly escaping the restriction.
func (a ACL) PermitsRename(client, from, to string) bool {
	if _, ok := a.Check(DelPrinc, client, from); !ok {
		return false
	}
	r, ok := a.Check(AddPrinc, client, to)
	return ok && r == nil
}
