package store

// Principal attributes, the bitfield upstream calls `attributes` and
// kadmin prints as `+requires_preauth` and friends
// (include/kdb.h:85-102).
//
// Most of them are DISALLOW_ bits, which is worth noticing: the
// default state of a fresh principal is permissive, and policy is
// expressed by turning things off.
const (
	AttrDisallowPostdated   uint32 = 0x00000001
	AttrDisallowForwardable uint32 = 0x00000002
	AttrDisallowTGTBased    uint32 = 0x00000004
	AttrDisallowRenewable   uint32 = 0x00000008
	AttrDisallowProxiable   uint32 = 0x00000010
	AttrDisallowDupSKey     uint32 = 0x00000020
	AttrDisallowAllTix      uint32 = 0x00000040
	AttrRequiresPreAuth     uint32 = 0x00000080
	AttrRequiresHWAuth      uint32 = 0x00000100
	AttrRequiresPWChange    uint32 = 0x00000200
	AttrDisallowSvr         uint32 = 0x00001000
	AttrPWChangeService     uint32 = 0x00002000
	AttrNewPrinc            uint32 = 0x00008000
	AttrOKAsDelegate        uint32 = 0x00100000
	AttrOKToAuthAsDelegate  uint32 = 0x00200000
	AttrNoAuthDataRequired  uint32 = 0x00400000
	AttrLockdownKeys        uint32 = 0x00800000
)

// Salt types (include/kdb.h:76-82). Types 1 and 5, the Kerberos 4 and
// AFS 3 salts, are commented out upstream and deliberately absent
// here.
const (
	SaltNormal    int32 = 0
	SaltNoRealm   int32 = 2
	SaltOnlyRealm int32 = 3
	SaltSpecial   int32 = 4
	SaltCertHash  int32 = 6
)

// tl-data types (include/kdb.h:249-276).
//
// Upstream's tl_data is an untyped extensibility bag -- a list of
// (type, length, bytes) with at most one record per type -- and
// several of its types are really columns in disguise. The five below
// are promoted to real columns on Principal; everything else is kept
// verbatim in TLDatum so that a dump and load still round-trips.
const (
	TLLastPWChange int32 = 0x0001
	TLModPrinc     int32 = 0x0002
	TLKadmData     int32 = 0x0003
	TLMKVNO        int32 = 0x0008
	TLStringAttrs  int32 = 0x000b
)

// RequiresPreAuth reports whether the KDC must refuse this principal
// a ticket until it proves knowledge of its key.
func (p *Principal) RequiresPreAuth() bool {
	return p.Attributes&AttrRequiresPreAuth != 0
}

// Allows reports whether none of the given DISALLOW_ bits are set.
func (p *Principal) Allows(disallow uint32) bool {
	return p.Attributes&disallow == 0
}
