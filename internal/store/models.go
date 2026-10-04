package store

import "time"

// Principal is one entry of the principal database.
//
// The columns are upstream's krb5_db_entry (include/kdb.h:191-213)
// projected into relations, and the projection is not invented here:
// kadmin/dbutil/tabdump.c already does it, and its table list is very
// nearly this schema. Following it means a tabdump and a SELECT line
// up field for field, which is what makes the two implementations
// comparable at all.
//
// Where it departs from tabdump: the tl-data types that tabdump
// derives on the fly for its princ_meta relation (:443-513) are
// stored as columns here rather than re-derived, because a relational
// database can enforce them and a packed record cannot.
type Principal struct {
	// Name is the fully qualified principal with its realm,
	// escaped exactly as krb5_unparse_name writes it, which is
	// also how tabdump keys every one of its relations. Realm is
	// stored alongside it because a KDC filters on it constantly
	// and re-parsing a name per row to find it would be silly.
	Name  string `gorm:"primaryKey;size:1024"`
	Realm string `gorm:"size:255;index"`

	// NameType is the PrincipalName name-type from the wire.
	NameType int32

	// Attributes is the DISALLOW_/REQUIRES_ bitfield.
	Attributes uint32

	// MaxLife and MaxRenewableLife are in seconds, and zero means
	// *unlimited*, not zero -- see kdc_get_ticket_endtime
	// (kdc/kdc_util.c:1676-1704).
	MaxLife          int32
	MaxRenewableLife int32

	// Expiration and PWExpiration are tabdump's princ_tktpolicy
	// relation. A zero time means no expiry.
	Expiration   time.Time
	PWExpiration time.Time

	// LastSuccess, LastFailed and FailAuthCount are tabdump's
	// princ_lockout relation. The KDC never writes them during an
	// AS exchange in this implementation.
	LastSuccess   time.Time
	LastFailed    time.Time
	FailAuthCount int32

	// The rest is tabdump's princ_meta relation, every column of
	// which upstream derives from tl-data rather than from a
	// struct field.
	ModBy        string `gorm:"size:1024"`
	ModTime      time.Time
	LastPWChange time.Time
	Policy       string `gorm:"size:255"`
	MKVNO        int32
	HistKVNO     int32

	Keys        []Key        `gorm:"constraint:OnDelete:CASCADE"`
	StringAttrs []StringAttr `gorm:"constraint:OnDelete:CASCADE"`
	TLData      []TLDatum    `gorm:"constraint:OnDelete:CASCADE"`
}

// Key is one row of tabdump's keydata relation: one enctype at one
// key version, with its salt.
type Key struct {
	ID uint `gorm:"primaryKey"`

	// PrincipalName is the owning principal, and the field name
	// is GORM's has-many convention -- owner type plus its
	// primary key -- so the association needs no tag of its own.
	PrincipalName string `gorm:"size:1024;index"`

	// KeyIndex is the position within the principal's key list,
	// kept so that a dump reproduces upstream's ordering.
	KeyIndex int32

	KVNO int32 `gorm:"index"`

	// EType is the key's own enctype. It is metadata, not the
	// enctype of Blob's ciphertext -- see decodeKeyBlob.
	EType int32

	// Blob is the stored key material: a 2-byte little-endian
	// true key length followed by the master-key-encrypted key.
	// It is stored in that exact layout rather than as a plain
	// ciphertext column so that an existing KDB can be read and a
	// dump round-trips.
	Blob []byte

	SaltType int32
	Salt     []byte

	// MKVNO is which master key Blob is encrypted under, copied
	// from the principal's tl-data type 8 at write time. Zero
	// means "not recorded", which upstream treats as the lowest
	// loaded master key version.
	MKVNO int32
}

// StringAttr is one row of tabdump's princ_stringattrs relation,
// upstream's tl-data type 0x0b.
type StringAttr struct {
	ID uint `gorm:"primaryKey"`

	// PrincipalName is the owning principal, and the field name
	// is GORM's has-many convention -- owner type plus its
	// primary key -- so the association needs no tag of its own.
	PrincipalName string `gorm:"size:1024;index"`

	Key   string `gorm:"size:255"`
	Value string
}

// TLDatum is a tl-data record that has no column of its own.
//
// Keeping it is what makes dump and load possible: upstream's tl_data
// is an open extensibility list, and a KDB can carry types this
// implementation has never heard of -- PAC logon info, server
// referrals, X.509 subject names. Dropping them on import would
// silently lose data that another KDC put there.
type TLDatum struct {
	ID uint `gorm:"primaryKey"`

	// PrincipalName is the owning principal, and the field name
	// is GORM's has-many convention -- owner type plus its
	// primary key -- so the association needs no tag of its own.
	PrincipalName string `gorm:"size:1024;index"`

	// Type is the tl-data type. At most one record per type
	// exists for a principal, which upstream relies on.
	Type     int32
	Contents []byte
}

// Alias is tabdump's alias relation: a name that resolves to another
// principal. Nothing in the AS exchange follows one yet.
type Alias struct {
	AliasName  string `gorm:"primaryKey;size:1024"`
	TargetName string `gorm:"size:1024"`
}
