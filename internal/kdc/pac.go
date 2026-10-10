package kdc

import (
	"errors"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/pac"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// pacPrivsvrEnctype is the string attribute a service sets to ask for
// a privsvr key of a particular enctype
// (KRB5_KDB_SK_PAC_PRIVSVR_ENCTYPE, kdb.h).
const pacPrivsvrEnctype = "pac_privsvr_enctype"

// wantPAC is handle_pac's gate (kdc_authdata.c:477-493), which is
// five separate refusals in the order upstream tests them.
//
// The first one turns off *everything*: a server with
// KRB5_KDB_NO_AUTH_DATA_REQUIRED gets neither a PAC nor
// authentication indicators, which is why addIndicators checks the
// same flag rather than this function being asked about indicators
// too.
//
// `isAS' distinguishes the two exchanges because the question they
// ask is different. An AS request may **decline** a PAC and that is
// honoured; a TGS request may neither decline one nor ask for one
// that was not in the ticket it presented, so what decides it there
// is whether the presented ticket carried a PAC at all.
func (k *KDC) wantPAC(
	server *store.Principal,
	flags wire.Flags,
	isAS bool,
	pa []wire.PAData,
	subject *pac.PAC,
) bool {
	if noAuthData(server) || k.DisablePAC {
		return false
	}
	if flags&wire.FlagAnonymous != 0 {
		return false
	}
	if isAS {
		return includePAC(pa)
	}
	return subject != nil
}

// includePAC reads PA-PAC-REQUEST (include_pac_p,
// kdc_preauth.c:1581-1609).
//
// **The default is a PAC**, three times over: no padata at all means
// one, padata with no PA-PAC-REQUEST in it means one, and a
// PA-PAC-REQUEST that fails to decode *also* means one, because
// upstream initialises its answer to TRUE and only overwrites it on a
// successful decode (:1587 and :1598-1602). So declining is something
// a client has to do correctly on purpose.
//
// A stock kinit sends no PA-PAC-REQUEST at all and gets a PAC by
// default; `kinit --no-request-pac' is how a client declines.
func includePAC(pa []wire.PAData) bool {
	d := findPAData(pa, wire.PAPACRequest)
	if d == nil {
		return true
	}
	want, err := wire.UnmarshalPAPACRequest(d.Value)
	if err != nil {
		return true
	}
	return want
}

// privsvrKey is the key the KDC's own PAC signatures are made with
// (pac_privsvr_key, kdc_util.c:527-558).
//
// Ordinarily it is the local krbtgt's key -- the same key a CAMMAC's
// KDC verifier uses, and for the same reason: only a KDC of this
// realm holds it. A server may ask for a different *enctype* with the
// pac_privsvr_enctype string attribute, and then the key is PRF+ of
// the krbtgt key over "pac_privsvr" -- which keeps it derived from
// the one secret rather than introducing a second.
//
// Nothing in this project sets that attribute, and the store can
// express it, so it is implemented rather than refused: a realm
// imported from an MIT database could carry one.
func (k *KDC) privsvrKey(
	server *store.Principal,
) (wire.EncryptionKey, error) {
	raw, etype, _, err := k.localTGT()
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	key := wire.EncryptionKey{
		KeyType: int32(etype), KeyValue: raw,
	}
	want := stringAttr(server, pacPrivsvrEnctype)
	if want == "" {
		return key, nil
	}
	return derivePrivsvr(key, want)
}

// derivePrivsvr honours pac_privsvr_enctype, deriving a key of the
// named enctype from the krbtgt's with PRF+.
func derivePrivsvr(
	tgt wire.EncryptionKey,
	name string,
) (wire.EncryptionKey, error) {
	etype, ok := crypto.EncTypeByName(name)
	if !ok {
		return wire.EncryptionKey{}, errBadPrivsvrEnctype
	}
	if etype == crypto.EncType(tgt.KeyType) {
		return tgt, nil
	}
	from, err := crypto.Profile(crypto.EncType(tgt.KeyType))
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	to, err := crypto.Profile(etype)
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	raw, err := from.PRFPlus(tgt.KeyValue,
		[]byte("pac_privsvr"), to.KeyLength)
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	return wire.EncryptionKey{
		KeyType: int32(etype), KeyValue: raw,
	}, nil
}

// clientInfoName is the client name a PAC's CLIENT_INFO buffer
// carries: the principal unparsed **without its realm**, unless the
// PAC is for a cross-realm S4U referral.
//
// It cannot be store.UnparseName, and the reason is one line of
// upstream. With KRB5_PRINCIPAL_UNPARSE_NO_REALM the '@' is **not**
// escaped (component_length_quoted, lib/krb5/krb/unparse.c:70-78 and
// copy_component_quoting's REALM_SEP case at :102-106), because
// without a realm separator there is nothing for it to be confused
// with. An enterprise name's interior at sign therefore travels bare,
// and a PAC that escaped it is one a Windows service rejects with
// nothing to say why.
func clientInfoName(
	name wire.PrincipalName,
	realm string,
) string {
	var b strings.Builder
	for i, c := range name.Components {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(escapeComponent(c, realm == ""))
	}
	if realm != "" {
		b.WriteByte('@')
		b.WriteString(escapeComponent(realm, false))
	}
	return b.String()
}

// escapeComponent is upstream's quoting, with noRealm saying whether
// '@' is left alone.
func escapeComponent(s string, noRealm bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '@':
			if !noRealm {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		case '/', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\b':
			b.WriteString(`\b`)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// errBadPrivsvrEnctype is a pac_privsvr_enctype naming something this
// project does not implement. Upstream answers the same way, with a
// message naming the value (kdc_util.c:543-547).
var errBadPrivsvrEnctype = errors.New(
	"invalid pac_privsvr_enctype")
