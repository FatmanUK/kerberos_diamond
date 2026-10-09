package kdc

import (
	"context"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// requireAuthAttr is the string attribute a service sets to insist
// its clients authenticated a particular way
// (KRB5_KDB_SK_REQUIRE_AUTH, kdb.h:138).
const requireAuthAttr = "require_auth"

// authIndicators extracts the indicators a presented ticket carries,
// keeping only those inside a CAMMAC whose **KDC verifier checks out
// against the local krbtgt key** (get_auth_indicators,
// kdc_authdata.c:338-379).
//
// Everything else in the ticket is ignored, and that is the point: a
// client can put an AD-AUTH-INDICATOR in a ticket -- it is filtered
// out of what a client *supplies*, but a ticket from another realm's
// KDC is not filtered -- and nothing may believe it unless this
// realm's own krbtgt key says so.
//
// **A CAMMAC that fails verification is silently dropped**, not
// refused (:362-363 simply does not extract from it). Copying that
// matters operationally: refusing would break a realm mid-rollover,
// when tickets signed under the previous krbtgt key are still in
// circulation.
func (k *KDC) authIndicators(
	part wire.EncTicketPart,
	tgtKey []byte,
	tgtEType crypto.EncType,
	tgtKVNO uint32,
) []string {
	ad, err := wire.AuthDataOf(part.AuthorizationData)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range cammacsIn(ad) {
		if !k.checkKDCVerifier(c, part, tgtKey,
			tgtEType, tgtKVNO) {
			continue
		}
		out = append(out, indicatorsIn(c.Elements)...)
	}
	return out
}

// cammacsIn finds every CAMMAC in a list, inside an AD-IF-RELEVANT
// container or not -- which is what krb5_find_authdata does (it
// descends into containers looking for a type).
func cammacsIn(ad wire.AuthorizationData) []wire.CAMMAC {
	var out []wire.CAMMAC
	for _, d := range ad {
		switch d.Type {
		case wire.ADCAMMAC:
			if c, err := wire.UnmarshalCAMMAC(
				d.Data); err == nil {
				out = append(out, c)
			}
		case wire.ADIfRelevant:
			inner, err := wire.
				UnmarshalAuthorizationData(d.Data)
			if err == nil {
				out = append(out, cammacsIn(inner)...)
			}
		}
	}
	return out
}

// indicatorsIn reads the AD-AUTH-INDICATOR elements of a verified
// CAMMAC.
func indicatorsIn(ad wire.AuthorizationData) []string {
	var out []string
	for _, d := range ad {
		if d.Type != wire.ADAuthIndicator {
			continue
		}
		ind, err := wire.UnmarshalAuthIndicators(d.Data)
		if err != nil {
			continue
		}
		out = append(out, ind...)
	}
	return out
}

// checkKDCVerifier re-computes the KDC verifier's checksum
// (cammac_check_kdcver, kdc/cammac.c:112-152).
//
// The key version has to match: upstream allows **only the first
// krbtgt key of the version the verifier names** (:122-131), so a
// verifier made under a previous key version is not checked against
// the current one. This KDC holds one key version at a time here, so
// a mismatch is a refusal rather than a second lookup -- which is the
// conservative half of upstream's behaviour and the half that
// matters.
func (k *KDC) checkKDCVerifier(
	c wire.CAMMAC,
	part wire.EncTicketPart,
	key []byte,
	etype crypto.EncType,
	kvno uint32,
) bool {
	v := c.KDCVerifier
	if v == nil || v.KVNO != kvno {
		return false
	}
	// An enctype is checked only when the verifier names one
	// (:127-128).
	if v.EType != 0 && v.EType != int32(etype) {
		return false
	}
	der, err := kdcVerPart(c.Elements, part)
	if err != nil {
		return false
	}
	p, err := crypto.Profile(etype)
	if err != nil {
		return false
	}
	return p.VerifyChecksum(key, der, v.MAC.Checksum,
		UsageCAMMAC) == nil
}

// checkIndicators refuses a ticket whose holder did not authenticate
// the way the server insists on (check_indicators,
// kdc_util.c:861-894).
//
// **Any one of the required indicators is enough**, which reads
// backwards and is upstream's: the attribute is a space-separated
// list and the loop returns success on the first match (:877-883). So
// `require_auth = "otp pkinit"' means *either*, not both -- an
// operator who wanted both would need two services.
func checkIndicators(
	server *store.Principal,
	have []string,
) (int32, string) {
	want := stringAttr(server, requireAuthAttr)
	if want == "" {
		return 0, ""
	}
	for _, w := range strings.Fields(want) {
		for _, h := range have {
			if h == w {
				return 0, ""
			}
		}
	}
	return wire.ErrCodePolicy,
		"REQUIRED AUTH INDICATORS NOT PRESENT"
}

// stringAttr reads one of a principal's string attributes.
func stringAttr(p *store.Principal, key string) string {
	if p == nil {
		return ""
	}
	for _, a := range p.StringAttrs {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// localTGT is the key of this realm's own ticket-granting service,
// which is what signs and checks a CAMMAC's KDC verifier.
//
// Upstream reaches it through get_local_tgt (do_as_req.c:620-626 and
// the TGS equivalent) and passes it down as local_tgt rather than
// using whatever key opened the presented ticket -- and the
// distinction matters on a cross-realm request, where the header
// ticket was sealed by *another* realm's krbtgt. A CAMMAC that
// arrives in a cross-realm TGT therefore does not verify here, and
// should not: this realm never vouched for it.
func (k *KDC) localTGT() (
	key []byte,
	etype crypto.EncType,
	kvno uint32,
	err error,
) {
	name := store.UnparseName(k.Realm,
		[]string{tgsName, k.Realm})
	p, err := k.Store.Lookup(context.Background(), name)
	if err != nil {
		return nil, 0, 0, err
	}
	start := 0
	row, raw, err := k.Store.Key(p, &start, store.AnyEType,
		store.AnySaltType, store.HighestKVNO)
	if err != nil {
		return nil, 0, 0, err
	}
	return raw, crypto.EncType(row.EType),
		uint32(row.KVNO), nil
}
