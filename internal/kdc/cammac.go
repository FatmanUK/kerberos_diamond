package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// UsageCAMMAC keys both of a CAMMAC's checksums
// (KRB5_KEYUSAGE_CAMMAC, krb5.hin:1001).
const UsageCAMMAC crypto.Usage = 64

// cammacFor wraps authorization data in a CAMMAC and then in an
// AD-IF-RELEVANT container, which is the shape an authentication
// indicator travels in (cammac_create, kdc/cammac.c:42-110, reached
// from add_auth_indicators, kdc_authdata.c:300-336).
//
// **Two checksums over two different things**, and the asymmetry is
// the whole design:
//
//   - the KDC verifier is over the DER-encoded EncTicketPart **with
//     these elements substituted as its authorization data**
//     (encode_kdcver_encpart, cammac.c:30-40), keyed with the local
//     krbtgt key. That is self-referential on purpose: it binds the
//     contents to the exact ticket they were issued in, so a CAMMAC
//     lifted from one ticket into another stops verifying. Only a
//     KDC holds that key, so only a KDC can check it -- which is
//     what makes it safe to trust an indicator arriving in a TGT.
//   - the service verifier is over the encoded elements alone, keyed
//     with the **server's** key, so the service that receives the
//     ticket can check it without the krbtgt key.
//
// The IF-RELEVANT wrapper means a service that does not understand
// CAMMAC ignores it rather than failing, which is what lets a realm
// turn indicators on without coordinating with every service.
func (k *KDC) cammacFor(
	elements wire.AuthorizationData,
	part wire.EncTicketPart,
	serverKey []byte,
	serverEType crypto.EncType,
	tgtKey []byte,
	tgtEType crypto.EncType,
	tgtKVNO uint32,
) (wire.AuthDatum, error) {
	var zero wire.AuthDatum
	kdcVer, err := kdcVerifier(elements, part, tgtKey,
		tgtEType, tgtKVNO)
	if err != nil {
		return zero, err
	}
	svcVer, err := svcVerifier(elements, serverKey,
		serverEType)
	if err != nil {
		return zero, err
	}
	der, err := wire.MarshalCAMMAC(wire.CAMMAC{
		Elements:    elements,
		KDCVerifier: kdcVer,
		SvcVerifier: svcVer,
	})
	if err != nil {
		return zero, err
	}
	return relevant(wire.AuthDatum{
		Type: wire.ADCAMMAC, Data: der,
	})
}

// relevant wraps one element in an AD-IF-RELEVANT container.
func relevant(d wire.AuthDatum) (wire.AuthDatum, error) {
	der, err := wire.MarshalAuthorizationData(
		wire.AuthorizationData{d})
	if err != nil {
		return wire.AuthDatum{}, err
	}
	return wire.AuthDatum{
		Type: wire.ADIfRelevant, Data: der,
	}, nil
}

// kdcVerifier checksums the ticket-with-these-elements.
func kdcVerifier(
	elements wire.AuthorizationData,
	part wire.EncTicketPart,
	key []byte,
	etype crypto.EncType,
	kvno uint32,
) (*wire.VerifierMAC, error) {
	der, err := kdcVerPart(elements, part)
	if err != nil {
		return nil, err
	}
	sum, ctype, err := cammacSum(key, etype, der)
	if err != nil {
		return nil, err
	}
	// The enctype is left out, not written: upstream sets it to
	// ENCTYPE_NULL and the encoder omits a zero (cammac.c:51). A
	// verifier that named one would oblige a reader to find a key
	// of exactly that enctype, which is stricter than the kvno
	// already makes it.
	return &wire.VerifierMAC{
		KVNO: kvno,
		MAC:  wire.Checksum{Type: ctype, Checksum: sum},
	}, nil
}

// kdcVerPart is the thing the KDC verifier covers: the reply's own
// EncTicketPart with the CAMMAC's elements in place of its
// authorization data.
func kdcVerPart(
	elements wire.AuthorizationData,
	part wire.EncTicketPart,
) ([]byte, error) {
	field, err := wire.AuthDataField(elements)
	if err != nil {
		return nil, err
	}
	part.AuthorizationData = field
	return wire.MarshalEncTicketPart(part)
}

// svcVerifier checksums the elements alone with the server's key.
//
// No kvno and no enctype, both of which upstream leaves zero
// (cammac.c:66-68): the service knows which of its own keys sealed
// the ticket, so saying it again would add nothing.
func svcVerifier(
	elements wire.AuthorizationData,
	key []byte,
	etype crypto.EncType,
) (*wire.VerifierMAC, error) {
	der, err := wire.MarshalAuthorizationData(elements)
	if err != nil {
		return nil, err
	}
	sum, ctype, err := cammacSum(key, etype, der)
	if err != nil {
		return nil, err
	}
	return &wire.VerifierMAC{
		MAC: wire.Checksum{Type: ctype, Checksum: sum},
	}, nil
}

// cammacSum is the checksum at key usage 64, with the checksum type
// the key's enctype requires.
//
// Upstream passes 0 for the type and lets krb5_c_make_checksum pick
// the enctype's mandatory one (cammac.c:46 and :61), which is what
// RequiredCksum records here.
func cammacSum(
	key []byte,
	etype crypto.EncType,
	msg []byte,
) ([]byte, int32, error) {
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, 0, err
	}
	sum, err := p.Checksum(key, msg, UsageCAMMAC)
	if err != nil {
		return nil, 0, err
	}
	return sum, int32(p.RequiredCksum), nil
}

// addIndicators appends a CAMMAC-wrapped AD-AUTH-INDICATOR to a list
// of authorization data, or leaves it alone when there is nothing to
// say (add_auth_indicators, kdc_authdata.c:300-336).
//
// The server's own flag comes first: a principal with
// KRB5_KDB_NO_AUTH_DATA_REQUIRED gets **neither a PAC nor
// indicators** (handle_pac's first test, :479-481). That is one flag
// turning off everything the KDC would otherwise vouch for, and it
// exists for services that cannot cope with a large ticket.
func (k *KDC) addIndicators(
	ad wire.AuthorizationData,
	ind []string,
	server *store.Principal,
	part wire.EncTicketPart,
	serverKey []byte,
	serverEType crypto.EncType,
) (wire.AuthorizationData, error) {
	if len(ind) == 0 || noAuthData(server) {
		return ad, nil
	}
	der, err := wire.MarshalAuthIndicators(ind)
	if err != nil {
		return nil, err
	}
	tgtKey, tgtEType, tgtKVNO, err := k.localTGT()
	if err != nil {
		return nil, err
	}
	// The CAMMAC's own elements are what the KDC verifier's
	// checksum covers, so the ticket it is computed over must
	// carry *those* and not the list being built -- which
	// kdcVerPart arranges by substituting them.
	wrapped, err := k.cammacFor(wire.AuthorizationData{{
		Type: wire.ADAuthIndicator, Data: der,
	}}, part, serverKey, serverEType, tgtKey, tgtEType,
		tgtKVNO)
	if err != nil {
		return nil, err
	}
	return append(ad, wrapped), nil
}

// noAuthData reports KRB5_KDB_NO_AUTH_DATA_REQUIRED, which this
// project's schema has carried since the beginning and which nothing
// read until now (internal/store/attrs.go).
func noAuthData(p *store.Principal) bool {
	return p != nil &&
		p.Attributes&store.AttrNoAuthDataRequired != 0
}
