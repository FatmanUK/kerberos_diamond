package pac

import (
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// dummyPAC is the single zero octet that stands in for the PAC while
// the ticket checksum is computed.
//
// It has to be *something* rather than nothing, because the checksum
// covers the encoded EncTicketPart and the element's own tag and
// length are part of that -- so the placeholder fixes the shape of
// what will replace it, and only its length may not change. One octet
// is upstream's choice (pac_sign.c:352, pac.c:603) and the two sides
// have to agree on it exactly.
var dummyPAC = []byte{0}

// SignTicket attaches a signed PAC to a ticket as authorization-data
// element [0] (krb5_kdc_sign_ticket, pac_sign.c:366-425).
//
// **It is a two-pass dance, and the reason is circular.** The PAC
// carries a checksum over the ticket, and the ticket carries the PAC,
// so neither can be finished first. Upstream breaks the circle by
// encoding the ticket with a *dummy* PAC of one zero octet, signing
// that, and then swapping the real PAC in -- which works only because
// the dummy's length is fixed by convention and the verifier rebuilds
// the same dummy to check.
//
// The PAC therefore ends up **first** in the authorization-data list,
// ahead of anything a client supplied or a presented ticket carried.
// That is not cosmetic: the verifier finds it by position and by
// container, and re-signing has to reproduce the same order.
func SignTicket(
	enc *wire.EncTicketPart,
	p *PAC,
	server wire.PrincipalName,
	ci *ClientInfo,
	serverKey, privsvrKey wire.EncryptionKey,
) error {
	rest, err := authDataOf(enc)
	if err != nil {
		return err
	}
	list := append(wire.AuthorizationData{
		{Type: wire.ADIfRelevant},
	}, rest...)
	isService := ShouldHaveTicketSignature(server)
	if err := p.ticketSignature(enc, list, isService,
		privsvrKey); err != nil {
		return err
	}
	data, err := p.Sign(ci, serverKey, privsvrKey, isService)
	if err != nil {
		return err
	}
	return setPACElement(enc, list, data)
}

// ticketSignature computes the KRB5_PAC_TICKET_CHECKSUM over the
// ticket encoded with the dummy PAC in place, and is a no-op for the
// two server names that do not get one.
func (p *PAC) ticketSignature(
	enc *wire.EncTicketPart,
	list wire.AuthorizationData,
	isService bool,
	privsvr wire.EncryptionKey,
) error {
	if !isService {
		return nil
	}
	if err := setPACElement(enc, list, dummyPAC); err != nil {
		return err
	}
	der, err := wire.MarshalEncTicketPart(*enc)
	if err != nil {
		return err
	}
	if _, err := p.insert(TypeTicketChecksum,
		privsvr); err != nil {
		return err
	}
	prof, err := cksumProfile(privsvr)
	if err != nil {
		return err
	}
	_, err = p.compute(TypeTicketChecksum, privsvr,
		prof.RequiredCksum, der)
	return err
}

// VerifyTicket checks a presented ticket's PAC before it is re-issued
// (krb5_kdc_verify_ticket, pac.c:593-688).
//
// **An absent PAC is success with no PAC**, not a refusal (:641-645),
// which is what lets a realm that issues none interoperate with one
// that does. The caller decides what to do about the absence; here it
// is simply not an error.
//
// A nil privsvr key skips both the ticket checksum and the KDC's own,
// which is the shape a service verifying its own ticket is in.
func VerifyTicket(
	enc *wire.EncTicketPart,
	server wire.PrincipalName,
	serverKey, privsvrKey wire.EncryptionKey,
) (*PAC, error) {
	list, err := authDataOf(enc)
	if err != nil {
		return nil, err
	}
	at, raw, ok := findPAC(list)
	if !ok {
		return nil, nil
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	isService := ShouldHaveTicketSignature(server)
	if len(privsvrKey.KeyValue) > 0 && isService {
		if err := p.checkTicketSignature(enc, list, at,
			privsvrKey); err != nil {
			return nil, err
		}
	}
	if err := p.Verify(serverKey, privsvrKey,
		isService); err != nil {
		return nil, err
	}
	return p, nil
}

// checkTicketSignature re-encodes the ticket with the PAC replaced by
// the dummy and checks the checksum over that.
//
// The replacement is of the PAC's *contents* inside its container,
// not of the whole element, so everything else in the
// authorization-data list -- including anything else in the same
// AD-IF-RELEVANT -- is covered exactly as it was when the KDC signed.
func (p *PAC) checkTicketSignature(
	enc *wire.EncTicketPart,
	list wire.AuthorizationData,
	at int,
	privsvr wire.EncryptionKey,
) error {
	keep := enc.AuthorizationData
	defer func() { enc.AuthorizationData = keep }()
	zeroed, err := replacePAC(list, at, dummyPAC)
	if err != nil {
		return err
	}
	field, err := wire.AuthDataField(zeroed)
	if err != nil {
		return err
	}
	enc.AuthorizationData = field
	der, err := wire.MarshalEncTicketPart(*enc)
	if err != nil {
		return err
	}
	return p.VerifyTicketChecksum(privsvr, der)
}

// authDataOf reads a ticket's authorization data, treating an absent
// field as an empty list.
func authDataOf(
	enc *wire.EncTicketPart,
) (wire.AuthorizationData, error) {
	if len(enc.AuthorizationData.FullBytes) == 0 {
		return nil, nil
	}
	return wire.AuthDataOf(enc.AuthorizationData)
}

// findPAC locates the AD-IF-RELEVANT container holding an
// AD-WIN2K-PAC, and returns the container's index and the PAC's
// octets.
//
// Only the first such container counts, and a container with no PAC
// in it is skipped rather than ending the search -- which is
// upstream's loop (pac.c:617-640) and matters because a ticket may
// carry several AD-IF-RELEVANT containers for unrelated reasons.
func findPAC(list wire.AuthorizationData) (int, []byte, bool) {
	for i, d := range list {
		if d.Type != wire.ADIfRelevant {
			continue
		}
		inner, err := wire.UnmarshalAuthorizationData(d.Data)
		if err != nil {
			continue
		}
		for _, e := range inner {
			if e.Type == wire.ADWin2KPAC {
				return i, e.Data, true
			}
		}
	}
	return 0, nil, false
}

// replacePAC returns the list with the PAC inside container `at'
// replaced by other contents.
func replacePAC(
	list wire.AuthorizationData,
	at int,
	with []byte,
) (wire.AuthorizationData, error) {
	inner, err := wire.UnmarshalAuthorizationData(list[at].Data)
	if err != nil {
		return nil, err
	}
	for i := range inner {
		if inner[i].Type == wire.ADWin2KPAC {
			inner[i].Data = with
		}
	}
	der, err := wire.MarshalAuthorizationData(inner)
	if err != nil {
		return nil, err
	}
	out := make(wire.AuthorizationData, len(list))
	copy(out, list)
	out[at] = wire.AuthDatum{
		Type: wire.ADIfRelevant, Data: der,
	}
	return out, nil
}

// setPACElement writes the list into the ticket with element [0]
// replaced by an AD-IF-RELEVANT holding a PAC of the given contents.
func setPACElement(
	enc *wire.EncTicketPart,
	list wire.AuthorizationData,
	data []byte,
) error {
	inner, err := wire.MarshalAuthorizationData(
		wire.AuthorizationData{
			{Type: wire.ADWin2KPAC, Data: data},
		})
	if err != nil {
		return err
	}
	out := make(wire.AuthorizationData, len(list))
	copy(out, list)
	out[0] = wire.AuthDatum{
		Type: wire.ADIfRelevant, Data: inner,
	}
	field, err := wire.AuthDataField(out)
	if err != nil {
		return err
	}
	enc.AuthorizationData = field
	return nil
}

// PACElement is the authorization-data element a signed PAC travels
// in: an AD-IF-RELEVANT container holding one AD-WIN2K-PAC.
//
// It is exported because a caller comparing against bytes somebody
// else produced needs the element rather than the PAC, and because
// the container is part of what a verifier matches on.
func PACElement(data []byte) (wire.AuthDatum, error) {
	inner, err := wire.MarshalAuthorizationData(
		wire.AuthorizationData{
			{Type: wire.ADWin2KPAC, Data: data},
		})
	if err != nil {
		return wire.AuthDatum{}, err
	}
	return wire.AuthDatum{
		Type: wire.ADIfRelevant, Data: inner,
	}, nil
}
