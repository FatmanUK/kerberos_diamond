package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/pac"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// asAuthData fills in an AS-issued ticket's authorization data:
// authentication indicators, and then the PAC (handle_authdata and
// handle_pac, kdc_authdata.c:566-615 and :456-570).
//
// **The AS exchange carried none at all before this**, and the
// indicator half of that was a real gap rather than an absence. D7
// made SPAKE assert an indicator and D6 made a service able to
// require one, but nothing wrote the indicator into the issued TGT --
// so `require_auth' worked on an AS request naming that server and
// the indicator then vanished, and a *service* could never insist on
// SPAKE because the service ticket's indicators are copied from the
// TGT's. Upstream calls add_auth_indicators from both exchanges
// (:572-574 for the AS path), which is what makes the chain hold.
//
// The order is upstream's and the PAC ends up first regardless,
// because SignTicket prepends it.
func (k *KDC) asAuthData(
	s *asState,
	part *wire.EncTicketPart,
) error {
	ad, err := k.addIndicators(nil, s.indicators, s.server,
		*part, s.serverKey, s.serverEType)
	if err != nil {
		return err
	}
	if len(ad) > 0 {
		field, err := wire.AuthDataField(ad)
		if err != nil {
			return err
		}
		part.AuthorizationData = field
	}
	return k.asPAC(s, part, ad)
}

// asPAC attaches a freshly built PAC to an AS-issued ticket.
//
// It is empty of payload buffers, and that is not a stub: a stock MIT
// KDC emits **no LOGON_INFO buffer at all**, because only its test
// KDB module implements issue_pac (plugins/kdb/test/kdb_test.c:820),
// so with db2 or LDAP the dispatch returns KRB5_PLUGIN_OP_NOTSUPP and
// handle_pac swallows it as success (kdc_authdata.c:507-512). What
// travels is the CLIENT_INFO buffer and the signatures -- which is
// exactly what S4U2Self needs, and S4U2Self is why a payload-free PAC
// is worth issuing at all.
func (k *KDC) asPAC(
	s *asState,
	part *wire.EncTicketPart,
	ad wire.AuthorizationData,
) error {
	if !k.wantPAC(s.server, part.Flags, true,
		s.req.PAData, nil) {
		return nil
	}
	privsvr, err := k.privsvrKey(s.server)
	if err != nil {
		return err
	}
	ci := &pac.ClientInfo{
		AuthTime: part.AuthTime,
		// No realm: an AS-issued PAC is never a cross-realm
		// S4U referral, which is the only case that carries
		// one (handle_pac's with_realm, :533-537).
		Name: clientInfoName(part.CName, ""),
	}
	return pac.SignTicket(part, pac.New(), s.ticketSName, ci,
		wire.EncryptionKey{
			KeyType:  int32(s.serverEType),
			KeyValue: s.serverKey,
		}, privsvr)
}
