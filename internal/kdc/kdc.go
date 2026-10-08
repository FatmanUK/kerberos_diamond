// Package kdc answers Kerberos requests.
//
// Only the AS exchange is here: a client with no ticket asking for
// one, which is the whole of what a kinit does. The TGS exchange
// reuses internal/wire and internal/crypto and is not yet written.
//
// The upstream spine this follows is dispatch (kdc/dispatch.c:89)
// into process_as_req (kdc/do_as_req.c:470) into
// finish_process_as_req (:194). That last one is a 150-line function
// with a callback continuation; it is split up here rather than
// translated shape-for-shape, so the function names are the map back
// to it.
package kdc

import (
	"errors"
	"fmt"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/hostrealm"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/transit"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Clock is the KDC's source of time, injectable so that a test can
// make an exchange deterministic.
type Clock func() time.Time

// KDC answers requests against a principal store.
type KDC struct {
	Store *store.Store

	// Realm is the one realm this KDC serves.
	Realm string

	// ClockSkew is how far a client's timestamp may be from this
	// host's clock and still be accepted in a PA-ENC-TIMESTAMP.
	ClockSkew time.Duration

	// Now is the clock. Nil means time.Now.
	Now Clock

	// MaxLife and MaxRenewableLife are the realm-wide caps. Zero
	// means no cap, matching realm_maxlife.
	MaxLife          time.Duration
	MaxRenewableLife time.Duration

	// Paths are the configured realm paths, krb5.conf's [capaths]
	// by another spelling. Nil means none, and then every path is
	// decided by the realm-naming hierarchy.
	Paths transit.Paths

	// Hosts is the host-to-realm map, krb5.conf's [domain_realm]
	// by another spelling, and HostBasedServices and
	// NoHostReferral are kdc.conf's keys of those names. All
	// three exist for the host-based referral and have no other
	// reader. An empty Hosts offers none, which is what this KDC
	// did before the map existed.
	Hosts             hostrealm.Map
	HostBasedServices hostrealm.Services
	NoHostReferral    hostrealm.Services
}

// The realm-wide lifetime defaults, from k5-int.h:132-133 by way of
// kdc/main.c:313-319.
const (
	DefaultMaxLife          = 24 * time.Hour
	DefaultMaxRenewableLife = 7 * 24 * time.Hour
)

// ErrNotARequest reports a message that is not one this KDC answers.
var ErrNotARequest = errors.New("not a KDC request")

// realmMaxLife and realmMaxRenewableLife apply the defaults.
func (k *KDC) realmMaxLife() int32 {
	if k.MaxLife <= 0 {
		return int32(DefaultMaxLife / time.Second)
	}
	return int32(k.MaxLife / time.Second)
}

func (k *KDC) realmMaxRenewableLife() int32 {
	if k.MaxRenewableLife <= 0 {
		return int32(DefaultMaxRenewableLife / time.Second)
	}
	return int32(k.MaxRenewableLife / time.Second)
}

func (k *KDC) now() time.Time {
	if k.Now == nil {
		return time.Now()
	}
	return k.Now()
}

// Handle answers one Kerberos message and returns the reply to send.
//
// A protocol refusal comes back as an encoded KRB-ERROR with a nil
// error: a KRB-ERROR *is* the reply, and treating it as a Go error
// would make every caller responsible for turning it back into one.
// Only a failure to produce any reply at all is returned as an error.
func (k *KDC) Handle(msg []byte) ([]byte, error) {
	// The application tag is what distinguishes the two requests
	// -- they are otherwise the same structure -- so the dispatch
	// is on which decoder accepts the message, not on anything
	// inside it.
	if len(msg) > 0 && msg[0] == appTagByte(wire.MsgTGSReq) {
		return k.handleTGS(msg)
	}
	return k.handleAS(msg)
}

// appTagByte is the identifier octet of a constructed [APPLICATION n]
// wrapper, for n below 31.
func appTagByte(n int) byte { return 0x60 | byte(n) }

func (k *KDC) handleAS(msg []byte) ([]byte, error) {
	req, err := wire.UnmarshalASReq(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotARequest, err)
	}
	rep, kerr := k.AS(msg, req)
	if kerr != nil {
		return wire.MarshalKRBError(*kerr)
	}
	return wire.MarshalASRep(*rep)
}

func (k *KDC) handleTGS(msg []byte) ([]byte, error) {
	req, err := wire.UnmarshalTGSReq(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotARequest, err)
	}
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		return wire.MarshalKRBError(*kerr)
	}
	return wire.MarshalTGSRep(*rep)
}

// krbError builds a KRB-ERROR for a refusal.
//
// The client's name is included when it is known, and the text is
// upstream's status string -- the same short uppercase tokens the C
// KDC logs -- so that a transcript from either implementation names
// the same cause.
func (k *KDC) krbError(
	code int32,
	status string,
	cname *wire.PrincipalName,
) *wire.KRBError {
	now := k.now()
	e := &wire.KRBError{
		STime:     now,
		SUsec:     int32(now.Nanosecond() / 1000),
		ErrorCode: code,
		Realm:     k.Realm,
		SName: wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", k.Realm},
		},
		EText: status,
	}
	if cname != nil {
		e.CRealm = k.Realm
		e.CName = cname
	}
	return e
}
