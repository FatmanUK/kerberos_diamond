package kdc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// changepwName is the instance of the administrative principal a
// password change authenticates to, and the only one this service
// accepts. Upstream names it explicitly when reading the AP-REQ
// (krb5_build_principal then krb5_rd_req, schpw.c:118-130), so a
// ticket for kadmin/admin does not reach it.
const changepwName = "changepw"

// ChangePW answers a password-change frame (RFC 3244 and its
// predecessor), which is upstream's process_chpw_request
// (kadmin/server/schpw.c:34-399).
//
// It is the one administrative operation ordinary users perform, and
// it is reachable by a stock client over this project's only
// transport: krb5's own locate_kpasswd resolves kpasswd_server
// through the same profile machinery as kdc
// (lib/krb5/os/changepw.c:59-88, locate_kdc.c:565-568), so
// `kpasswd_server = https://host/path` goes over MS-KKDCP --
// make_proxy_request wraps any payload at all (sendto_kdc.c:603-659)
// -- and upstream tests exactly that (tests/t_proxy.py:116-193).
//
// Every failure answers the client rather than returning an error.
// That is deliberate and it is upstream's shape too: a result code
// and a sentence are what kpasswd prints, and a client that got
// nothing back would retry.
func (k *KDC) ChangePW(frame []byte) []byte {
	f, err := wire.UnmarshalChangePWFrame(frame)
	if err != nil {
		return k.chpwFailed(nil, wire.KPasswdMalformed,
			"Request was malformed")
	}
	if f.Version != wire.ChangePWVersion1 &&
		f.Version != wire.ChangePWVersionSet {
		return k.chpwFailed(nil, wire.KPasswdBadVersion,
			"Request contained an unknown version")
	}
	id, kerr := k.AcceptAPReq(f.APReq)
	if kerr != nil {
		return k.chpwFailed(nil, wire.KPasswdAuthError,
			"Failed reading application request")
	}
	if len(id.Service.Components) != 2 ||
		id.Service.Components[1] != changepwName {
		return k.chpwFailed(nil, wire.KPasswdAuthError,
			"Not a ticket for the password service")
	}
	code, text := k.changePW(id, f)
	return k.chpwFailed(id, code, text)
}

// changePW opens the sealed half and does the work, returning the
// result a client will read either way.
func (k *KDC) changePW(
	id *Identity,
	f wire.ChangePWFrame,
) (uint16, string) {
	data, code, text := k.openChangePWPriv(id, f.Rest)
	if code != wire.KPasswdSuccess {
		return code, text
	}
	password, target, code, text := changePWTarget(
		id, f.Version, data)
	if code != wire.KPasswdSuccess {
		return code, text
	}
	if code, text := k.authorisePW(id,
		target); code != wire.KPasswdSuccess {
		return code, text
	}
	return k.setPassword(id, target, password)
}

// openChangePWPriv decrypts the KRB-PRIV.
//
// The key is the authenticator's subkey when it sent one and the
// ticket's session key otherwise, which is what upstream's auth
// context does for it. No address is compared, in either direction:
// upstream sets no remote address before reading so that a client
// behind a NAT still works, and explains itself at schpw.c:152-159.
// This project reads no addresses anywhere, so it agrees -- and here
// it agrees on purpose rather than by omission.
func (k *KDC) openChangePWPriv(
	id *Identity,
	rest []byte,
) ([]byte, uint16, string) {
	priv, err := wire.UnmarshalKRBPriv(rest)
	if err != nil {
		return nil, wire.KPasswdMalformed,
			"Failed decoding request"
	}
	key := id.ReplyKey()
	p, err := crypto.Profile(crypto.EncType(key.KeyType))
	if err != nil {
		return nil, wire.KPasswdHardError,
			"Unsupported encryption type"
	}
	plain, err := p.Decrypt(key.KeyValue, priv.EncPart.Cipher,
		crypto.UsageKRBPrivEncPart)
	if err != nil {
		return nil, wire.KPasswdHardError,
			"Failed decrypting request"
	}
	part, err := wire.UnmarshalEncKRBPrivPart(plain)
	if err != nil {
		return nil, wire.KPasswdMalformed,
			"Failed decoding request"
	}
	return part.UserData, wire.KPasswdSuccess, ""
}

// changePWTarget reads the new password and whose it is.
//
// Version 1 carries the password raw and can only change the sender's
// own; the RFC 3244 version carries a ChangePasswdData, in which an
// absent target means the same thing (schpw.c:170-196).
func changePWTarget(
	id *Identity,
	version uint16,
	data []byte,
) (string, string, uint16, string) {
	self := id.Name()
	if version == wire.ChangePWVersion1 {
		return string(data), self, wire.KPasswdSuccess, ""
	}
	c, err := wire.UnmarshalChangePasswdData(data)
	if err != nil {
		return "", "", wire.KPasswdMalformed,
			"Failed decoding ChangePasswdData"
	}
	if c.TargName == nil {
		return string(c.NewPassword), self,
			wire.KPasswdSuccess, ""
	}
	// Setting somebody else's password is an administrative act
	// and the authorisation is the same as kadmin's own cpw --
	// auth(OP_CPW, client, target), kadmin/server/misc.c:51 --
	// which is why the access-control list reaches here at all.
	return string(c.NewPassword),
		store.UnparseName(c.TargRealm,
			c.TargName.Components),
		wire.KPasswdSuccess, ""
}

// setPassword is the change itself, with the one check a self change
// carries: an initial ticket.
//
// Upstream requires TKT_FLG_INITIAL for a self change and answers
// KRB5_KPASSWD_AUTH_INITIAL without one (schpw_util_wrapper,
// kadmin/server/misc.c:24-32). The reason is worth stating because
// the requirement looks like friction: a ticket obtained from a TGT
// proves only that the holder had a TGT, which a stolen credential
// cache also proves, while an initial ticket means a password was
// typed just now.
func (k *KDC) setPassword(
	id *Identity,
	target, password string,
) (uint16, string) {
	ctx := context.Background()
	p, err := k.Store.Lookup(ctx, target)
	if errors.Is(err, store.ErrNotFound) {
		return wire.KPasswdAuthError, "No such principal"
	}
	if err != nil {
		return wire.KPasswdHardError, "Database unavailable"
	}
	code, text := k.checkPolicy(ctx, p, password)
	if code != wire.KPasswdSuccess {
		return code, text
	}
	return k.storePassword(ctx, p, password)
}

// storePassword writes the new keys and everything that moves with
// them.
func (k *KDC) storePassword(
	ctx context.Context,
	p *store.Principal,
	password string,
) (uint16, string) {
	// The history entry is built from the keys that are about to
	// be replaced, so it is written first -- the one ordering
	// constraint here, and the one upstream comments on
	// (svr_principal.c:1270-1271).
	err := k.Store.RecordPasswordHistory(ctx, p)
	if err != nil {
		return wire.KPasswdHardError, "Failed storing history"
	}
	// The key version goes up by one. Note that this replaces the
	// whole key list rather than keeping the old version, so a
	// ticket already issued under the old key stops verifying at
	// once -- which is what keepold exists to avoid, and which a
	// self-service password change has no way to ask for.
	kvno := p.HighestKVNO() + 1
	err = k.Store.SetPassword(p, password, kvno)
	if err != nil {
		return wire.KPasswdHardError, "Failed deriving keys"
	}
	if err := k.Store.SetPasswordExpiry(ctx, p,
		k.now()); err != nil {
		return wire.KPasswdHardError, "Failed setting expiry"
	}
	p.LastPWChange = k.now()
	// And the bit that demanded the change is cleared, which
	// upstream does in the same place (svr_principal.c:1298). A
	// stock kinit found this one: it changed the password and
	// retried the login, and was told the password had expired.
	p.Attributes &^= store.AttrRequiresPWChange
	if err := k.Store.Save(ctx, p); err != nil {
		return wire.KPasswdHardError, "Failed storing keys"
	}
	return wire.KPasswdSuccess, "Password changed"
}

// chpwFailed builds the reply, which has the same shape whether the
// change succeeded or not: a result code and a sentence, sealed in a
// KRB-PRIV behind an AP-REP.
//
// With no identity there is no key to seal with, and then the reply
// is a KRB-ERROR carrying the same two-plus-string blob in its e-data
// and no AP-REP at all (schpw.c:311-349). A client reads the result
// out of either.
func (k *KDC) chpwFailed(
	id *Identity,
	code uint16,
	text string,
) []byte {
	result := wire.MarshalChangePWResult(code, text)
	if id == nil {
		return k.chpwError(result)
	}
	apRep, priv, err := k.chpwSealed(id, result)
	if err != nil {
		return k.chpwError(result)
	}
	out, err := wire.MarshalChangePWFrame(wire.ChangePWFrame{
		// Always version 1, whichever version was asked for.
		Version: wire.ChangePWVersion1,
		APReq:   apRep,
		Rest:    priv,
	})
	if err != nil {
		return k.chpwError(result)
	}
	return out
}

// chpwSealed builds the AP-REP and the KRB-PRIV of a reply.
//
// The two are not sealed with the same key, and working out which is
// which took a stock client telling us. krb5_mk_rep encrypts the
// AP-REP with auth_context->key -- the ticket's **session key** --
// whatever subkey the client sent (mk_rep.c:120), and the client
// decrypts it the same way (rd_rep.c:95). The KRB-PRIV that follows
// is sealed with the client's subkey, but *only* because the AP-REP
// echoed that subkey back: krb5_rd_rep sets both of the client's
// subkey slots from the AP-REP's subkey field (rd_rep.c:113-121), and
// without the echo the client would read the KRB-PRIV with the
// session key instead and report a decrypt failure.
//
// So the echo is load-bearing in a way nothing about the field's
// description suggests, and the symptom of leaving it out is "Decrypt
// integrity check failed" from the client with the server convinced
// it had replied correctly.
//
// The sequence number is the other thing that has to agree with
// itself: the AP-REP's becomes the client's remote_seq_number
// (rd_rep.c:132) and the KRB-PRIV's is then checked against it
// (rd_priv.c:128-133). One value, both places.
func (k *KDC) chpwSealed(
	id *Identity,
	result []byte,
) ([]byte, []byte, error) {
	seq, err := chpwSeqNumber()
	if err != nil {
		return nil, nil, err
	}
	session, err := crypto.Profile(
		crypto.EncType(id.Session.KeyType))
	if err != nil {
		return nil, nil, err
	}
	apRep, err := k.chpwAPRep(id, session, seq)
	if err != nil {
		return nil, nil, err
	}
	reply := id.ReplyKey()
	rp, err := crypto.Profile(crypto.EncType(reply.KeyType))
	if err != nil {
		return nil, nil, err
	}
	priv, err := k.chpwPriv(rp, reply, result, seq)
	if err != nil {
		return nil, nil, err
	}
	return apRep, priv, nil
}

// chpwSeqNumber picks the sequence number both halves of the reply
// carry.
//
// Upstream generates one with krb5_generate_seq_number when the auth
// context asked for sequencing, which the password-change service
// does (schpw.c:106). The top of the range is avoided because
// k5_privsafe_check_seqnum treats 0xFF800000 upwards as ambiguous and
// handles it specially (privsafe.c:241-245); there is no reason to
// send a number that needs that path.
func chpwSeqNumber() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF
	if n == 0 {
		n = 1
	}
	return n, nil
}

// chpwAPRep echoes the client's own clock and its subkey back to it.
//
// The clock echo is what makes the authentication mutual: only a
// holder of the session key could have read the authenticator, and
// krb5_rd_rep refuses the reply outright if either half of the
// timestamp differs (rd_rep.c:106-110). The subkey echo is what
// upstream does when the caller did not ask for a fresh one --
// repl.subkey = auth_context->authentp->subkey (mk_rep.c:106) -- and
// it decides which key the KRB-PRIV after it is read with.
func (k *KDC) chpwAPRep(
	id *Identity,
	p *crypto.EncProfile,
	seq uint32,
) ([]byte, error) {
	part, err := wire.MarshalEncAPRepPart(wire.EncAPRepPart{
		CTime:     id.CTime,
		CUsec:     id.CUsec,
		SubKey:    id.SubKey,
		SeqNumber: seq,
	})
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(id.Session.KeyValue, part,
		crypto.UsageAPRepEncPart)
	if err != nil {
		return nil, err
	}
	return wire.MarshalAPRep(wire.APRep{
		EncPart: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
}

// chpwPriv seals the result.
//
// The s-address is the directional acceptor address, which is what
// upstream falls back to when it cannot tell which interface a
// request arrived on (schpw.c:290) -- and a KDC reached over HTTPS
// never can, because the frame arrives inside an HTTP body and the
// socket beneath belongs to the transport. The client never compares
// it (changepw.c:166 sets no remote address), so it has only to be
// present.
func (k *KDC) chpwPriv(
	p *crypto.EncProfile,
	key wire.EncryptionKey,
	result []byte,
	seq uint32,
) ([]byte, error) {
	part, err := wire.MarshalEncKRBPrivPart(
		wire.EncKRBPrivPart{
			UserData:  result,
			SAddress:  wire.DirectionalAccept(),
			SeqNumber: seq,
		})
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(key.KeyValue, part,
		crypto.UsageKRBPrivEncPart)
	if err != nil {
		return nil, err
	}
	return wire.MarshalKRBPriv(wire.KRBPriv{
		EncPart: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
}

// chpwError is the unauthenticated reply: a KRB-ERROR from
// kadmin/changepw with the result in its e-data, and an AP-REQ length
// of zero so the client knows which it got.
func (k *KDC) chpwError(result []byte) []byte {
	now := k.now()
	e := &wire.KRBError{
		STime:     now,
		SUsec:     int32(now.Nanosecond() / 1000),
		ErrorCode: wire.ErrCodeGeneric,
		Realm:     k.Realm,
		SName: wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{adminName, changepwName},
		},
		EData: result,
	}
	der, err := wire.MarshalKRBError(*e)
	if err != nil {
		return nil
	}
	out, err := wire.MarshalChangePWFrame(wire.ChangePWFrame{
		Version: wire.ChangePWVersion1,
		Rest:    der,
	})
	if err != nil {
		return nil
	}
	return out
}

// checkPolicy runs the two constraints a self-service change is
// subject to: the quality rules of whatever policy the principal
// names, and the minimum time since its last change.
//
// Both answer KRB5_KPASSWD_SOFTERROR, which is the code that tells a
// client the password was *rejected* rather than that something went
// wrong -- upstream maps every PASS_Q_* and PASS_TOOSOON to it
// (schpw.c:246-273), and kpasswd prints the string beside it. So the
// sentence matters: it is the only thing telling a user what to type
// instead.
func (k *KDC) checkPolicy(
	ctx context.Context,
	p *store.Principal,
	password string,
) (uint16, string) {
	if password == "" {
		return wire.KPasswdSoftError,
			"An empty password is not accepted"
	}
	err := k.Store.CheckPassword(ctx, p, password)
	if err != nil {
		if errors.Is(err, store.ErrPasswordTooShort) ||
			errors.Is(err, store.ErrPasswordTooSimple) {
			return wire.KPasswdSoftError, err.Error()
		}
		return wire.KPasswdHardError, "Policy unavailable"
	}
	err = k.Store.CheckMinPasswordLife(ctx, p, k.now())
	if errors.Is(err, store.ErrPasswordTooSoon) {
		return wire.KPasswdSoftError, err.Error()
	}
	if err != nil {
		return wire.KPasswdHardError, "Policy unavailable"
	}
	err = k.Store.CheckPasswordReuse(ctx, p, password)
	if errors.Is(err, store.ErrPasswordReuse) {
		return wire.KPasswdSoftError, err.Error()
	}
	if err != nil {
		return wire.KPasswdHardError, "History unavailable"
	}
	return wire.KPasswdSuccess, ""
}

// authorisePW decides whether this client may set this target's
// password, which is the one place in the protocol where the
// access-control list is consulted.
//
// Two rules, and they are schpw_util_wrapper's own
// (kadmin/server/misc.c:13-57). A change of one's *own* password
// needs an initial ticket, and that requirement is what makes it mean
// something: a ticket obtained from a TGT proves only that the holder
// had a TGT, which a stolen credential cache also proves
// (check_self_keychange, server_stubs.c:369-381). Anybody else's
// needs the c privilege in the list, and no initial ticket -- because
// an administrator is not proving who they are to the password
// service, they are proving they are an administrator.
//
// Note what does *not* belong here. changepw_not_self
// (server_stubs.c:345-354) forbids a client that arrived on
// kadmin/changepw from touching another principal, and it is a rule
// of the *RPC* surface rather than of this one: there the acceptor
// name distinguishes kadmin/admin from kadmin/changepw, while here
// every request arrives on kadmin/changepw by construction. Putting
// it here would make RFC 3244 set-password impossible, which was the
// first draft's mistake.
func (k *KDC) authorisePW(
	id *Identity,
	target string,
) (uint16, string) {
	client := id.Name()
	if client == target {
		if !id.Initial {
			return wire.KPasswdInitialNeeded,
				"Your own password needs an " +
					"initial ticket"
		}
		return wire.KPasswdSuccess, ""
	}
	if _, ok := k.AdminACL.Permits(acl.CPW, client,
		target); !ok {
		return wire.KPasswdAccessDenied,
			"Not authorised to set that password"
	}
	return wire.KPasswdSuccess, ""
}
