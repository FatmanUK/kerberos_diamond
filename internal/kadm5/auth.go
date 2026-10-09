package kadm5

import (
	"net/http"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/kdc"
)

// Caller is who asked, and what they are allowed.
type Caller struct {
	// Identity is the authenticated client.
	*kdc.Identity

	// ACL is the realm's access control list.
	ACL acl.ACL

	// Realm qualifies a bare principal name in a request.
	Realm string
}

// authenticate implements RFC 4559's acceptor half.
//
// Three outcomes. No Authorization header at all is answered 401 with
// a bare `WWW-Authenticate: Negotiate', which is the challenge that
// makes `curl --negotiate -u :' work: curl sends the first request
// unauthenticated, reads the challenge and retries with a token. A
// header carrying a token that does not authenticate is also 401, and
// the challenge is repeated so that a client with another credential
// to try can. Anything else is the caller's.
//
// The reply token is returned rather than written, because it belongs
// on the *successful* response's headers and this function does not
// know yet whether there will be one.
func (s *Server) authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*kdc.Identity, string, bool) {
	token, ok := negotiateToken(r)
	if !ok {
		challenge(w, "authentication required")
		return nil, "", false
	}
	n, kerr := s.KDC.AcceptNegotiate(r.Context(), token)
	if kerr != nil {
		// The Kerberos error code travels in the body. It is
		// the only thing that distinguishes a replayed
		// request from an expired ticket from a client this
		// realm has never heard of, and an administrator
		// debugging one needs to know which.
		challenge(w, kerberosReason(kerr.ErrorCode))
		return nil, "", false
	}
	var reply string
	if len(n.Reply) > 0 {
		reply = base64Token.EncodeToString(n.Reply)
	}
	return n.Identity, reply, true
}

// negotiateToken pulls the token out of an Authorization header.
//
// The scheme is matched case-insensitively because RFC 7235 says
// scheme names are, and clients differ: curl sends `Negotiate' and
// some send `negotiate'. A header with the scheme and no token is
// treated as absent, which is what a client does on the *first*
// request of a conversation it expects to take two.
func negotiateToken(r *http.Request) ([]byte, bool) {
	h := r.Header.Get("Authorization")
	const scheme = "negotiate "
	if len(h) < len(scheme) ||
		!strings.EqualFold(h[:len(scheme)], scheme) {
		return nil, false
	}
	b64 := strings.TrimSpace(h[len(scheme):])
	if b64 == "" {
		return nil, false
	}
	token, err := base64Token.DecodeString(b64)
	if err != nil || len(token) == 0 {
		return nil, false
	}
	return token, true
}

// challenge answers 401 and asks for a Negotiate token.
func challenge(w http.ResponseWriter, why string) {
	w.Header().Set("WWW-Authenticate", "Negotiate")
	fail(w, http.StatusUnauthorized, why)
}

// permit runs the ACL check for one operation on one target.
//
// Two things are folded in here that upstream also folds together
// (auth.c:184-201): the self module is consulted first, so a
// principal may change its own password with no ACL line at all, and
// the restrictions an entry carries come back to be imposed by the
// caller rather than merely checked.
func (c *Caller) permit(
	op acl.Op,
	target string,
) (*acl.Restrictions, error) {
	r, ok := c.ACL.Permits(op, c.Name(), target)
	if !ok {
		return nil, &Refusal{Op: op, Target: target}
	}
	return r, nil
}

// permitSelfOnly is the gate for an operation with no target of its
// own -- listprincs, getpols -- where upstream's self module cannot
// help because there is nothing to compare the client against.
func (c *Caller) permitGlobal(op acl.Op) error {
	if _, ok := c.ACL.Check(op, c.Name(), ""); !ok {
		return &Refusal{Op: op}
	}
	return nil
}

// qualify turns a bare name into a fully qualified one, which is what
// kadmin does and what the ACL matches against.
func (c *Caller) qualify(name string) string {
	if name == "" || strings.Contains(name, "@") {
		return name
	}
	return name + "@" + c.Realm
}

// changepwOnly reports whether this caller arrived on
// kadmin/changepw, which upstream forbids from touching anybody else
// (changepw_not_self, server_stubs.c:345-354).
//
// It belongs here and not in the password-change service, which is
// what B6 got wrong the first time: there the acceptor name
// distinguishes kadmin/admin from kadmin/changepw, and every kpasswd
// request arrives on kadmin/changepw by construction.
func (c *Caller) changepwOnly() bool {
	s := c.Service.Components
	return len(s) == 2 && s[1] == "changepw"
}

// selfOnly refuses a caller that arrived on kadmin/changepw and named
// somebody else.
func (c *Caller) selfOnly(target string) error {
	if c.changepwOnly() && target != c.Name() {
		return &Refusal{Target: target}
	}
	return nil
}
