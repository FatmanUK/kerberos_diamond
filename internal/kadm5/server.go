// Package kadm5 is the administrative surface: kadmin's operations
// over HTTPS, authenticated with Kerberos and carrying JSON.
//
// # Why it is not kadmin's protocol
//
// Stock kadmin speaks Sun RPC program KADM under RPCSEC_GSS on port
// 749 (ovsec_kadmd.c:155-158), and this will never answer it. Porting
// RPCSEC_GSS and GSS-API would break the TLS-only invariant and is
// larger than everything else left in the project, so the consequence
// is stated plainly rather than discovered: **the kadmin binary does
// not work against this KDC.**
//
// What makes that tolerable is that it was never the whole of
// administration. Split by who does the work:
//
//   - users change passwords with a stock kpasswd and a stock
//     kinit, over the port this KDC already listens on;
//   - services get keys from a keytab kdiamond writes and a stock
//     kinit -k reads;
//   - operators provision principals, and that is this surface.
//
// Upstream's own argument for kadmin existing is that a flat-file
// database can only be edited on its own host. That survives for
// provisioning and never covered the other two.
//
// # Authentication, and the absence of a session
//
// RFC 4559: an unauthenticated request is answered 401 with
// `WWW-Authenticate: Negotiate', and the client retries carrying a
// SPNEGO token. **Every request carries its own**, and there is no
// session, no cookie and nothing remembered between them. That is the
// crash-only rule applied to an HTTP surface -- a request can be
// answered by any process that can reach the database, and a restart
// loses nothing -- and it is also what makes the replay cache
// necessary rather than optional, because an authenticator that is
// good once would otherwise be good forever.
//
// # Why JSON
//
// Nothing here is on the Kerberos wire, so there is no interop
// requirement and no reference encoding to match. And the kadm5
// modify mask (admin.h:88-113) is exactly the presence or absence of
// a field, which a JSON object expresses natively: a key that is
// there is a field being set and a key that is absent is one being
// left alone. The verbs and the field names stay kadmin's so that
// what an operator knows transfers.
package kadm5

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/kdc"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// Server answers the administrative route.
type Server struct {
	// KDC accepts the SPNEGO tokens. The administrative surface
	// borrows the KDC's acceptor rather than having one of its
	// own because the ticket it verifies was issued by that KDC
	// and sealed with a key out of that store.
	KDC *kdc.KDC

	// Store is the database every operation acts on.
	Store *store.Store

	// ACL decides who may do what. A zero ACL permits nothing
	// except what the self module allows, which is upstream's
	// behaviour for an empty kadm5.acl.
	ACL acl.ACL

	// Realm is this realm's name, used to qualify a bare
	// principal in a request the way kadmin does.
	Realm string
}

// Prefix is the route this server is mounted on.
const Prefix = "/kadm5/"

// ServeHTTP routes one request.
//
// The order is deliberate: the method and the verb are checked before
// authentication, so that a client sending nonsense is told what is
// wrong rather than being asked to authenticate first and then told.
// An unknown verb is not a secret.
func (s *Server) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed,
			"only POST is accepted")
		return
	}
	verb := strings.TrimPrefix(r.URL.Path, Prefix)
	op, ok := operations[verb]
	if !ok {
		fail(w, http.StatusNotFound,
			"no such operation: "+verb)
		return
	}
	id, reply, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if reply != "" {
		w.Header().Set("WWW-Authenticate",
			"Negotiate "+reply)
	}
	s.run(w, r, op, id)
}

// run decodes the body, calls the operation and writes the answer.
func (s *Server) run(
	w http.ResponseWriter,
	r *http.Request,
	op operation,
	id *kdc.Identity,
) {
	var body json.RawMessage
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := op(s, r.Context(), &Caller{
		Identity: id,
		ACL:      s.ACL,
		Realm:    s.Realm,
	}, body)
	if err != nil {
		fail(w, statusOf(err), err.Error())
		return
	}
	respond(w, http.StatusOK, out)
}

// decode reads the request body, tolerating an empty one.
//
// An operation that takes no arguments should not oblige a client to
// send `{}', and curl's --negotiate retry sends an empty body on the
// first, unauthenticated attempt in any case.
func decode(r *http.Request, out *json.RawMessage) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body,
		maxBody))
	if err := dec.Decode(out); err != nil {
		*out = json.RawMessage("{}")
	}
	return nil
}

// maxBody bounds a request. Nothing this surface accepts is large;
// the largest is a principal's whole attribute set.
const maxBody = 1 << 20

// respond writes a JSON object.
func respond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// fail writes a JSON error, so that a client has one shape to parse
// whatever happened.
func fail(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}

// base64Token is RFC 4559's encoding of a token, which is standard
// base64 with padding.
var base64Token = base64.StdEncoding
