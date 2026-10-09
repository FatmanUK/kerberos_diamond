package kadm5

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Refusal is the ACL saying no.
//
// It is one error type for every operation because upstream gives one
// answer for all of them -- KADM5_AUTH_* codes that differ only in
// which operation was refused -- and because telling a client *why*
// it was refused tells it about the ACL.
type Refusal struct {
	Op     acl.Op
	Target string
}

// Error says that the operation was refused and nothing more.
func (r *Refusal) Error() string {
	if r.Target == "" {
		return "operation not permitted"
	}
	return fmt.Sprintf("operation not permitted on %q",
		r.Target)
}

// ErrBadRequest is a request this surface cannot make sense of.
var ErrBadRequest = errors.New("malformed request")

// statusOf maps an error to its HTTP status.
//
// The distinction that matters is 401 against 403: a client told 401
// should try to authenticate differently and one told 403 should not,
// because it authenticated perfectly well and simply may not do this.
// Conflating them is how a client ends up in a retry loop against an
// ACL.
func statusOf(err error) int {
	var refusal *Refusal
	switch {
	case errors.As(err, &refusal):
		return http.StatusForbidden
	case errors.Is(err, store.ErrNotFound),
		errors.Is(err, store.ErrPolicyNotFound):
		return http.StatusNotFound
	case errors.Is(err, store.ErrNameInUse),
		errors.Is(err, store.ErrPolicyInUse):
		return http.StatusConflict
	case errors.Is(err, ErrBadRequest),
		errors.Is(err, store.ErrBadPolicyName):
		return http.StatusBadRequest
	}
	if isPolicyError(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// isPolicyError reports an error that is the *request's* fault rather
// than this server's -- a password that fails the quality rules, a
// policy field out of range -- all of which upstream answers with a
// KADM5 code and not a failure.
func isPolicyError(err error) bool {
	for _, e := range []error{
		store.ErrPasswordTooShort,
		store.ErrPasswordTooSimple,
		store.ErrPasswordReuse,
		store.ErrPasswordTooSoon,
		store.ErrBadMinPWLife,
		store.ErrBadPWLength,
		store.ErrBadPWClasses,
		store.ErrBadPWHistory,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// kerberosReason turns a Kerberos error code into a sentence for the
// 401 body.
//
// Only the codes this acceptor actually produces are named. The rest
// fall through to the number, which is more use to an administrator
// than a generic phrase would be: the number can be looked up.
func kerberosReason(code int32) string {
	switch code {
	case wire.ErrCodeRepeat:
		return "the request was replayed"
	case wire.ErrCodeTktExpired:
		return "the ticket has expired"
	case wire.ErrCodeTktNYV:
		return "the ticket is not yet valid"
	case wire.ErrCodeSkew:
		return "the clock skew is too great"
	case wire.ErrCodeBadIntegrity:
		return "the ticket could not be decrypted"
	case wire.ErrCodeServerNoMatch:
		return "the ticket does not name an admin service"
	case wire.ErrCodePolicy:
		return "the negotiation was refused by policy"
	}
	return fmt.Sprintf("authentication failed (krb5 %d)", code)
}
