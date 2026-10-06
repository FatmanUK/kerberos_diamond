package transport

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// HealthPath is where the readiness check lives.
//
// It is deliberately not under the KKDCP path: a load balancer has to
// be able to probe a KDC without constructing a Kerberos message, and
// a Kerberos client has to be able to reach the KDC without the probe
// path being special.
const HealthPath = "/healthz"

// Health answers a readiness probe.
//
// Readiness, not liveness. A KDC can only answer a request it can
// look principals up for, so the probe asks the database and reports
// what it finds. The distinction matters behind a load balancer: a
// KDC whose database is unreachable should stop receiving traffic
// *and* stop being killed and restarted, because restarting it will
// not help -- the fault is elsewhere and the process will recover on
// its own when the database returns.
//
// That recovery is the crash-only property worth having: there is no
// cached connection state to repair, so nothing has to be restarted
// to pick the database back up.
type Health struct {
	// Check is what readiness means. Nil is always ready, which
	// is only useful in a test.
	Check func(ctx context.Context) error

	// Timeout bounds one probe. Zero means two seconds, short
	// enough that a probe cannot be what holds a rollout up.
	Timeout time.Duration

	// Log receives one line per failed probe. Nil discards.
	Log *slog.Logger
}

// ServeHTTP answers the probe.
//
// A failure is 503 rather than 500: the request was understood and
// the answer is "not yet", which is what a load balancer acts on. The
// reason is in the body because an operator reading a probe failure
// has nothing else to go on.
func (h *Health) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if h.Check == nil {
		writeHealth(w, http.StatusOK, "ok")
		return
	}
	timeout := h.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(
		r.Context(), timeout)
	defer cancel()

	if err := h.Check(ctx); err != nil {
		if h.Log != nil {
			h.Log.Warn("not ready", "err", err)
		}
		writeHealth(w, http.StatusServiceUnavailable,
			err.Error())
		return
	}
	writeHealth(w, http.StatusOK, "ok")
}

func writeHealth(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body + "\n"))
}
