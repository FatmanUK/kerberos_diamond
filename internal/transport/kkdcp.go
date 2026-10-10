// Package transport carries Kerberos 5 messages over TLS.
//
// There is no cleartext listener: the KDC is an HTTPS server speaking
// MS-KKDCP, and this package holds both halves of that -- the server
// the KDC listens with, and the client kdiamond-proxy forwards with
// on behalf of clients built without a TLS module of their own.
//
// The shape is taken from make_proxy_request
// (lib/krb5/os/sendto_kdc.c:603-656) and service_https_read
// (:1342-1386), which between them are the only specification that
// matters: whatever an unmodified Kerberos 5 client sends and
// accepts.
package transport

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// ContentType is what a KKDCP request and reply carry.
const ContentType = "application/kerberos"

// MessageHandler answers one Kerberos message with another. A
// protocol refusal is a reply, not an error: only a failure to
// produce any reply is an error.
type MessageHandler func(msg []byte) ([]byte, error)

// Handler serves KKDCP requests on one URL path.
type Handler struct {
	// Path is the URL path, without a leading slash, as a
	// client's profile names it in "kdc =
	// https://host:port/<path>".
	Path string

	Handle MessageHandler

	// Log receives one line per rejected request. Nil discards.
	Log *slog.Logger
}

// ServeHTTP answers a KKDCP request.
//
// The checks here are deliberately looser in one direction and
// stricter in another than they first look. Looser: the request's
// Content-Type is not required to match, because what matters is
// whether the body decodes and a client that got the header wrong but
// the body right is still asking a well-formed question. Stricter:
// the method and path are both required, so that a GET to the right
// path is a 405 rather than an attempt to parse an empty body.
func (h *Handler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.URL.Path != "/"+strings.TrimPrefix(h.Path, "/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only",
			http.StatusMethodNotAllowed)
		return
	}
	reply, err := h.answer(r)
	if err != nil {
		h.reject(w, err)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := w.Write(reply); err != nil && h.Log != nil {
		h.Log.Warn("kkdcp: write failed", "err", err)
	}
}

// answer unwraps the request, hands the message to the KDC and wraps
// the reply back up.
func (h *Handler) answer(r *http.Request) ([]byte, error) {
	// The 4-byte prefix and the DER envelope both sit inside the
	// body, so the cap has to allow for them on top of the
	// message.
	body, err := io.ReadAll(
		http.MaxBytesReader(nil, r.Body, wire.MaxFrame+1024))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	pm, err := wire.UnmarshalKDCProxyMessage(body)
	if err != nil {
		return nil, err
	}
	msg, err := wire.Unframe(pm.KerbMessage)
	if err != nil {
		return nil, err
	}
	out, err := h.Handle(msg)
	if err != nil {
		return nil, err
	}
	// The reply's kerb-message carries the length prefix too: the
	// client checks it and drops the connection if it is missing
	// (sendto_kdc.c:1367-1371).
	return wire.MarshalKDCProxyMessage(wire.KDCProxyMessage{
		KerbMessage:  wire.Frame(out),
		TargetDomain: pm.TargetDomain,
	})
}

// reject answers a request the KDC could not be asked.
//
// A malformed envelope is the client's fault and gets 400; anything
// else is ours and gets 500. Neither carries a Kerberos message,
// because there is nothing to put in one: a KRB-ERROR needs a decoded
// request to answer.
func (h *Handler) reject(w http.ResponseWriter, err error) {
	if h.Log != nil {
		h.Log.Warn("kkdcp: rejected", "err", err)
	}
	code := http.StatusInternalServerError
	if errors.Is(err, wire.ErrMalformed) {
		code = http.StatusBadRequest
	}
	http.Error(w, http.StatusText(code), code)
}
