package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// echoHandler answers every message with its bytes reversed, which is
// enough to prove the envelope survived in both directions without
// needing a KDC.
func echoHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		Path: "KdcProxy",
		Handle: func(msg []byte) ([]byte, error) {
			out := make([]byte, len(msg))
			for i := range msg {
				out[i] = msg[len(msg)-1-i]
			}
			return out, nil
		},
	}
}

func post(
	t *testing.T,
	srv *httptest.Server,
	path string,
	body []byte,
) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ContentType)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func proxyBody(t *testing.T, msg []byte) []byte {
	t.Helper()
	b, err := wire.MarshalKDCProxyMessage(wire.KDCProxyMessage{
		KerbMessage:  wire.Frame(msg),
		TargetDomain: "KDIAMOND.TEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKKDCPRoundTrip(t *testing.T) {
	srv := httptest.NewServer(echoHandler(t))
	defer srv.Close()

	msg := []byte{0x6A, 0x03, 0x02, 0x01, 0x05}
	resp := post(t, srv, "/KdcProxy", proxyBody(t, msg))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}
	got := resp.Header.Get("Content-Type")
	if got != ContentType {
		t.Errorf("Content-Type is %q, want %q",
			got, ContentType)
	}
	out, err := readReply(resp)
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	assertReversed(t, out, msg)
}

// The reply's kerb-message must carry the 4-byte prefix: the C client
// checks it against the field length and drops the connection when it
// disagrees (sendto_kdc.c:1367-1371). Omitting it is the first thing
// to suspect when a client rejects a reply, so it is asserted on the
// raw bytes rather than through readReply, which would strip it.
func TestReplyCarriesTheLengthPrefix(t *testing.T) {
	srv := httptest.NewServer(echoHandler(t))
	defer srv.Close()

	msg := bytes.Repeat([]byte{0xAB}, 300)
	resp := post(t, srv, "/KdcProxy", proxyBody(t, msg))
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	pm, err := wire.UnmarshalKDCProxyMessage(body[:n])
	if err != nil {
		t.Fatalf("KDC-PROXY-MESSAGE: %v", err)
	}
	want := []byte{0x00, 0x00, 0x01, 0x2C}
	if !bytes.HasPrefix(pm.KerbMessage, want) {
		t.Errorf("kerb-message starts % X, want % X",
			pm.KerbMessage[:4], want)
	}
}

// target-domain is echoed back, because a client that sent one has no
// reason to be told something else.
func TestTargetDomainIsEchoed(t *testing.T) {
	srv := httptest.NewServer(echoHandler(t))
	defer srv.Close()

	resp := post(t, srv, "/KdcProxy",
		proxyBody(t, []byte{1, 2, 3}))
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	pm, err := wire.UnmarshalKDCProxyMessage(body[:n])
	if err != nil {
		t.Fatal(err)
	}
	if pm.TargetDomain != "KDIAMOND.TEST" {
		t.Errorf("target-domain is %q", pm.TargetDomain)
	}
}

func TestHandlerRejections(t *testing.T) {
	srv := httptest.NewServer(echoHandler(t))
	defer srv.Close()

	cases := []struct {
		name string
		path string
		body []byte
		want int
	}{
		{"wrong path", "/Nope",
			proxyBody(t, []byte{1}), http.StatusNotFound},
		{"not DER", "/KdcProxy",
			[]byte("hello"), http.StatusBadRequest},
		{"no length prefix", "/KdcProxy",
			noPrefixBody(t), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, srv, tc.path, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status %s, want %d",
					resp.Status, tc.want)
			}
		})
	}
}

// noPrefixBody is a well-formed envelope whose kerb-message has no
// length prefix, which is the mistake the field invites.
func noPrefixBody(t *testing.T) []byte {
	t.Helper()
	b, err := wire.MarshalKDCProxyMessage(wire.KDCProxyMessage{
		KerbMessage: []byte{0x6A, 0x03, 0x02, 0x01, 0x05},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGetIsNotAllowed(t *testing.T) {
	srv := httptest.NewServer(echoHandler(t))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/KdcProxy")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status %s, want 405", resp.Status)
	}
	if got := resp.Header.Get("Allow"); got != "POST" {
		t.Errorf("Allow is %q, want POST", got)
	}
}

// tlsConfigOf borrows the test server's own root so the shim verifies
// the certificate rather than skipping the check -- which would leave
// the TLS leg untested in the one test that exists to exercise it.
func tlsConfigOf(srv *httptest.Server) *tls.Config {
	tr := srv.Client().Transport.(*http.Transport)
	return &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs}
}

// The shim is the path a client without a TLS module takes: plain
// Kerberos TCP in, KKDCP over TLS out. This drives the whole chain,
// TLS included, which is the only way to find out whether the two
// halves agree.
func TestShimForwardsOverTLS(t *testing.T) {
	srv := httptest.NewTLSServer(echoHandler(t))
	defer srv.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn := startShim(t, srv, l)
	msg := []byte{1, 2, 3, 4, 5}
	if _, err := conn.Write(wire.Frame(msg)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFramed(conn)
	if err != nil {
		t.Fatalf("ReadFramed: %v", err)
	}
	assertReversed(t, got, msg)

	// A second message on the same connection must work too: the
	// preauth handshake is two round trips and a client reuses
	// the connection for both.
	if _, err := conn.Write(wire.Frame(msg)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFramed(conn); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
}

// startShim runs a Shim against the test server and dials it.
func startShim(
	t *testing.T,
	srv *httptest.Server,
	l net.Listener,
) net.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Shim{
		Client: &Client{
			URL:       srv.URL + "/KdcProxy",
			Realm:     "KDIAMOND.TEST",
			TLSConfig: tlsConfigOf(srv),
			Timeout:   5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
	go s.Serve(ctx, l)

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// assertReversed checks the echo handler's answer came back intact.
func assertReversed(t *testing.T, got, sent []byte) {
	t.Helper()
	if len(got) != len(sent) {
		t.Fatalf("reply is %d bytes, sent %d",
			len(got), len(sent))
	}
	for i := range sent {
		if got[i] != sent[len(sent)-1-i] {
			t.Fatalf("reply is % X", got)
		}
	}
}

// The frame length is attacker-controlled, so it is checked before
// anything is allocated.
func TestReadFramedRefusesAnOversizedFrame(t *testing.T) {
	r := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if _, err := ReadFramed(r); err == nil {
		t.Error("accepted a 4 GiB frame")
	}
}
