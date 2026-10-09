package golden

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/kdc"
	"github.com/FatmanUK/kerberos_diamond/internal/spnego"
)

// The gss-sample token flags (appl/gss-sample/gss-misc.h:43-52).
const (
	tokNoop        byte = 1 << 0
	tokContext     byte = 1 << 1
	tokData        byte = 1 << 2
	tokContextNext byte = 1 << 4
)

// gssFramed reads one token in gss-sample's framing: a flags octet,
// then a four-octet big-endian length, then the token (recv_token,
// gss-misc.c:139-186).
func gssFramed(c net.Conn) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0] == 0 {
		return 0, nil, errors.New("v1 framing")
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > 1<<20 {
		return 0, nil, fmt.Errorf("token of %d octets", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

// gssSend writes one token in the same framing.
func gssSend(c net.Conn, flags byte, body []byte) error {
	out := append([]byte{flags, 0, 0, 0, 0}, body...)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)))
	_, err := c.Write(out)
	return err
}

// gssResult is what the acceptor side of one conversation observed.
type gssResult struct {
	// Negotiated is the outcome of accepting the context token.
	Negotiated *kdc.Negotiated

	// Data is the message the client sent after the context was
	// established, which arrives only if the client accepted the
	// AP-REP. That is this test's real assertion -- see
	// TestStockGSSClientSPNEGO.
	Data []byte

	// Err is the first thing that went wrong.
	Err error
}

// serveOneGSS accepts a single gss-sample conversation and drives it
// with this project's acceptor.
//
// It is not a GSS implementation and does not need to be. The
// conversation gss-client runs with -nw -nx -nm is: an empty
// TOKEN_NOOP|TOKEN_CONTEXT_NEXT, the context token, our reply, an
// unwrapped data token, a reply to that, and a closing TOKEN_NOOP.
// Nothing in it needs per-message tokens, which is what makes a real
// GSS initiator usable as an anchor for an acceptor that has none.
func serveOneGSS(
	ln net.Listener,
	k *kdc.KDC,
	out chan<- gssResult,
) {
	var r gssResult
	defer func() { out <- r }()
	c, err := ln.Accept()
	if err != nil {
		r.Err = err
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		flags, body, err := gssFramed(c)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.Err = err
			}
			return
		}
		if done := gssStep(c, k, &r, flags, body); done {
			return
		}
	}
}

// gssStep handles one received token and reports whether the
// conversation is over.
func gssStep(
	c net.Conn,
	k *kdc.KDC,
	r *gssResult,
	flags byte,
	body []byte,
) bool {
	switch {
	case flags&tokContextNext != 0:
		return false
	case flags&tokContext != 0:
		n, kerr := k.AcceptNegotiate(body)
		if kerr != nil {
			r.Err = fmt.Errorf("accepting: %v", kerr)
			return true
		}
		r.Negotiated = n
		r.Err = gssSend(c, tokContext, n.Reply)
		return r.Err != nil
	case flags&tokData != 0:
		r.Data = body
		// Any token satisfies the client's recv_token here
		// because -nm turned off the signature check
		// (gss-client.c:543-560).
		r.Err = gssSend(c, tokData, nil)
		return r.Err != nil
	case flags&tokNoop != 0:
		return true
	}
	return false
}

// spnegoConf is the client configuration for the GSS cases.
//
// The one addition over clientConf is [domain_realm], and it is there
// because of how a GSS hostbased name is resolved rather than
// anything to do with SPNEGO. gss-client's service argument becomes a
// GSS_C_NT_HOSTBASED_SERVICE name, which krb5_sname_to_principal
// turns into service/host -- so asking for `kadmin@admin' asks for
// the principal kadmin/admin, and the realm comes from looking up
// `admin' as though it were a hostname. With no mapping the lookup
// yields the referral realm and the client goes hunting; one line
// settles it, and upstream's own referral test puts the stanza in the
// same place for the same kind of reason.
func spnegoConf(port int) string {
	return clientConf(port) + fmt.Sprintf(`
[domain_realm]
	admin = %s
`, Realm)
}

// gssClientArgs is a gss-client invocation against a host listener.
//
// -nw -nx -nm turn off wrapping, encryption and the message
// signature, which leaves exactly the context establishment plus one
// plaintext data token. The data token is the assertion: gss-client
// only reaches it if gss_init_sec_context returned GSS_S_COMPLETE,
// and with mutual authentication that means it decrypted our AP-REP,
// found its own ctime and cusec echoed in it and accepted the
// acceptor subkey.
func gssClientArgs(port int, extra ...string) []string {
	args := []string{"gss-client", "-port", fmt.Sprint(port)}
	args = append(args, extra...)
	return append(args, HostAlias, "kadmin@admin",
		"a message")
}

// hostListener opens a listener the container can reach.
//
// It binds every interface rather than loopback, because the client
// is in a container and reaches the host through a gateway address
// that is not 127.0.0.1.
func hostListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// TestStockGSSClientSPNEGO is the anchor for the whole of B7a: a real
// GSS-API initiator establishes a SPNEGO context against this
// project's acceptor.
//
// It is the third-party agreement the plan asks for, and it is worth
// being precise about what it proves and what it does not. The token
// gss-client sends is built by upstream's own SPNEGO and Kerberos
// mechanisms -- the NegTokenInit, the mechTypeList, the RFC 2743
// framing, the RFC 4121 token identifier, the AP-REQ and the 0x8003
// authenticator checksum are all its work and none of it is simulated
// here. If this acceptor misread any of them the client would stop.
//
// And the reply is checked by the client, not by this test. With
// mutual authentication -- which gss-client requests by default
// (gss-client.c:684) -- gss_init_sec_context does not complete until
// it has opened the AP-REP, matched the echoed ctime and cusec and
// taken the acceptor subkey. A client that refused the reply never
// sends a data token, so the arrival of one is the assertion.
func TestStockGSSClientSPNEGO(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "spnego", spnegoConf)
	if out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm); err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	ln, port := hostListener(t)
	done := make(chan gssResult, 1)
	go serveOneGSS(ln, diamondOf(t).KDC, done)

	out, err := o.ExecEnv(ctx, env, "",
		gssClientArgs(port, "-spnego", "-nw", "-nx",
			"-nm")...)
	if err != nil {
		t.Fatalf("gss-client failed: %v\n%s", err, out)
	}
	assertGSSAccepted(t, <-done, "a message")
}

// assertGSSAccepted checks the acceptor's side of a conversation.
func assertGSSAccepted(t *testing.T, r gssResult, msg string) {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("the acceptor failed: %v", r.Err)
	}
	if r.Negotiated == nil {
		t.Fatal("no context was established")
	}
	if got := r.Negotiated.Name(); got != UserName+"@"+Realm {
		t.Errorf("authenticated %q", got)
	}
	want := storeName(AdminName)
	got := storeName(r.Negotiated.Service.Components)
	if got != want {
		t.Errorf("service is %q, want %q", got, want)
	}
	if string(r.Data) != msg {
		t.Errorf("the client sent %q, not %q", r.Data, msg)
	}
}

// TestStockGSSClientBareKerberosMech is the same exchange with the
// SPNEGO layer taken away: gss-client -krb5 frames the AP-REQ
// directly under the Kerberos mechanism OID with no NegTokenInit
// around it.
//
// Both shapes have to work because the client picks and the acceptor
// does not. An HTTP client sending `Authorization: Negotiate' may
// send either -- RFC 4559 names SPNEGO but a Kerberos mech token is
// what several clients actually put there -- and upstream dispatches
// on the OID in the framing rather than assuming.
func TestStockGSSClientBareKerberosMech(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "gssbare", spnegoConf)
	if out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm); err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	ln, port := hostListener(t)
	done := make(chan gssResult, 1)
	go serveOneGSS(ln, diamondOf(t).KDC, done)

	out, err := o.ExecEnv(ctx, env, "",
		gssClientArgs(port, "-krb5", "-nw", "-nx", "-nm")...)
	if err != nil {
		t.Fatalf("gss-client failed: %v\n%s", err, out)
	}
	r := <-done
	assertGSSAccepted(t, r, "a message")
	if r.Negotiated.Flags&spnego.FlagMutual == 0 {
		t.Error("mutual authentication was not honoured")
	}
	if r.Negotiated.Subkey == nil {
		t.Error("no acceptor subkey was sent")
	}
}

// TestStockGSSClientWithoutMutualAuth proves the AP-REP is sent
// because the client asked for it and not because this acceptor
// always sends one.
//
// -nomutual clears GSS_C_MUTUAL_FLAG in the 0x8003 checksum, and
// upstream generates no AP-REP at all in that case
// (accept_sec_context.c:989). An acceptor that replied anyway would
// not break this client -- it ignores an unexpected token -- which is
// exactly why the flag has to be read rather than assumed, and why
// this asserts on the acceptor's own side of the exchange.
func TestStockGSSClientWithoutMutualAuth(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "gssnomut", spnegoConf)
	if out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm); err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	ln, port := hostListener(t)
	done := make(chan gssResult, 1)
	go serveOneGSS(ln, diamondOf(t).KDC, done)

	out, err := o.ExecEnv(ctx, env, "",
		gssClientArgs(port, "-spnego", "-nomutual", "-nw",
			"-nx", "-nm")...)
	if err != nil {
		t.Fatalf("gss-client failed: %v\n%s", err, out)
	}
	r := <-done
	assertGSSAccepted(t, r, "a message")
	if r.Negotiated.Flags&spnego.FlagMutual != 0 {
		t.Error("mutual authentication was invented")
	}
	if r.Negotiated.Subkey != nil {
		t.Error("an acceptor subkey was sent anyway")
	}
}
