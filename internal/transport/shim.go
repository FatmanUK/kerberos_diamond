package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// Shim accepts plain Kerberos TCP and forwards each message to a KDC
// over KKDCP.
//
// It exists because reaching an https:// KDC needs a TLS module the
// client was built with, and Kerberos 5's is an OpenSSL-dependent
// plugin. A client without one points at a Shim on its own host and
// needs no TLS support of its own.
//
// Be straight about what this proves and does not: the hop into the
// Shim is cleartext loopback, so an exchange driven through it
// demonstrates that an unmodified client interoperates with the Go
// KDC, not that the client negotiated the TLS itself.
type Shim struct {
	Client *Client

	// Timeout bounds one connection, read and write together.
	Timeout time.Duration

	// Log receives one line per failed connection. Nil discards.
	Log *slog.Logger
}

// Serve accepts connections until the listener is closed.
func (s *Shim) Serve(ctx context.Context, l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConn(ctx, conn)
	}
}

// serveConn answers every message on one connection.
//
// A client may send more than one request down a single connection --
// the preauth handshake is two -- so this loops until the peer stops
// rather than closing after the first reply.
func (s *Shim) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	for {
		if s.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(s.Timeout))
		}
		msg, err := ReadFramed(conn)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			s.warn("shim: read failed", err)
			return
		}
		reply, err := s.Client.Send(ctx, msg)
		if err != nil {
			s.warn("shim: forward failed", err)
			return
		}
		_, err = conn.Write(wire.Frame(reply))
		if err != nil {
			s.warn("shim: write failed", err)
			return
		}
	}
}

func (s *Shim) warn(msg string, err error) {
	if s.Log != nil {
		s.Log.Warn(msg, "err", err)
	}
}

// ReadFramed reads one length-prefixed Kerberos message.
//
// The length is checked against wire.MaxFrame before anything is
// allocated, because the prefix is attacker-controlled and the C's
// own listener refuses an oversized one for the same reason
// (net-server.c:1391).
func ReadFramed(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > wire.MaxFrame {
		return nil, fmt.Errorf(
			"%w: frame claims %d bytes, limit is %d",
			wire.ErrMalformed, n, wire.MaxFrame)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
