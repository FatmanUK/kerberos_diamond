package golden

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"
)

// OracleImage is the container holding Kerberos 5 built from the C
// sources in the kerberos submodule. `make golden-build' makes it.
const OracleImage = "localhost/krb5-oracle"

// oraclePort is the port the C KDC listens on inside its container.
const oraclePort = 8088

// The realm the oracle image creates at start-up. These must match
// the defaults in deploy/golden/Containerfile.krb5: the harness needs
// the principals' names and passwords to drive the exchange, and the
// C side needs them to answer it.
const (
	Realm        = "KDIAMOND.TEST"
	MasterPass   = "master"
	UserName     = "user"
	UserPassword = "userpassword"

	// PreauthName demands pre-authentication; UserName does not.
	// Keeping both means the padata-free single round trip and
	// the PA-ENC-TIMESTAMP path can be exercised separately.
	PreauthName = "preauth"
)

// Oracle is a running C KDC.
type Oracle struct {
	// Addr is the host address its TCP listener is published on.
	Addr string

	name string
}

// WithOracle starts a C KDC, runs fn against it, and tears it down.
//
// The realm is created inside the container at start-up rather than
// baked into the image, so every run begins from an identical,
// empty-of-history database without the harness having to manage a
// fixture directory.
func WithOracle(
	ctx context.Context,
	fn func(*Oracle) error,
) error {
	o, err := startOracle(ctx)
	if err != nil {
		return err
	}
	defer o.stop()
	return fn(o)
}

// startOracle runs the container and waits for the KDC to listen.
func startOracle(ctx context.Context) (*Oracle, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("krb5gold-%d", port)

	// --rm so a crashed run leaves nothing behind; the container
	// is also removed explicitly, in case the KDC does not exit.
	publish := fmt.Sprintf(
		"127.0.0.1:%d:%d", port, oraclePort)
	run := exec.CommandContext(ctx, "podman", "run", "--rm", "-d",
		"--name", name,
		"--label", oracleLabel,
		"-p", publish,
		OracleImage,
	)
	if out, err := run.CombinedOutput(); err != nil {
		return nil, fmt.Errorf(
			"starting the oracle: %v: %s", err, out)
	}

	o := &Oracle{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		name: name,
	}
	if err := o.waitUntilUp(ctx); err != nil {
		logs, _ := exec.Command(
			"podman", "logs", name).CombinedOutput()
		o.stop()
		return nil, fmt.Errorf("%w (logs: %s)", err, logs)
	}
	return o, nil
}

// oracleLabel marks every container this harness starts, so a stale
// one can be found and removed without guessing at names.
const oracleLabel = "kdiamond-golden=1"

// stop removes the container, ignoring the error: it is called from a
// defer, and a container that is already gone is the wanted state.
func (o *Oracle) stop() {
	_ = exec.Command("podman", "rm", "-f", o.name).Run()
}

// SweepOracles removes every container this harness has left running.
//
// `podman run --rm' only cleans up a container that *stops*, and a
// test binary killed outright -- SIGPIPE from a closed pipe is the
// easy way to do it, SIGKILL the other -- never reaches its cleanup,
// so the KDC keeps running and holds its published port. Sweeping
// before a run is what stops those accumulating.
func SweepOracles() error {
	out, err := exec.Command("podman", "ps", "-aq",
		"--filter", "label="+oracleLabel).Output()
	if err != nil {
		return err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{"rm", "-f"}, ids...)
	return exec.Command("podman", args...).Run()
}

// waitUntilUp blocks until the KDC answers a request.
//
// It must be an answer and not merely an accepted connection.
// Podman's rootless port forwarder binds the published host port as
// soon as the container is created, so dialling it succeeds
// immediately and proves nothing: the realm still has to be built --
// a database, a stash file and two principals -- before the KDC is
// even started, and a request arriving in that window is answered
// with a connection reset by the forwarder.
//
// The probe is the same malformed frame the liveness test uses, so
// readiness is established by the whole path the harness depends on.
func (o *Oracle) waitUntilUp(ctx context.Context) error {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		reply, err := o.SendFramed(ctx, tooLongFrame)
		if err == nil && len(reply) > 0 &&
			reply[0] == tagKrbError {
			return nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	if last != nil {
		return fmt.Errorf(
			"the oracle's KDC never answered: %w", last)
	}
	return errors.New("the oracle's KDC never answered")
}

// tooLongFrame is a length prefix of 0xFFFFFFFF with no message
// behind it. The KDC cannot honour a length that large, so it answers
// KRB_ERR_FIELD_TOOLONG -- which makes this the cheapest possible
// proof that it is alive and speaking Kerberos, needing no encoder of
// our own. Upstream probes its own KDC the same way, in
// kdc/t_bigreply.py.
var tooLongFrame = []byte{0xFF, 0xFF, 0xFF, 0xFF}

// tagKrbError is [APPLICATION 30] constructed, the outermost DER tag
// of a KRB-ERROR.
const tagKrbError = 0x7E

// Exec runs a command inside the oracle's container.
//
// The container holds the realm's configuration and keytab, so a
// client run this way needs no arguments to find them. Output is
// returned with stderr folded in, which is what a transcript wants.
func (o *Oracle) Exec(
	ctx context.Context,
	args ...string,
) (string, error) {
	full := append([]string{"exec", o.name}, args...)
	out, err := exec.CommandContext(
		ctx, "podman", full...).CombinedOutput()
	return string(out), err
}

// Kinit obtains a TGT inside the container, with the password on
// standard input, and returns the transcript.
func (o *Oracle) Kinit(
	ctx context.Context,
	princ, password string,
) (string, error) {
	return o.kinit(ctx, princ, password, false)
}

// KinitTraced is Kinit with KRB5_TRACE on, so the transcript says
// which transport was used and whether the client pre-authenticated.
//
// The trace is how a test can tell a one-round-trip exchange from a
// two-round-trip one, which the exit status cannot.
func (o *Oracle) KinitTraced(
	ctx context.Context,
	princ, password string,
) (string, error) {
	return o.kinit(ctx, princ, password, true)
}

func (o *Oracle) kinit(
	ctx context.Context,
	princ, password string,
	trace bool,
) (string, error) {
	full := []string{"exec", "-i"}
	if trace {
		full = append(full, "-e", "KRB5_TRACE=/dev/stderr")
	}
	full = append(full, o.name, "kinit", princ+"@"+Realm)

	cmd := exec.CommandContext(ctx, "podman", full...)
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// SendRaw sends one message to the C KDC over TCP and returns the
// reply.
//
// Kerberos' TCP framing is a 4-byte big-endian length followed by the
// message, in both directions. The length is written here rather than
// by the caller so that a caller holding a bare DER message cannot
// forget it.
func (o *Oracle) SendRaw(
	ctx context.Context,
	msg []byte,
) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(
			time.Now().Add(10 * time.Second))
	}

	var framed []byte
	framed = binary.BigEndian.AppendUint32(
		framed, uint32(len(msg)))
	if _, err := conn.Write(append(framed, msg...)); err != nil {
		return nil, err
	}
	return readFramed(conn)
}

// SendFramed sends bytes exactly as given, length prefix included,
// and returns the reply's payload.
//
// This exists for the cases where the prefix is the thing under test
// and so must be allowed to lie about the message's length.
func (o *Oracle) SendFramed(
	ctx context.Context,
	framed []byte,
) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	return readFramed(conn)
}

// maxReply bounds a reply, so a wrong length prefix cannot make the
// harness allocate without limit.
const maxReply = 1 << 20

// readFramed reads one length-prefixed message.
func readFramed(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxReply {
		return nil, fmt.Errorf(
			"reply length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// freePort asks the kernel for an unused port.
//
// There is an unavoidable gap between closing this listener and the
// container binding the port. Nothing portable closes it, and the
// alternative -- letting Podman choose and parsing it back out -- is
// slower and no more reliable.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
