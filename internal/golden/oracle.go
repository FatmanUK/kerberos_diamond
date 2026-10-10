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

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
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

	// TgtPassword is what the krbtgt key is set from. kdb5_util
	// create gives krbtgt a *random* key
	// (kadmin/dbutil/kdb5_create.c:441-460), which no independent
	// implementation can reproduce, so realm-setup.sh resets it
	// from this password. That is what lets the harness decrypt
	// the C KDC's tickets and compare the EncTicketPart, where
	// most of what the AS exchange decides actually lives. cpw
	// bumps the key version, so krbtgt sits at kvno 2.
	TgtPassword = "tgtpassword"
	TgtKVNO     = 2

	// ServiceName and ServicePassword are the principal a TGS
	// exchange asks for a ticket to. Its key comes from a
	// password for the same reason krbtgt's does: the harness has
	// to decrypt the ticket the KDC issues, and a key derived
	// from a password is one it can compute.
	ServicePassword = "servicepassword"

	// PeerName is the user-to-user peer: a principal with
	// DISALLOW_SVR set, so an ordinary TGS-REQ naming it is
	// refused and only a user-to-user request can reach it. That
	// is what the mechanism is for -- a user has a password and
	// no keytab, so there is no long-term key to seal a ticket
	// with.
	PeerName     = "peer"
	PeerPassword = "peerpassword"

	// ForeignRealm is a second realm the oracle serves, with a
	// direct trust to Realm in one direction: its users can reach
	// services here. krb5kdc serves both realms in the one
	// container on the one port, which is what lets the
	// cross-realm comparison present the *same* cross TGT to both
	// implementations.
	ForeignRealm   = "FOREIGN.TEST"
	RemoteName     = "remote"
	RemotePassword = "remotepassword"

	// InterRealmPassword is the key the two realms share. The
	// principal is krbtgt/<Realm>@<ForeignRealm> and both
	// databases hold it: the foreign realm so it can issue the
	// cross TGT, this realm so it can verify one. Its default
	// salt is the realm plus the name components, which are the
	// same on both sides, so one password gives one key.
	InterRealmPassword = "interrealmpassword"

	// LocalForeignPassword is the *other* direction of that
	// trust, krbtgt/<ForeignRealm>@<Realm>, which the host-based
	// referral needs and nothing before it did: a client sent
	// from here to there carries a ticket sealed with this key. A
	// separate principal from the one above and so a separate
	// password, so that a bug confusing the two directions cannot
	// hide.
	LocalForeignPassword = "localforeignpassword"

	// ReferralDomain is the DNS domain the oracle's kdc.conf maps
	// to ForeignRealm, and ReferralService a host-based service
	// that exists in that realm alone.
	//
	// The stanza is in kdc.conf and deliberately *not* krb5.conf,
	// which decides whether the referral is exercised at all: the
	// KDC's profile is kdc.conf prepended to the usual file list
	// (add_kdc_config_file, lib/krb5/os/init_os_ctx.c:339-366),
	// so either file reaches it -- but a mapping in krb5.conf
	// would also let the *client* resolve the host's realm
	// itself, and it would then ask the right realm directly and
	// never need a referral. Upstream's own fixture puts it in
	// kdc_conf for that reason (tests/t_referral.py:5-11).
	ReferralDomain      = "referral.test"
	ReferralSvcPassword = "referralsvcpassword"

	// MidRealm and FarRealm are the other two realms the oracle
	// serves, arranged as a hierarchy below Realm so that a path
	// through three of them exists without a [capaths] entry: the
	// hierarchical walk is a convention about names, and it is
	// the only path resolution either side implements.
	//
	// MidLocalPassword is the trust between MidRealm and Realm,
	// and it is the one the Go side needs -- the far end's trust
	// is between two realms only the C serves.
	MidRealm         = "OTHER." + Realm
	FarRealm         = "SUB." + MidRealm
	FarUser          = "far"
	FarPassword      = "farpassword"
	MidLocalPassword = "midlocalpassword"

	// FarTGTPassword and FarMidPassword are the far realm's own
	// krbtgt key and its trust with the middle realm. The Go side
	// needs them only to *be* the far realm, which one
	// differential case does so that the alternate-TGS search can
	// be compared: that search runs at the realm a client asks
	// from, and the realm a client asks from is the far one.
	FarTGTPassword = "fartgtpassword"
	FarMidPassword = "farmidpassword"

	// OraclePort is the port the C KDC listens on *inside* the
	// container, which is fixed by the image. A process in the
	// container reaches it at 127.0.0.1:OraclePort; the host
	// reaches it at Oracle.Addr, which is a freshly chosen port
	// published onto this one.
	OraclePort = 8088

	// ChangePWPassword is the key of kadmin/changepw, the
	// principal a password change authenticates to. Only the Go
	// side needs it: the C realm's own copy is created with a
	// random key by kdb5_util and nothing compares the two.
	ChangePWPassword = "changepwpassword"

	// AdminPassword is the key of kadmin/admin, the principal a
	// remote administrator authenticates to. Only the Go side
	// needs it, for the same reason ChangePWPassword is only
	// needed there.
	AdminPassword = "adminpassword"

	// PreauthName demands pre-authentication; UserName does not.
	// Keeping both means the padata-free single round trip and
	// the PA-ENC-TIMESTAMP path can be exercised separately.
	PreauthName = "preauth"
)

// ServiceName is the service principal's components. It is a var
// rather than a const because a principal name is a list.
var ServiceName = []string{"host", "service.kdiamond.test"}

// ReferralService is the host-based service that exists only in the
// foreign realm, in a domain this realm's KDC maps there.
var ReferralService = []string{"host", "www." + ReferralDomain}

// ChangePWName is the password-change service's components. A stock
// kpasswd gets an initial ticket for it with the user's current
// password and then presents it, which is why the principal has to
// exist before any of that works.
var ChangePWName = []string{"kadmin", "changepw"}

// AdminName is the administrative service's components, which is what
// a GSS initiator asks for a ticket to. Written as the host-based
// pair `kadmin@admin' by a client, because krb5_sname_to_principal
// turns a hostbased GSS name into service/host -- so the second
// component is a hostname as far as the client is concerned, and
// AdminRealmMap exists to tell it which realm that host belongs to.
var AdminName = []string{"kadmin", "admin"}

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
	// host.containers.internal is added so that a client inside
	// the container can reach a listener on the host. That is the
	// direction the end-to-end check needs -- the C client
	// dialling the Go KDC's shim -- and it is not the direction a
	// published port covers.
	run := exec.CommandContext(ctx, "podman", "run", "--rm", "-d",
		"--name", name,
		"--label", oracleLabel,
		"--add-host",
		"host.containers.internal:host-gateway",
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
	return o, o.ready(ctx)
}

// ready waits for the KDC and folds the container's log into the
// error if it never answers. That failure path is the reason this is
// worth having: without the log, a realm that failed to build looks
// exactly like a port that was never published.
func (o *Oracle) ready(ctx context.Context) error {
	if err := o.waitUntilUp(ctx); err != nil {
		logs, _ := exec.Command(
			"podman", "logs", o.name).CombinedOutput()
		o.stop()
		return fmt.Errorf("%w (logs: %s)", err, logs)
	}
	return nil
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

// HostAlias is the name a process inside the container uses to reach
// a listener on the host.
const HostAlias = "host.containers.internal"

// WriteFile puts a file inside the container.
//
// It goes through the shell rather than `podman cp' because the
// content is small, generated, and wanted at a path the image does
// not have -- and because a heredoc is one call rather than a
// temporary file on the host plus a copy.
func (o *Oracle) WriteFile(
	ctx context.Context,
	path, content string,
) error {
	cmd := exec.CommandContext(ctx, "podman", "exec", "-i",
		o.name, "sh", "-c", "cat > "+path)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing %s: %v: %s",
			path, err, out)
	}
	return nil
}

// ExecEnv runs a command inside the container with extra environment.
//
// podman exec starts a process with the *image's* environment and
// does not inherit the entrypoint's, so anything the start-up script
// exported has to be passed again here.
func (o *Oracle) ExecEnv(
	ctx context.Context,
	env []string,
	stdin string,
	args ...string,
) (string, error) {
	full := []string{"exec", "-i"}
	for _, e := range env {
		full = append(full, "-e", e)
	}
	full = append(full, o.name)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "podman", full...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
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

// GoldenEnctypes is the supported_enctypes both halves of the
// comparison are given, which realm-setup.sh writes into the oracle's
// kdc.conf verbatim.
//
// All six, so that every family is in range at all, and in this order
// because the first entry is the enctype every ticket is sealed with.
// If the two lists ever disagree the diff stops being about the
// implementations.
func GoldenEnctypes() store.SupportedEnctypes {
	return store.SupportedEnctypes{
		crypto.AES256CTSHMACSHA384192,
		crypto.AES128CTSHMACSHA256128,
		crypto.AES256CTSHMACSHA196,
		crypto.AES128CTSHMACSHA196,
		crypto.Camellia256CTSCMAC,
		crypto.Camellia128CTSCMAC,
	}
}
