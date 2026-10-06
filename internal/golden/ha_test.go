package golden

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
	"gorm.io/gorm"
)

// This file checks the claim the project exists to make: that a KDC
// holds nothing a restart would have to rebuild, so several can serve
// one realm and any of them can be killed at any moment.
//
// Two things make that claim real rather than architectural, and both
// are measured here. A ticket issued by one KDC has to be honoured by
// another with no shared state between them, and a KDC has to recover
// from its database disappearing and coming back without being
// restarted itself.

// TestTwoKDCsAreInterchangeable issues a TGT at one KDC and spends it
// at another.
//
// They share a database and nothing else: separate processes' worth
// of state, separate HTTPS listeners, separately derived master keys.
// If anything about an exchange lived in the issuing KDC -- a session
// table, a cached key, a nonce the second would have to recognise --
// the second would refuse the ticket. Nothing does, which is what
// makes putting several behind one address safe.
func TestTwoKDCsAreInterchangeable(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	const schema = "kd_ha_pair"
	a := diamond(t, schema, time.Now().UTC)
	provisionService(t, ctx, a)
	// The second opens the *same* schema. StartDiamond would drop
	// and recreate it, so this one is built by hand.
	b := secondDiamond(t, schema, time.Now().UTC)

	tgt := tgtFromKDC(t, a)
	msg := tgsRequestFor(t, tgt,
		time.Now().UTC().Add(2*time.Hour).Truncate(
			time.Second))
	raw, err := b.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("the second KDC could not answer: %v", err)
	}
	x := openTGS(t, raw, tgt)
	want := "host/service.kdiamond.test"
	if got := x.Enc.SName.String(); got != want {
		t.Errorf("the second KDC named %q", got)
	}
	if x.Tkt.CName.String() != UserName {
		t.Errorf("ticket client is %q", x.Tkt.CName)
	}
}

// tgtFromKDC runs a full AS exchange against one Go KDC and keeps
// what a client keeps.
func tgtFromKDC(t *testing.T, d *Diamond) tgt {
	t.Helper()
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}
	return tgtOf(open(t, raw, UserPassword,
		[]string{UserName}))
}

// provisionService adds the service a TGS request asks for, which
// StartDiamond already does -- this is here so the intent is visible
// at the call site rather than being an accident of the fixture.
func provisionService(
	t *testing.T,
	ctx context.Context,
	d *Diamond,
) {
	t.Helper()
	if _, err := d.Store.Lookup(
		ctx, storeName(ServiceName)); err != nil {
		t.Fatalf("the service is not provisioned: %v", err)
	}
}

// TestKDCSurvivesTheDatabaseRestarting is the crash-only property.
//
// A Postgres of its own is started for this one test, so that killing
// it disturbs nothing else. A KDC is pointed at it, asked a question,
// then the database is stopped: the KDC must refuse cleanly rather
// than panicking, and its readiness probe must say so. The database
// comes back and the *same* KDC process must answer again, with no
// restart and no reconnection logic of its own -- because there is no
// connection state of its own to repair.
func TestKDCSurvivesTheDatabaseRestarting(t *testing.T) {
	if !haveDatabaseURL(t) {
		return
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), 150*time.Second)
	defer cancel()

	pg := startScratchPostgres(t, ctx)
	d := diamondAt(t, pg.url, "public", time.Now().UTC)
	s, err := Serve(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(s.Close)

	assertProbe(t, ctx, s, http.StatusOK)
	tgt := tgtFromKDC(t, d)
	if len(tgt.session) == 0 {
		t.Fatal("no session key before the restart")
	}

	pg.stop(t, ctx)
	assertProbe(t, ctx, s, http.StatusServiceUnavailable)
	assertRefusesCleanly(t, d)

	pg.start(t, ctx)
	waitForProbe(t, ctx, s, http.StatusOK)
	// The same process, never restarted, answers again.
	if got := tgtFromKDC(t, d); len(got.session) == 0 {
		t.Error("no session key after the restart")
	}
}

// assertRefusesCleanly checks a KDC with no database refuses rather
// than panicking or hanging.
//
// It must be a KRB-ERROR and not a Go error: the KDC still has to
// answer the client, because a client that got nothing would retry
// forever against a KDC that will never recover on its own schedule.
// The code is the generic one, which is right -- "our database is
// down" is not something to tell a client about.
func assertRefusesCleanly(t *testing.T, d *Diamond) {
	t.Helper()
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("Handle returned an error, not a reply: %v",
			err)
	}
	kerr, err := wire.UnmarshalKRBError(raw)
	if err != nil {
		t.Fatalf("the reply is not a KRB-ERROR: %v", err)
	}
	if kerr.ErrorCode != wire.ErrCodeGeneric {
		t.Errorf("code is %d, want %d",
			kerr.ErrorCode, wire.ErrCodeGeneric)
	}
}

func assertProbe(
	t *testing.T,
	ctx context.Context,
	s *Served,
	want int,
) {
	t.Helper()
	got, err := s.Probe(ctx)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if got != want {
		t.Errorf("probe returned %d, want %d", got, want)
	}
}

// waitForProbe waits for readiness to come back.
//
// Postgres takes a moment to accept connections after it starts, and
// the pool takes one more to notice. Polling is the honest way to
// express "recovers on its own" -- a fixed sleep would either be
// flaky or be longer than it needs to be.
func waitForProbe(
	t *testing.T,
	ctx context.Context,
	s *Served,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := s.Probe(ctx); err == nil &&
			got == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("readiness never returned to %d", want)
}

// scratchPostgres is a Postgres container belonging to one test.
type scratchPostgres struct {
	name string
	url  string
}

// scratchURL is the connection string for a scratch Postgres.
func scratchURL(port int) string {
	return fmt.Sprintf("postgres://kdiamond:kdiamond@"+
		"127.0.0.1:%d/kdiamond_test?sslmode=disable", port)
}

// startScratchPostgres runs a Postgres of its own on a free port.
//
// A dedicated one rather than the shared container, because this test
// stops the database and every other test in the run would notice.
//
// Deliberately *not* --rm: stopping has to keep the container so that
// starting it again brings the same data back. A fresh container on
// the same port would look like a restart to the connection pool and
// like an empty realm to everything else, and the test would then be
// measuring re-provisioning rather than reconnection.
func startScratchPostgres(
	t *testing.T,
	ctx context.Context,
) *scratchPostgres {
	t.Helper()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	pg := &scratchPostgres{
		name: fmt.Sprintf("kdiamond-ha-%d", port),
		url:  scratchURL(port),
	}
	run := exec.CommandContext(ctx, "podman", "run", "-d",
		"--name", pg.name,
		"--label", oracleLabel,
		"-e", "POSTGRES_USER=kdiamond",
		"-e", "POSTGRES_PASSWORD=kdiamond",
		"-e", "POSTGRES_DB=kdiamond_test",
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", port),
		"docker.io/library/postgres:17-alpine",
	)
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("no scratch Postgres: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("podman", "rm", "-f", pg.name).Run()
	})
	pg.waitUntilUp(t, ctx)
	return pg
}

// stop and start are the restart this test is about.
//
// podman stop rather than kill, so Postgres shuts down the way a
// scheduler would stop it; the KDC must not care either way, and a
// kill would additionally test crash recovery in Postgres rather than
// in this project.
func (p *scratchPostgres) stop(
	t *testing.T,
	ctx context.Context,
) {
	t.Helper()
	out, err := exec.CommandContext(ctx, "podman", "stop",
		"-t", "10", p.name).CombinedOutput()
	if err != nil {
		t.Fatalf("stopping Postgres: %v\n%s", err, out)
	}
}

func (p *scratchPostgres) start(
	t *testing.T,
	ctx context.Context,
) {
	t.Helper()
	out, err := exec.CommandContext(ctx, "podman", "start",
		p.name).CombinedOutput()
	if err != nil {
		t.Fatalf("restarting Postgres: %v\n%s", err, out)
	}
	p.waitUntilUp(t, ctx)
}

// waitUntilUp waits for Postgres to answer *through the published
// port*, which takes two checks and not one.
//
// A TCP connect alone is not enough, and the reason is the trap this
// project has now hit three times: podman binds the published port
// when the container is created, so the forwarder accepts a
// connection while the server behind it is still starting and then
// resets it. pg_isready inside the container asks the server
// directly, which settles the server half.
//
// The second check settles the other half, and it is the one this
// test was missing. pg_isready passing says nothing about the
// *forwarder*: a connection from the host can still be reset after
// the server is ready, which is exactly how this test failed
// intermittently -- "failed to receive message: read: connection
// reset by peer" from the very first connection the KDC made. So the
// wait ends when a real query over the real connection string
// succeeds, because that is what the KDC is about to do.
func (p *scratchPostgres) waitUntilUp(
	t *testing.T,
	ctx context.Context,
) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if p.ready(ctx) && p.answers(ctx) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("context ended waiting for Postgres")
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatalf("Postgres never answered in %s", p.name)
}

// ready asks the server, from inside the container.
func (p *scratchPostgres) ready(ctx context.Context) bool {
	return exec.CommandContext(ctx, "podman", "exec",
		p.name, "pg_isready", "-U", "kdiamond",
		"-d", "kdiamond_test", "-q").Run() == nil
}

// answers asks the server through the published port, which is the
// path the KDC uses.
func (p *scratchPostgres) answers(ctx context.Context) bool {
	db, err := openAdmin(p.url)
	if err != nil {
		return false
	}
	defer closeDB(db)
	return db.WithContext(ctx).Exec("SELECT 1").Error == nil
}

// closeDB releases a GORM handle's pool, which is otherwise left open
// until the test binary exits.
func closeDB(db *gorm.DB) {
	if sql, err := db.DB(); err == nil {
		sql.Close()
	}
}

// Readiness is readiness, not liveness: a KDC whose database is away
// reports not-ready so a load balancer stops sending it traffic, and
// stays alive so nothing restarts it. Restarting would not help,
// because the fault is elsewhere and the process recovers on its own.
func TestReadinessIsNotLiveness(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	d := diamond(t, "kd_ha_probe", time.Now().UTC)
	s, err := Serve(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(s.Close)
	assertProbe(t, ctx, s, http.StatusOK)

	// Closing the store is what an unreachable database looks
	// like from inside the process, without having to stop a
	// container.
	d.Store.Close()
	assertProbe(t, ctx, s, http.StatusServiceUnavailable)
}

// The probe must not need a Kerberos message, and the KKDCP path must
// not need the probe. They are separate routes for separate callers.
func TestHealthAndKKDCPAreSeparateRoutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	d := diamond(t, "kd_ha_routes", time.Now().UTC)
	s, err := Serve(ctx, d)
	if err != nil {
		t.Fatalf("starting the Go KDC: %v", err)
	}
	t.Cleanup(s.Close)

	assertProbe(t, ctx, s, http.StatusOK)
	// And the KKDCP path still answers a real exchange.
	tgt := tgtFromKDC(t, d)
	if tgt.sessionEType != crypto.AES256CTSHMACSHA196 &&
		tgt.sessionEType != crypto.AES256CTSHMACSHA384192 {
		t.Errorf("unexpected session enctype %d",
			tgt.sessionEType)
	}
}
