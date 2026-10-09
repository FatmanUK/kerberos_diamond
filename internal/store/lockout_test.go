package store

import (
	"context"
	"testing"
	"time"
)

// A maximum of zero is no lockout at all, which is the default and
// the first test locked_check_p makes (lockout.c:98-99). Without that
// a realm with a policy but no lockout settings would lock everybody
// out at the first typo.
func TestNoMaximumMeansNoLockout(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "nolock", 1)
	p.FailAuthCount = 1000

	out, err := s.LockoutFor(ctx, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out.Locked {
		t.Error("locked with no maximum set")
	}
}

// The count has to reach the maximum, and then the duration decides
// whether it ever lifts: zero means never, and only an administrator
// can clear it (lockout.c:100-105).
func TestLockoutCountsAndThenExpires(t *testing.T) {
	s, _ := testStore(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := lockoutPrincipal(t, s, 3, 600, 0)

	p.FailAuthCount = 2
	p.LastFailed = now
	assertLocked(t, s, p, now, false)

	p.FailAuthCount = 3
	assertLocked(t, s, p, now, true)
	// Ten minutes later it has lifted.
	assertLocked(t, s, p, now.Add(11*time.Minute), false)
}

// A lockout duration of zero is permanent, which is the setting an
// administrator uses when they want to be told about it.
func TestAZeroDurationLocksPermanently(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := lockoutPrincipal(t, s, 2, 0, 0)
	p.FailAuthCount = 2
	p.LastFailed = now

	assertLocked(t, s, p, now, true)
	assertLocked(t, s, p, now.Add(365*24*time.Hour), true)
	// And an administrative unlock clears it.
	if err := s.Unlock(ctx, p); err != nil {
		t.Fatal(err)
	}
	assertLocked(t, s, p, now, false)
}

// Failures count up and are written, and a failure older than the
// policy's interval does not count towards the next lockout
// (lockout.c:190-194).
func TestFailuresCountAndTheIntervalResets(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := lockoutPrincipal(t, s, 5, 600, 300)

	for i := 1; i <= 3; i++ {
		err := s.RecordOutcome(ctx, p, FailedPreauth, now)
		if err != nil {
			t.Fatal(err)
		}
		if p.FailAuthCount != int32(i) {
			t.Fatalf("count is %d, want %d",
				p.FailAuthCount, i)
		}
	}
	// It is written, not just held: a second KDC reading the same
	// row sees it.
	again, err := s.Lookup(ctx, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if again.FailAuthCount != 3 {
		t.Errorf("the stored count is %d, want 3",
			again.FailAuthCount)
	}
	// Six minutes later the interval has elapsed, so the next
	// failure starts over.
	later := now.Add(6 * time.Minute)
	if err := s.RecordOutcome(ctx, again, FailedPreauth,
		later); err != nil {
		t.Fatal(err)
	}
	if again.FailAuthCount != 1 {
		t.Errorf("count is %d after the interval, want 1",
			again.FailAuthCount)
	}
}

// A success resets the count -- but **only** for a principal that
// requires pre-authentication, which is the subtlety upstream puts a
// comment on: "Only mark the authentication as successful if the
// entry required preauthentication, otherwise we have no idea"
// (lockout.c:177-178).
//
// Without preauth a client gets a ticket without ever proving it
// knows the password, so a successful exchange says nothing about
// whoever asked and must not clear a count of failures.
func TestSuccessResetsOnlyWithPreauth(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	plain := lockoutPrincipal(t, s, 5, 600, 0)
	plain.FailAuthCount = 3
	if err := s.RecordOutcome(ctx, plain, Succeeded,
		now); err != nil {
		t.Fatal(err)
	}
	if plain.FailAuthCount != 3 {
		t.Errorf("a preauth-free success cleared the count")
	}

	needs := lockoutPrincipal(t, s, 5, 600, 0)
	needs.Attributes |= AttrRequiresPreAuth
	needs.FailAuthCount = 3
	if err := s.RecordOutcome(ctx, needs, Succeeded,
		now); err != nil {
		t.Fatal(err)
	}
	if needs.FailAuthCount != 0 {
		t.Errorf("count is %d after a proven success",
			needs.FailAuthCount)
	}
	if !needs.LastSuccess.Equal(now) {
		t.Errorf("last success is %v", needs.LastSuccess)
	}
}

// With no lockout policy nothing is written at all, which is this
// project's divergence: upstream writes last_success on every
// authenticated exchange, gated only by a disable_last_success option
// that exists *because* the write is expensive. A realm that has not
// asked for lockout keeps the guarantee that an exchange leaves
// nothing behind.
func TestNoLockoutPolicyWritesNothing(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "nolock", 1)
	p.Attributes |= AttrRequiresPreAuth

	err := s.RecordOutcome(ctx, p, Succeeded, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !again.LastSuccess.IsZero() {
		t.Errorf("a success was recorded: %v",
			again.LastSuccess)
	}
}

// An already-locked principal is not written to again, which upstream
// does deliberately: in most cases the request was refused before
// reaching the audit, but an integrity failure can arrive before any
// policy check (lockout.c:168-172).
func TestALockedPrincipalIsNotCountedFurther(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := lockoutPrincipal(t, s, 2, 0, 0)
	p.FailAuthCount = 2
	p.LastFailed = now

	err := s.RecordOutcome(ctx, p, FailedPreauth, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.FailAuthCount != 2 {
		t.Errorf("count climbed to %d while locked",
			p.FailAuthCount)
	}
}

// lockoutPrincipal makes a principal under a policy with the given
// lockout settings.
func lockoutPrincipal(
	t *testing.T,
	s *Store,
	maxFail, duration, interval int32,
) *Principal {
	t.Helper()
	ctx := context.Background()
	name := "locked" + itoa(maxFail) + itoa(duration) +
		itoa(interval)
	pol := NewPolicy(name)
	pol.PWMaxFail = maxFail
	pol.PWLockoutDuration = duration
	pol.PWFailCountInterval = interval
	if err := s.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	full := name + "@" + testRealm
	principal(t, s, full, "a-password")
	p, err := s.Lookup(ctx, full)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = name
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, full)
	if err != nil {
		t.Fatal(err)
	}
	return again
}

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

func assertLocked(
	t *testing.T,
	s *Store,
	p *Principal,
	now time.Time,
	want bool,
) {
	t.Helper()
	out, err := s.LockoutFor(context.Background(), p, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Locked != want {
		t.Errorf("locked = %v at %v, want %v",
			out.Locked, now, want)
	}
}
