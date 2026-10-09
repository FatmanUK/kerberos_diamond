package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// An authenticator is remembered once and refused the second time,
// which is upstream's KRB5KRB_AP_ERR_REPEAT (memrcache.c:174).
func TestAnAuthenticatorIsRecordedOnce(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	tag := []byte("an integrity tag")
	if err := s.RecordAuthenticator(
		ctx, tag, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	err := s.RecordAuthenticator(ctx, tag, now, 5*time.Minute)
	if !errors.Is(err, ErrReplay) {
		t.Errorf("got %v, want ErrReplay", err)
	}
	// A different authenticator is unaffected.
	if err := s.RecordAuthenticator(ctx, []byte("another"),
		now, 5*time.Minute); err != nil {
		t.Errorf("a distinct tag was refused: %v", err)
	}
}

// A row lives exactly as long as the clock skew and no longer, which
// is what bounds the table: an authenticator older than the skew is
// refused for being stale before it is ever looked up here, so
// remembering it past that point would buy nothing
// (k5_memrcache_store discards on the same test,
// memrcache.c:176-186).
func TestAReplayRecordExpiresWithTheSkew(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	skew := 5 * time.Minute
	tag := []byte("a tag that will go stale")
	if err := s.RecordAuthenticator(
		ctx, tag, now, skew); err != nil {
		t.Fatal(err)
	}
	// Still a replay within the window.
	if err := s.RecordAuthenticator(ctx, tag,
		now.Add(skew-time.Second), skew); !errors.Is(
		err, ErrReplay) {
		t.Errorf("inside the window: %v", err)
	}
	// And accepted again once the window has passed, because by
	// then the skew check refuses it on its own.
	if err := s.RecordAuthenticator(ctx, tag,
		now.Add(skew+time.Second), skew); err != nil {
		t.Errorf("outside the window: %v", err)
	}
}

// An empty tag is refused rather than recorded, because every
// authenticator with no integrity tag would otherwise be the same
// one.
func TestAnEmptyReplayTagIsRefused(t *testing.T) {
	s, _ := testStore(t)
	if err := s.RecordAuthenticator(context.Background(), nil,
		time.Now(), time.Minute); err == nil {
		t.Error("an empty tag was recorded")
	}
}
