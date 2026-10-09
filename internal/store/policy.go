package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Policy is a password policy, kadm5_policy_ent_rec
// (lib/kadm5/admin.h:215-236).
//
// A principal names one and most name none. Upstream keeps these in a
// separate database from the principals and refers to them by name;
// here they are a table beside the principals and referred to the
// same way, because the one thing that must not happen is a policy
// becoming a *copy* on each principal -- changing a policy has to
// change what it constrains.
type Policy struct {
	// Name is the policy's own, which an operator types and a
	// principal's Policy column holds.
	Name string `gorm:"primaryKey;size:255"`

	// PWMinLife and PWMaxLife are in seconds. The first is how
	// long a password must be kept before it may be changed
	// again, and it is the one a user meets; the second is how
	// long it may be kept, and sets PWExpiration when a password
	// is set.
	PWMinLife int32
	PWMaxLife int32

	// PWMinLength and PWMinClasses are the quality rules. A class
	// is lower case, upper case, a digit, punctuation, or
	// anything else -- five of them, counted that way by
	// check_against_policy (srv/server_misc.c:72-101).
	PWMinLength  int32
	PWMinClasses int32

	// PWHistoryNum is how many previous keys may not be reused.
	// One means the current password alone, which is the minimum
	// and the default.
	PWHistoryNum int32

	// The lockout trio (admin.h:225-227). PWMaxFail of zero means
	// no lockout at all.
	PWMaxFail           int32
	PWFailCountInterval int32
	PWLockoutDuration   int32

	// Attributes, MaxLife and MaxRenewableLife are the version 4
	// fields: a policy can impose ticket policy as well as
	// password policy.
	Attributes       uint32
	MaxLife          int32
	MaxRenewableLife int32

	// AllowedKeysalts is upstream's string form, kept verbatim
	// because it is what an operator typed and what
	// krb5_string_to_keysalts reads.
	AllowedKeysalts string `gorm:"size:1024"`
}

// The floors upstream enforces (srv/svr_policy.c:15-18), which are
// also the values an unset field takes.
const (
	MinPWLength  int32 = 1
	MinPWClasses int32 = 1
	MaxPWClasses int32 = 5
	MinPWHistory int32 = 1
)

// The reasons a policy is refused, which are kadm5's own error codes
// by another spelling. They are separate errors because an operator
// acts on each differently.
var (
	ErrBadPolicyName = errors.New(
		"store: policy name must be printable ASCII")
	ErrBadMinPWLife = errors.New(
		"store: minimum password life exceeds the maximum")
	ErrBadPWLength = errors.New(
		"store: minimum password length below 1")
	ErrBadPWClasses = errors.New(
		"store: minimum character classes outside 1..5")
	ErrBadPWHistory = errors.New(
		"store: password history below 1")
	ErrPolicyNotFound = errors.New("store: no such policy")
	ErrPolicyInUse    = errors.New(
		"store: policy is referenced by a principal")
)

// NewPolicy is a policy with upstream's defaults for everything
// unset, which is what kadm5_create_policy writes when a mask bit is
// absent (svr_policy.c:113-134).
func NewPolicy(name string) *Policy {
	return &Policy{
		Name:         name,
		PWMinLength:  MinPWLength,
		PWMinClasses: MinPWClasses,
		PWHistoryNum: MinPWHistory,
	}
}

// Validate refuses a policy that cannot mean anything.
//
// Each check is upstream's, in upstream's order, and each has its own
// error for the same reason it has its own kadm5 code: an operator
// who set the wrong field needs to be told which.
func (p *Policy) Validate() error {
	if p.Name == "" || !printableASCII(p.Name) {
		return fmt.Errorf("%w: %q",
			ErrBadPolicyName, p.Name)
	}
	// A maximum of zero means no maximum, so a minimum above it
	// is only wrong when there *is* one (svr_policy.c:107-110).
	if p.PWMaxLife != 0 && p.PWMinLife > p.PWMaxLife {
		return ErrBadMinPWLife
	}
	if p.PWMinLength < MinPWLength {
		return ErrBadPWLength
	}
	if p.PWMinClasses < MinPWClasses ||
		p.PWMinClasses > MaxPWClasses {
		return ErrBadPWClasses
	}
	if p.PWHistoryNum < MinPWHistory {
		return ErrBadPWHistory
	}
	return nil
}

// printableASCII is upstream's test on a policy name: every octet
// between a space and a tilde (svr_policy.c:96-101). Not a Unicode
// category -- the name goes into a database key and a log line, and
// upstream would refuse anything this accepted beyond it.
func printableASCII(s string) bool {
	for _, r := range s {
		if r < ' ' || r > '~' {
			return false
		}
	}
	return true
}

// Check reports whether a password satisfies the policy's quality
// rules (check_against_policy, srv/server_misc.c:72-101).
//
// A nil Policy accepts anything, which is what a principal with no
// policy gets: upstream calls passwd_check with a NULL policy in
// exactly that case (svr_principal.c:1264-1267), so "no policy" is
// not "the default policy".
func (p *Policy) Check(password string) error {
	if p == nil {
		return nil
	}
	if int32(len(password)) < p.PWMinLength {
		return fmt.Errorf("%w: %d characters, want %d",
			ErrPasswordTooShort, len(password),
			p.PWMinLength)
	}
	if n := classesIn(password); n < p.PWMinClasses {
		return fmt.Errorf("%w: %d, want %d",
			ErrPasswordTooSimple, n, p.PWMinClasses)
	}
	return nil
}

// The two ways a password fails the quality rules.
var (
	ErrPasswordTooShort = errors.New(
		"store: password is too short")
	ErrPasswordTooSimple = errors.New(
		"store: too few character classes in password")
)

// classesIn counts the character classes a password uses.
//
// Five classes, and the fifth is "anything else" -- so a password of
// nothing but accented letters counts as one class rather than as
// letters, and a space counts in that fifth class too.
//
// The tests are ASCII ranges because upstream's are ctype in the C
// locale, where ispunct means "printable, not alphanumeric, not a
// space". Go's unicode predicates differ: unicode.IsUpper is true of
// 'À' where C's isupper is not, so a password that satisfied the
// policy on one side and not the other would be a bad surprise.
func classesIn(password string) int32 {
	var lower, upper, digit, punct, other bool
	for i := 0; i < len(password); i++ {
		switch c := password[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c > ' ' && c < 0x7F:
			punct = true
		default:
			other = true
		}
	}
	var n int32
	for _, b := range []bool{
		lower, upper, digit, punct, other,
	} {
		if b {
			n++
		}
	}
	return n
}

// SavePolicy writes a policy, creating or replacing it.
func (s *Store) SavePolicy(
	ctx context.Context,
	p *Policy,
) error {
	if err := p.Validate(); err != nil {
		return err
	}
	err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		UpdateAll: true,
	}).Create(p).Error
	if err != nil {
		return fmt.Errorf("store: save policy: %w", err)
	}
	return nil
}

// LookupPolicy reads one by name.
func (s *Store) LookupPolicy(
	ctx context.Context,
	name string,
) (*Policy, error) {
	var p Policy
	err := s.db.WithContext(ctx).
		First(&p, "name = ?", name).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %q",
			ErrPolicyNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("store: policy: %w", err)
	}
	return &p, nil
}

// PolicyFor reads the policy a principal names, or nil when it names
// none.
//
// A name that no policy answers to is **not** an error, and that is
// upstream's behaviour rather than leniency: get_policy reports
// have_pol false for KRB5_KDB_NOENTRY and chpass then checks the
// password against no policy at all (svr_principal.c:1264-1283).
// Upstream has a regression test for the case
// (tests/t_policy.py:98-101), so a principal can outlive the policy
// it names.
func (s *Store) PolicyFor(
	ctx context.Context,
	p *Principal,
) (*Policy, error) {
	if strings.TrimSpace(p.Policy) == "" {
		return nil, nil
	}
	pol, err := s.LookupPolicy(ctx, p.Policy)
	if errors.Is(err, ErrPolicyNotFound) {
		return nil, nil
	}
	return pol, err
}

// DeletePolicy removes one, refusing while a principal names it.
//
// Upstream counts references and refuses with KADM5_POLICY_REF unless
// the caller passes KADM5_REF_COUNT force, because a principal left
// naming a deleted policy silently loses its constraints -- which is
// exactly the state its own #8427 test covers. Refusing is the better
// default.
func (s *Store) DeletePolicy(
	ctx context.Context,
	name string,
) error {
	db := s.db.WithContext(ctx)
	var used int64
	err := db.Model(&Principal{}).
		Where("policy = ?", name).Count(&used).Error
	if err != nil {
		return fmt.Errorf("store: policy refs: %w", err)
	}
	if used > 0 {
		return fmt.Errorf("%w: %d principal(s) name %q",
			ErrPolicyInUse, used, name)
	}
	res := db.Delete(&Policy{Name: name})
	if res.Error != nil {
		return fmt.Errorf("store: delete policy: %w",
			res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: %q", ErrPolicyNotFound, name)
	}
	return nil
}

// ListPolicies names every policy, sorted.
func (s *Store) ListPolicies(
	ctx context.Context,
) ([]string, error) {
	var out []string
	err := s.db.WithContext(ctx).Model(&Policy{}).
		Order("name").Pluck("name", &out).Error
	if err != nil {
		return nil, fmt.Errorf("store: policies: %w", err)
	}
	return out, nil
}

// CheckPassword runs the quality rules of whatever policy a principal
// names.
//
// A principal naming no policy, or naming one that does not exist, is
// unconstrained -- see PolicyFor.
func (s *Store) CheckPassword(
	ctx context.Context,
	p *Principal,
	password string,
) error {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil {
		return err
	}
	return pol.Check(password)
}

// ErrPasswordTooSoon reports a change made before the policy's
// minimum password life has elapsed.
var ErrPasswordTooSoon = errors.New(
	"store: password changed too recently")

// CheckMinPasswordLife refuses a change made too soon
// (check_min_life, kadmin/server/misc.c:59-120).
//
// The exemption is the part worth reading twice: a principal with
// REQUIRES_PWCHANGE set is **not** subject to the minimum (:88-89).
// It has to be that way round, or an administrator who both forced a
// change and set a minimum life would have locked the user out of
// doing the thing they were told to do.
//
// Only a self-service change goes through this. kadmin's own cpw does
// not -- upstream calls check_min_life from schpw_util_wrapper's self
// branch alone (misc.c:24-32) -- because an administrator with the
// authority to change a password has the authority to change it now.
func (s *Store) CheckMinPasswordLife(
	ctx context.Context,
	p *Principal,
	now time.Time,
) error {
	if p.Attributes&AttrRequiresPWChange != 0 {
		return nil
	}
	pol, err := s.PolicyFor(ctx, p)
	if err != nil || pol == nil || pol.PWMinLife == 0 {
		return err
	}
	min := time.Duration(pol.PWMinLife) * time.Second
	until := p.LastPWChange.Add(min)
	if p.LastPWChange.IsZero() || !now.Before(until) {
		return nil
	}
	return fmt.Errorf("%w: not again until %s",
		ErrPasswordTooSoon, until.UTC().Format(time.RFC3339))
}

// SetPasswordExpiry sets a principal's password expiry from its
// policy's maximum life, which is where PWExpiration comes from
// (svr_principal.c:1328-1329 on a change, :405-412 at creation).
//
// With no policy, or a policy with no maximum, the expiry is cleared
// rather than left: a principal moved off a policy that expired its
// password should not keep the old deadline.
func (s *Store) SetPasswordExpiry(
	ctx context.Context,
	p *Principal,
	now time.Time,
) error {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil {
		return err
	}
	if pol == nil || pol.PWMaxLife == 0 {
		p.PWExpiration = time.Time{}
		return nil
	}
	p.PWExpiration = now.UTC().Truncate(time.Second).Add(
		time.Duration(pol.PWMaxLife) * time.Second)
	return nil
}
