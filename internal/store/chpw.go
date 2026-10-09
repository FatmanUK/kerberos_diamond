package store

import (
	"context"
	"time"
)

// ChangePassword sets a principal's password, running everything a
// policy says about it in the order upstream runs it.
//
// The policy's quality rules apply to an administrator's change as
// much as to a user's own: upstream calls passwd_check from
// chpass_principal_3, which both paths go through
// (svr_principal.c:1281).
//
// What does *not* apply is the minimum password life. An
// administrator with the authority to change a password has the
// authority to change it now, which is why upstream reaches
// check_min_life only from the self-service branch
// (kadmin/server/misc.c:24-32) -- so a caller that *is* the
// self-service path calls CheckMinPasswordLife itself first.
//
// It lives here rather than in either caller because there are two --
// the local subcommands and the administrative surface -- and the
// ordering below is the kind that goes wrong silently when it is
// written twice.
func (s *Store) ChangePassword(
	ctx context.Context,
	p *Principal,
	pw string,
	keepOld bool,
) (int32, error) {
	if err := s.CheckPassword(ctx, p, pw); err != nil {
		return 0, err
	}
	if err := s.CheckPasswordReuse(ctx, p, pw); err != nil {
		return 0, err
	}
	// The history entry is built from the keys that are about to
	// be replaced, so it has to be written first -- which is the
	// one ordering constraint here and the one upstream puts a
	// comment on (svr_principal.c:1270-1271).
	if err := s.RecordPasswordHistory(ctx, p); err != nil {
		return 0, err
	}
	kvno, err := s.setNewPassword(p, pw, keepOld)
	if err != nil {
		return 0, err
	}
	if err := s.SetPasswordExpiry(ctx, p,
		time.Now()); err != nil {
		return 0, err
	}
	// And the bit that demanded a change is cleared, as it is on
	// a self-service change (svr_principal.c:1298).
	p.Attributes &^= AttrRequiresPWChange
	return kvno, nil
}

// setNewPassword replaces the keys at the next version.
func (s *Store) setNewPassword(
	p *Principal,
	pw string,
	keepOld bool,
) (int32, error) {
	kvno := p.HighestKVNO() + 1
	var err error
	if keepOld {
		err = s.SetPasswordKeepOld(p, pw, kvno)
	} else {
		err = s.SetPassword(p, pw, kvno)
	}
	return kvno, err
}

// SetRandomPassword re-keys a principal with random keys, which is
// kadmin's -randkey.
//
// It runs **neither the quality check nor the history check**, and
// that is upstream's behaviour rather than an omission: randkey_3
// (svr_principal.c:1388-1505) calls neither passwd_check nor
// check_pw_reuse, which is why `cpw -randkey' escapes a minimum
// password life and a password history. Reproduced rather than
// improved, because an operator who knows kadmin would be surprised
// by the improvement.
func (s *Store) SetRandomPassword(
	ctx context.Context,
	p *Principal,
	keepOld bool,
) (int32, error) {
	kvno := p.HighestKVNO() + 1
	var err error
	if keepOld {
		err = s.SetRandomKeyKeepOld(p, kvno)
	} else {
		err = s.SetRandomKey(p, kvno)
	}
	if err != nil {
		return 0, err
	}
	if err := s.SetPasswordExpiry(ctx, p,
		time.Now()); err != nil {
		return 0, err
	}
	return kvno, nil
}
