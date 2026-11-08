package store

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, *atomic.Int64) {
	t.Helper()
	var now atomic.Int64
	now.Store(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC).Unix())
	s, err := Open(filepath.Join(t.TempDir(), "sub", "relay.db"), func() time.Time { return time.Unix(now.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, &now
}

func TestServerLifecycle(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	srv, err := s.CreateServer(ctx, NewServerParams{Name: "n", AppID: "a", Verified: true, DailyQuota: 10})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Server(ctx, srv.ID)
	if err != nil || got.Secret != srv.Secret || got.Status != StatusActive || !got.Verified {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.Server(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	if err := s.SetServerStatus(ctx, srv.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.Server(ctx, srv.ID); got.Status != StatusDisabled || got.DisabledAt == nil {
		t.Errorf("%+v", got)
	}
	if err := s.SetServerStatus(ctx, srv.ID, StatusActive); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServerStatus(ctx, srv.ID, StatusRevoked); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.Server(ctx, srv.ID); got.Secret == srv.Secret {
		t.Error("revoked server kept its secret")
	}
	if err := s.SetServerStatus(ctx, srv.ID, StatusActive); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked is final: %v", err)
	}
	if err := s.SetServerStatus(ctx, "nope", StatusDisabled); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	if l, _ := s.ListServers(ctx); len(l) != 1 {
		t.Errorf("list %d", len(l))
	}
}

func TestInviteIsOneShotAndHashed(t *testing.T) {
	s, now := open(t)
	ctx := t.Context()
	code, inv, err := s.CreateInvite(ctx, true, "note", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.PeekInvite(ctx, code); err != nil || !p.Manual {
		t.Fatalf("%+v %v", p, err)
	}
	var stored string
	if err := s.db.QueryRow(`SELECT code_hash FROM invite WHERE id=?`, inv.ID).Scan(&stored); err != nil || stored == code {
		t.Errorf("plaintext code stored: %q %v", stored, err)
	}
	srv, err := s.CommitEnrollment(ctx, EnrollParams{NewServerParams: NewServerParams{AppID: "a", DailyQuota: 1}, InviteHash: InviteHash(code)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekInvite(ctx, code); !errors.Is(err, ErrInviteInvalid) {
		t.Error("used invite still valid")
	}
	if _, err := s.CommitEnrollment(ctx, EnrollParams{NewServerParams: NewServerParams{AppID: "a"}, InviteHash: InviteHash(code)}); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("second use: %v", err)
	}
	if l, _ := s.ListServers(ctx); len(l) != 1 || l[0].ID != srv.ID {
		t.Errorf("failed enrollment left a server behind: %d", len(l))
	}
	il, _ := s.ListInvites(ctx)
	if len(il) != 1 || il[0].UsedAt == nil || il[0].UsedBy != srv.ID {
		t.Errorf("%+v", il)
	}
	code2, inv2, _ := s.CreateInvite(ctx, false, "", time.Minute)
	if err := s.RevokeInvite(ctx, inv2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekInvite(ctx, code2); !errors.Is(err, ErrInviteInvalid) {
		t.Error("revoked invite valid")
	}
	code3, _, _ := s.CreateInvite(ctx, false, "", time.Minute)
	now.Add(61)
	if _, err := s.PeekInvite(ctx, code3); !errors.Is(err, ErrInviteInvalid) {
		t.Error("expired invite valid")
	}
}

func TestNonceReplayAndPurge(t *testing.T) {
	s, now := open(t)
	ctx := t.Context()
	if err := s.UseNonce(ctx, "s", "n", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.UseNonce(ctx, "s", "n", time.Minute); !errors.Is(err, ErrReplay) {
		t.Error(err)
	}
	if err := s.UseNonce(ctx, "other", "n", time.Minute); err != nil {
		t.Errorf("nonces are per server: %v", err)
	}
	now.Add(61)
	if err := s.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.UseNonce(ctx, "s", "n", time.Minute); err != nil {
		t.Errorf("after purge: %v", err)
	}
}

func TestConcurrentNonceOnlyOneWins(t *testing.T) {
	s, _ := open(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.UseNonce(t.Context(), "s", "same", time.Minute) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("%d winners", wins.Load())
	}
}

func TestQuota(t *testing.T) {
	s, now := open(t)
	ctx := t.Context()
	for _, c := range []struct{ n, limit, want int }{{3, 5, 3}, {5, 5, 2}, {1, 5, 0}} {
		if got, err := s.Reserve(ctx, "s", c.n, int64(c.limit)); err != nil || got != c.want {
			t.Errorf("reserve %+v = %d %v", c, got, err)
		}
	}
	if got, _ := s.Reserve(ctx, "s", 1000, 0); got != 1000 {
		t.Errorf("unlimited: %d", got)
	}
	if err := s.Record(ctx, "s", 4, 1, 2, 3); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Today(ctx, "s")
	if c.Accepted != 1005 || c.OK != 4 || c.InvalidToken != 1 || c.Error != 2 || c.RateLimited != 3 {
		t.Errorf("%+v", c)
	}
	now.Add(24 * 3600)
	if got, _ := s.Reserve(ctx, "s", 5, 5); got != 5 {
		t.Errorf("new day: %d", got)
	}
	// Concurrent reservations never exceed the limit.
	var total atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, _ := s.Reserve(ctx, "race", 3, 25)
			total.Add(int64(g))
		}()
	}
	wg.Wait()
	if total.Load() != 25 {
		t.Errorf("granted %d, want exactly 25", total.Load())
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, _ := Open(path, nil)
	srv, _ := s.CreateServer(t.Context(), NewServerParams{AppID: "a"})
	_ = s.Close()
	s2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if got, err := s2.Server(t.Context(), srv.ID); err != nil || got.Secret != srv.Secret {
		t.Errorf("%+v %v", got, err)
	}
}

func TestPendingEnrollment(t *testing.T) {
	s, now := open(t)
	ctx := t.Context()
	code, _, _ := s.CreateInvite(ctx, false, "", time.Hour)
	p, tok, err := s.BeginEnrollment(ctx, "app", code, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Challenge) < 7+43 || p.Challenge == tok {
		t.Errorf("challenge %q", p.Challenge)
	}
	var stored string
	if err := s.db.QueryRow(`SELECT token_hash FROM pending_enrollment WHERE id=?`, p.ID).Scan(&stored); err != nil || stored == tok {
		t.Errorf("token stored in clear: %q %v", stored, err)
	}
	// Wrong token, wrong id: indistinguishable.
	if _, err := s.OpenPending(ctx, p.ID, "obk_et_wrong"); !errors.Is(err, ErrPendingInvalid) {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := s.OpenPending(ctx, "enr_nope", tok); !errors.Is(err, ErrPendingInvalid) {
		t.Errorf("unknown id: %v", err)
	}
	got, err := s.OpenPending(ctx, p.ID, tok)
	if err != nil || got.Challenge != p.Challenge || got.AppID != "app" {
		t.Fatalf("%+v %v", got, err)
	}
	// Completion is single use.
	ep := EnrollParams{NewServerParams: NewServerParams{AppID: "app"}, InviteHash: InviteHash(code), PendingID: p.ID}
	if _, err := s.CommitEnrollment(ctx, ep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitEnrollment(ctx, ep); !errors.Is(err, ErrPendingInvalid) {
		t.Errorf("second completion: %v", err)
	}
	if _, err := s.OpenPending(ctx, p.ID, tok); !errors.Is(err, ErrPendingInvalid) {
		t.Error("completed enrollment still open")
	}
	// Attempts are bounded.
	p2, tok2, _ := s.BeginEnrollment(ctx, "app", "", false)
	for range MaxPendingAttempts {
		if err := s.ConsumeAttempt(ctx, p2.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ConsumeAttempt(ctx, p2.ID); !errors.Is(err, ErrPendingInvalid) {
		t.Errorf("attempt beyond bound: %v", err)
	}
	if _, err := s.OpenPending(ctx, p2.ID, tok2); !errors.Is(err, ErrPendingInvalid) {
		t.Error("exhausted enrollment still open")
	}
	// Expiry.
	p3, tok3, _ := s.BeginEnrollment(ctx, "app", "", false)
	now.Add(int64(PendingTTL/time.Second) + 1)
	if _, err := s.OpenPending(ctx, p3.ID, tok3); !errors.Is(err, ErrPendingInvalid) {
		t.Error("expired enrollment open")
	}
	if _, err := s.CommitEnrollment(ctx, EnrollParams{NewServerParams: NewServerParams{AppID: "app"}, PendingID: p3.ID}); !errors.Is(err, ErrPendingInvalid) {
		t.Errorf("commit after expiry: %v", err)
	}
	if err := s.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM pending_enrollment`).Scan(&n)
	if n != 0 {
		t.Errorf("%d pending rows survive purge", n)
	}
}

func TestPendingPerInviteBound(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	code, _, _ := s.CreateInvite(ctx, false, "", time.Hour)
	for range maxPendingPerInvite {
		if _, _, err := s.BeginEnrollment(ctx, "app", code, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.BeginEnrollment(ctx, "app", code, false); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("%v", err)
	}
	if _, _, err := s.BeginEnrollment(ctx, "app", "", false); err != nil {
		t.Errorf("inviteless begin blocked by an invite's bound: %v", err)
	}
}
