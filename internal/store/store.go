// Package store persists server enrollments, invites, replay nonces, used
// enrollment challenges and daily quota counters in SQLite. It never stores
// device tokens or message content.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Server statuses.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusRevoked  = "revoked"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrReplay is returned when a nonce was already seen.
var ErrReplay = errors.New("store: nonce replayed")

// ErrInviteInvalid is returned when an invite is unknown, used or expired.
var ErrInviteInvalid = errors.New("store: invite invalid")

// ErrChallengeUsed is returned when an enrollment challenge was already used.
var ErrChallengeUsed = errors.New("store: challenge already used")

// Server is an enrolled instance.
type Server struct {
	ID         string
	Name       string
	Secret     string
	AppID      string
	Status     string
	Verified   bool
	BaseURL    string
	DailyQuota int64
	CreatedAt  time.Time
	DisabledAt *time.Time
}

// Invite is a one-shot enrollment code (the plaintext code is never stored).
type Invite struct {
	ID        string
	Manual    bool
	Note      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	UsedBy    string
	CreatedAt time.Time
}

// Counters are the per-day totals for one server.
type Counters struct {
	Day          string
	Accepted     int64
	OK           int64
	InvalidToken int64
	Error        int64
	RateLimited  int64
}

// Store is the SQLite-backed store.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS server (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  secret TEXT NOT NULL,
  app_id TEXT NOT NULL,
  status TEXT NOT NULL,
  verified INTEGER NOT NULL,
  base_url TEXT NOT NULL DEFAULT '',
  daily_quota INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS invite (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  manual INTEGER NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonce (
  server_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (server_id, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nonce_expires ON nonce(expires_at);
CREATE TABLE IF NOT EXISTS challenge_used (
  hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS quota (
  server_id TEXT NOT NULL,
  day TEXT NOT NULL,
  accepted INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 0,
  invalid_token INTEGER NOT NULL DEFAULT 0,
  error INTEGER NOT NULL DEFAULT 0,
  rate_limited INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server_id, day)
) WITHOUT ROWID;
`

// securePath makes sure a newly created database directory is 0700 and the
// database file exists with mode 0600 before SQLite opens it. The relay keeps
// server secrets in clear, so other local users must not read the file. SQLite
// creates the -wal and -shm files with the permissions of the main database
// file, so pre-creating it restricted covers them too. An existing directory
// is left alone (it may be a shared mount); the file mode protects the data.
func securePath(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Open opens (creating if needed) the database at path and applies the schema.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if err := securePath(path); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	return &Store{db: db, now: now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func randString(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// NewServerParams describes a server to register.
type NewServerParams struct {
	Name       string
	AppID      string
	BaseURL    string
	Verified   bool
	DailyQuota int64
}

// CreateServer registers a server and returns it with its generated secret.
// The secret is returned to the caller once; the relay keeps it because HMAC
// verification needs the key.
func (s *Store) CreateServer(ctx context.Context, p NewServerParams) (Server, error) {
	return createServer(ctx, s.db, s.now(), p)
}

type execer interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func createServer(ctx context.Context, e execer, now time.Time, p NewServerParams) (Server, error) {
	srv := Server{
		ID: "srv_" + hex.EncodeToString(mustRand(8)), Name: p.Name, Secret: "obk_rs_" + randString(32),
		AppID: p.AppID, Status: StatusActive, Verified: p.Verified, BaseURL: p.BaseURL,
		DailyQuota: p.DailyQuota, CreatedAt: now.UTC(),
	}
	_, err := e.ExecContext(ctx, `INSERT INTO server(id,name,secret,app_id,status,verified,base_url,daily_quota,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		srv.ID, srv.Name, srv.Secret, srv.AppID, srv.Status, b2i(srv.Verified), srv.BaseURL, srv.DailyQuota, srv.CreatedAt.Unix())
	return srv, err
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

const serverCols = `id,name,secret,app_id,status,verified,base_url,daily_quota,created_at,disabled_at`

type scanner interface{ Scan(dest ...any) error }

func scanServer(r scanner) (Server, error) {
	var s Server
	var verified int
	var created int64
	var disabled sql.NullInt64
	if err := r.Scan(&s.ID, &s.Name, &s.Secret, &s.AppID, &s.Status, &verified, &s.BaseURL, &s.DailyQuota, &created, &disabled); err != nil {
		return s, err
	}
	s.Verified = verified == 1
	s.CreatedAt = time.Unix(created, 0).UTC()
	if disabled.Valid {
		t := time.Unix(disabled.Int64, 0).UTC()
		s.DisabledAt = &t
	}
	return s, nil
}

// Server fetches one server by id.
func (s *Store) Server(ctx context.Context, id string) (Server, error) {
	srv, err := scanServer(s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM server WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return srv, ErrNotFound
	}
	return srv, err
}

// ListServers returns every server ordered by creation time.
func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+serverCols+` FROM server ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Server
	for rows.Next() {
		srv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

// SetServerStatus moves a server between active, disabled and revoked. A
// revoked server also loses its secret so the credential is dead for good.
func (s *Store) SetServerStatus(ctx context.Context, id, status string) error {
	var res sql.Result
	var err error
	switch status {
	case StatusActive:
		res, err = s.db.ExecContext(ctx, `UPDATE server SET status=?, disabled_at=NULL WHERE id=? AND status<>'revoked'`, status, id)
	case StatusDisabled:
		res, err = s.db.ExecContext(ctx, `UPDATE server SET status=?, disabled_at=? WHERE id=? AND status<>'revoked'`, status, s.now().Unix(), id)
	case StatusRevoked:
		res, err = s.db.ExecContext(ctx, `UPDATE server SET status=?, secret=?, disabled_at=? WHERE id=?`, status, randString(32), s.now().Unix(), id)
	default:
		return fmt.Errorf("store: unknown status %q", status)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateInvite issues a one-shot invite and returns the plaintext code, which
// is shown once and stored only as a hash.
func (s *Store) CreateInvite(ctx context.Context, manual bool, note string, ttl time.Duration) (string, Invite, error) {
	code := "obk_inv_" + randString(18)
	now := s.now().UTC()
	inv := Invite{ID: "inv_" + hex.EncodeToString(mustRand(6)), Manual: manual, Note: note, ExpiresAt: now.Add(ttl), CreatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO invite(id,code_hash,manual,note,expires_at,created_at) VALUES(?,?,?,?,?,?)`,
		inv.ID, hash(code), b2i(manual), note, inv.ExpiresAt.Unix(), now.Unix())
	return code, inv, err
}

// ListInvites returns all invites, newest first.
func (s *Store) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,manual,note,expires_at,used_at,used_by,created_at FROM invite ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Invite
	for rows.Next() {
		var i Invite
		var man int
		var exp, created int64
		var used sql.NullInt64
		if err := rows.Scan(&i.ID, &man, &i.Note, &exp, &used, &i.UsedBy, &created); err != nil {
			return nil, err
		}
		i.Manual = man == 1
		i.ExpiresAt = time.Unix(exp, 0).UTC()
		i.CreatedAt = time.Unix(created, 0).UTC()
		if used.Valid {
			t := time.Unix(used.Int64, 0).UTC()
			i.UsedAt = &t
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// RevokeInvite expires an unused invite immediately.
func (s *Store) RevokeInvite(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invite SET expires_at=0 WHERE id=? AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PeekInvite checks that code names an unused, unexpired invite and returns
// it without consuming it.
func (s *Store) PeekInvite(ctx context.Context, code string) (Invite, error) {
	var i Invite
	var man int
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT id,manual,expires_at FROM invite WHERE code_hash=? AND used_at IS NULL`, hash(code)).Scan(&i.ID, &man, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrInviteInvalid
	}
	if err != nil {
		return i, err
	}
	i.Manual = man == 1
	i.ExpiresAt = time.Unix(exp, 0).UTC()
	if !s.now().Before(i.ExpiresAt) {
		return i, ErrInviteInvalid
	}
	return i, nil
}

// EnrollParams carries what an enrollment commit needs.
type EnrollParams struct {
	NewServerParams
	InviteCode    string // empty when the mode needs none
	ChallengeHash string // empty for manual enrollments
	ChallengeTTL  time.Duration
}

// CommitEnrollment atomically consumes the invite (when given), records the
// challenge as used (when given) and creates the server.
func (s *Store) CommitEnrollment(ctx context.Context, p EnrollParams) (Server, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Server{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now()
	if p.InviteCode != "" {
		res, err := tx.ExecContext(ctx, `UPDATE invite SET used_at=?, used_by=? WHERE code_hash=? AND used_at IS NULL AND expires_at>?`,
			now.Unix(), p.AppID, hash(p.InviteCode), now.Unix())
		if err != nil {
			return Server{}, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return Server{}, ErrInviteInvalid
		}
	}
	if p.ChallengeHash != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM challenge_used WHERE expires_at<=?`, now.Unix()); err != nil {
			return Server{}, err
		}
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO challenge_used(hash,expires_at) VALUES(?,?)`, p.ChallengeHash, now.Add(p.ChallengeTTL).Unix())
		if err != nil {
			return Server{}, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return Server{}, ErrChallengeUsed
		}
	}
	srv, err := createServer(ctx, tx, now, p.NewServerParams)
	if err != nil {
		return Server{}, err
	}
	if p.InviteCode != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE invite SET used_by=? WHERE code_hash=?`, srv.ID, hash(p.InviteCode)); err != nil {
			return Server{}, err
		}
	}
	return srv, tx.Commit()
}

// ChallengeHash is the value stored for a used challenge.
func ChallengeHash(challenge string) string { return hash(challenge) }

// UseNonce records a nonce, returning ErrReplay if already present.
func (s *Store) UseNonce(ctx context.Context, serverID, nonce string, ttl time.Duration) error {
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO nonce(server_id,nonce,expires_at) VALUES(?,?,?)`, serverID, nonce, s.now().Add(ttl).Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReplay
	}
	return nil
}

// Purge deletes expired nonces and challenges.
func (s *Store) Purge(ctx context.Context) error {
	now := s.now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nonce WHERE expires_at<=?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM challenge_used WHERE expires_at<=?`, now)
	return err
}

// Day returns the UTC quota day key for t.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Reserve tries to take n messages from the server's daily quota and returns
// how many were granted (0..n). limit <= 0 means unlimited.
func (s *Store) Reserve(ctx context.Context, serverID string, n int, limit int64) (int, error) {
	day := Day(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO quota(server_id,day) VALUES(?,?)`, serverID, day); err != nil {
		return 0, err
	}
	var used int64
	if err := tx.QueryRowContext(ctx, `SELECT accepted FROM quota WHERE server_id=? AND day=?`, serverID, day).Scan(&used); err != nil {
		return 0, err
	}
	grant := int64(n)
	if limit > 0 && used+grant > limit {
		grant = max(limit-used, 0)
	}
	if grant > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE quota SET accepted=accepted+? WHERE server_id=? AND day=?`, grant, serverID, day); err != nil {
			return 0, err
		}
	}
	return int(grant), tx.Commit()
}

// Record adds outcome counts for today. rateLimited counts messages refused
// by the bucket or the quota (they were not accepted).
func (s *Store) Record(ctx context.Context, serverID string, ok, invalid, errs, rateLimited int) error {
	day := Day(s.now())
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO quota(server_id,day) VALUES(?,?)`, serverID, day); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE quota SET ok=ok+?, invalid_token=invalid_token+?, error=error+?, rate_limited=rate_limited+? WHERE server_id=? AND day=?`,
		ok, invalid, errs, rateLimited, serverID, day)
	return err
}

// Today returns today's counters for a server (zero values when none).
func (s *Store) Today(ctx context.Context, serverID string) (Counters, error) {
	c := Counters{Day: Day(s.now())}
	err := s.db.QueryRowContext(ctx, `SELECT accepted,ok,invalid_token,error,rate_limited FROM quota WHERE server_id=? AND day=?`, serverID, c.Day).
		Scan(&c.Accepted, &c.OK, &c.InvalidToken, &c.Error, &c.RateLimited)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	return c, err
}
