//go:build unix

package store

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "relay.db")
	// A permissive umask must not widen what the relay creates.
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.CreateServer(t.Context(), NewServerParams{AppID: "a", DailyQuota: 1}); err != nil {
		t.Fatal(err)
	}
	check := func(p string, want os.FileMode) {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode %o, want %o", p, got, want)
		}
	}
	check(filepath.Dir(path), 0o700)
	check(path, 0o600)
	for _, ext := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + ext); err == nil {
			check(path+ext, 0o600)
		}
	}
}
