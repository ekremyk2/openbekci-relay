package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func runAdmin(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"admin"}, args...), &out, &errb)
	if code != 0 {
		return errb.String(), code
	}
	return out.String(), code
}

func TestAdminFlow(t *testing.T) {
	t.Setenv("RELAY_DB_PATH", filepath.Join(t.TempDir(), "relay.db"))

	out, code := runAdmin(t, "servers", "create", "--app-id", "org.openbekci.app", "--name", "demo")
	if code != 0 {
		t.Fatalf("create: %s", out)
	}
	id := regexp.MustCompile(`server_id:\s+(srv_[0-9a-f]+)`).FindStringSubmatch(out)
	if id == nil || !strings.Contains(out, "server_secret: obk_rs_") {
		t.Fatalf("create output: %s", out)
	}

	list, _ := runAdmin(t, "servers", "list")
	if !strings.Contains(list, id[1]) || !strings.Contains(list, "active") {
		t.Errorf("list: %s", list)
	}
	if strings.Contains(list, "obk_rs_") {
		t.Error("list prints secrets")
	}
	if _, code := runAdmin(t, "servers", "disable", id[1]); code != 0 {
		t.Error("disable failed")
	}
	if list, _ = runAdmin(t, "servers", "list"); !strings.Contains(list, "disabled") {
		t.Errorf("list after disable: %s", list)
	}
	if _, code := runAdmin(t, "servers", "enable", id[1]); code != 0 {
		t.Error("enable failed")
	}
	if _, code := runAdmin(t, "servers", "revoke", id[1]); code != 0 {
		t.Error("revoke failed")
	}
	if _, code := runAdmin(t, "servers", "enable", id[1]); code == 0 {
		t.Error("revoked server re-enabled")
	}
	if _, code := runAdmin(t, "servers", "disable", "srv_missing"); code == 0 {
		t.Error("unknown server accepted")
	}
	if _, code := runAdmin(t, "servers", "create"); code == 0 {
		t.Error("create without --app-id accepted")
	}

	inv, code := runAdmin(t, "invites", "create", "--manual", "--note", "lan site")
	if code != 0 || !strings.Contains(inv, "invite_code: obk_inv_") || !strings.Contains(inv, "manual: true") {
		t.Fatalf("invite: %s", inv)
	}
	invID := regexp.MustCompile(`invite_id: (inv_[0-9a-f]+)`).FindStringSubmatch(inv)[1]
	il, _ := runAdmin(t, "invites", "list")
	if !strings.Contains(il, invID) || strings.Contains(il, "obk_inv_") {
		t.Errorf("invite list: %s", il)
	}
	if _, code := runAdmin(t, "invites", "revoke", invID); code != 0 {
		t.Error("invite revoke failed")
	}
}

func TestUsageAndUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, &out, &errb) != 2 || run([]string{"nope"}, &out, &errb) != 2 {
		t.Error("expected usage exit code 2")
	}
	if run([]string{"version"}, &out, &errb) != 0 || !strings.Contains(out.String(), "dev") {
		t.Errorf("version: %q", out.String())
	}
}
