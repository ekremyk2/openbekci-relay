package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbekci/openbekci-relay/internal/push"
)

type captured struct {
	proto  int
	path   string
	header http.Header
	body   map[string]any
}

type fakeAPNs struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	srv    *httptest.Server
	mu     sync.Mutex
	got    []captured
	calls  atomic.Int32
	status func(call int, auth string) (int, string)
}

func newFakeAPNs(t *testing.T) *fakeAPNs {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPNs{t: t, key: k, status: func(int, string) (int, string) { return 200, "" }}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPNs) handle(w http.ResponseWriter, r *http.Request) {
	call := int(f.calls.Add(1))
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	f.mu.Lock()
	f.got = append(f.got, captured{proto: r.ProtoMajor, path: r.URL.Path, header: r.Header.Clone(), body: body})
	f.mu.Unlock()
	code, resp := f.status(call, r.Header.Get("Authorization"))
	w.WriteHeader(code)
	_, _ = io.WriteString(w, resp)
}

func (f *fakeAPNs) config() Config {
	der, _ := x509.MarshalPKCS8PrivateKey(f.key)
	return Config{KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), KeyID: "ABC123DEFG", TeamID: "TEAM123456", Topic: "org.openbekci.app"}
}

func (f *fakeAPNs) sender(now func() time.Time) *Sender {
	s, err := New(f.config(), Options{BaseURL: f.srv.URL, HTTPClient: f.srv.Client(), Now: now})
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func intp(n int) *int { return &n }

func baseMsg() push.Message {
	return push.Message{
		Kind: push.KindAPNs, Token: "00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0", AppID: "org.openbekci.app",
		Priority: push.PriorityHigh, TTL: time.Hour,
		Data: push.Data{InstanceID: "inst", OrgID: "org", NotificationID: "n1", Type: "ticket.updated", CollapseKey: "ticket:9", Badge: intp(3)},
		APNs: push.APNsOptions{MutableContent: true, GenericTitleKey: "push.ticket_updated"},
	}
}

func TestAlertRequestShape(t *testing.T) {
	f := newFakeAPNs(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := f.sender(func() time.Time { return now })
	if res := s.Send(t.Context(), baseMsg()); res != push.OK {
		t.Fatalf("result %+v", res)
	}
	c := f.got[0]
	if c.proto != 2 {
		t.Errorf("HTTP/%d, want HTTP/2", c.proto)
	}
	if c.path != "/3/device/00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0" {
		t.Errorf("path %s", c.path)
	}
	for k, want := range map[string]string{
		"Apns-Topic": "org.openbekci.app", "Apns-Push-Type": "alert", "Apns-Priority": "10",
		"Apns-Expiration": "1767229200", "Apns-Collapse-Id": "ticket:9", "Content-Type": "application/json",
	} {
		if got := c.header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	got, _ := json.Marshal(c.body)
	want := `{"aps":{"alert":{"title-loc-key":"push.ticket_updated"},"badge":3,"mutable-content":1},"collapse_key":"ticket:9","instance_id":"inst","notification_id":"n1","org_id":"org","type":"ticket.updated"}`
	if string(got) != want {
		t.Errorf("payload\n got %s\nwant %s", got, want)
	}
	// The alert carries a localisation key only: no title or body text.
	alert := c.body["aps"].(map[string]any)["alert"].(map[string]any)
	if len(alert) != 1 {
		t.Errorf("alert has extra keys: %v", alert)
	}
}

func TestProviderTokenIsValidES256AndCached(t *testing.T) {
	f := newFakeAPNs(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(now.Unix())
	s := f.sender(func() time.Time { return time.Unix(clock.Load(), 0) })
	s.Send(t.Context(), baseMsg())
	s.Send(t.Context(), baseMsg())
	a1, a2 := f.got[0].header.Get("Authorization"), f.got[1].header.Get("Authorization")
	if a1 != a2 || !strings.HasPrefix(a1, "bearer ") {
		t.Fatalf("token not reused: %q vs %q", a1, a2)
	}
	parts := strings.Split(strings.TrimPrefix(a1, "bearer "), ".")
	var hdr, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &hdr)
	_ = json.Unmarshal(cb, &claims)
	if hdr["alg"] != "ES256" || hdr["kid"] != "ABC123DEFG" || claims["iss"] != "TEAM123456" || int64(claims["iat"].(float64)) != now.Unix() {
		t.Errorf("hdr %v claims %v", hdr, claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature length %d", len(sig))
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&f.key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("signature does not verify")
	}
	clock.Add(int64(51 * time.Minute / time.Second))
	s.Send(t.Context(), baseMsg())
	if f.got[2].header.Get("Authorization") == a1 {
		t.Error("token not refreshed after 50 minutes")
	}
}

func TestSilentPushWhenNoTitleKey(t *testing.T) {
	f := newFakeAPNs(t)
	s := f.sender(nil)
	m := baseMsg()
	m.APNs = push.APNsOptions{}
	m.Priority = push.PriorityHigh // must still be downgraded: background pushes are priority 5
	m.Data.Badge = nil
	m.Data.CollapseKey = ""
	m.TTL = 0
	s.Send(t.Context(), m)
	c := f.got[0]
	if c.header.Get("Apns-Push-Type") != "background" || c.header.Get("Apns-Priority") != "5" ||
		c.header.Get("Apns-Expiration") != "0" || c.header.Get("Apns-Collapse-Id") != "" {
		t.Errorf("headers %v", c.header)
	}
	got, _ := json.Marshal(c.body)
	if string(got) != `{"aps":{"content-available":1},"instance_id":"inst","notification_id":"n1","org_id":"org","type":"ticket.updated"}` {
		t.Errorf("payload %s", got)
	}
}

func TestNormalPriorityAlert(t *testing.T) {
	f := newFakeAPNs(t)
	m := baseMsg()
	m.Priority = push.PriorityNormal
	f.sender(nil).Send(t.Context(), m)
	if f.got[0].header.Get("Apns-Priority") != "5" {
		t.Errorf("priority %q", f.got[0].header.Get("Apns-Priority"))
	}
}

func TestLongCollapseKeyIsHashedTo64Bytes(t *testing.T) {
	f := newFakeAPNs(t)
	m := baseMsg()
	m.Data.CollapseKey = strings.Repeat("k", 100)
	f.sender(nil).Send(t.Context(), m)
	id := f.got[0].header.Get("Apns-Collapse-Id")
	if len(id) != 64 || id == strings.Repeat("k", 64) {
		t.Errorf("collapse id %q", id)
	}
	if collapseID(strings.Repeat("k", 100)) != id {
		t.Error("collapse id not stable")
	}
	if f.got[0].body["collapse_key"] != strings.Repeat("k", 100) {
		t.Error("payload collapse_key must stay untouched")
	}
}

func TestExpiredProviderTokenRefreshesOnce(t *testing.T) {
	f := newFakeAPNs(t)
	f.status = func(call int, _ string) (int, string) {
		if call == 1 {
			return 403, `{"reason":"ExpiredProviderToken"}`
		}
		return 200, ""
	}
	var clock atomic.Int64
	clock.Store(1000)
	s := f.sender(func() time.Time { v := clock.Add(1); return time.Unix(v, 0) }) // each call is a new second so iat differs
	if res := s.Send(t.Context(), baseMsg()); res != push.OK {
		t.Fatalf("result %+v", res)
	}
	if f.calls.Load() != 2 || f.got[0].header.Get("Authorization") == f.got[1].header.Get("Authorization") {
		t.Errorf("calls=%d, token reused=%v", f.calls.Load(), f.got[0].header.Get("Authorization") == f.got[1].header.Get("Authorization"))
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   push.Status
		code   string
		retry  bool
	}{
		{"gone", 410, `{"reason":"Unregistered","timestamp":1}`, push.StatusInvalidToken, "unregistered", false},
		{"bad device token", 400, `{"reason":"BadDeviceToken"}`, push.StatusInvalidToken, "unregistered", false},
		{"topic mismatch is config, not a dead device", 400, `{"reason":"DeviceTokenNotForTopic"}`, push.StatusError, "topic_mismatch", false},
		{"payload too large", 413, `{"reason":"PayloadTooLarge"}`, push.StatusError, "provider_rejected", false},
		{"throttled", 429, `{"reason":"TooManyRequests"}`, push.StatusError, "provider_throttled", true},
		{"unavailable", 503, `{"reason":"ServiceUnavailable"}`, push.StatusError, "provider_unavailable", true},
		{"auth", 403, `{"reason":"InvalidProviderToken"}`, push.StatusError, "provider_auth_failed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAPNs(t)
			f.status = func(int, string) (int, string) { return c.status, c.body }
			res := f.sender(nil).Send(t.Context(), baseMsg())
			if res.Status != c.want || res.Code != c.code || res.Retryable != c.retry {
				t.Errorf("got %+v", res)
			}
		})
	}
}

func TestUnreachableProvider(t *testing.T) {
	f := newFakeAPNs(t)
	s := f.sender(nil)
	f.srv.Close()
	if res := s.Send(t.Context(), baseMsg()); res.Status != push.StatusError || res.Code != "provider_unreachable" || !res.Retryable {
		t.Errorf("%+v", res)
	}
}

func TestConfigValidation(t *testing.T) {
	f := newFakeAPNs(t)
	c := f.config()
	c.Topic = ""
	if _, err := New(c, Options{}); err == nil {
		t.Error("missing topic accepted")
	}
	c = f.config()
	c.KeyPEM = []byte("garbage")
	if _, err := New(c, Options{}); err == nil {
		t.Error("bad key accepted")
	}
	c = f.config()
	c.Sandbox = true
	s, err := New(c, Options{})
	if err != nil || s.base != sandboxHost {
		t.Errorf("sandbox base %v %v", s, err)
	}
}
