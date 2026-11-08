package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbekci/openbekci-relay/internal/config"
	enroll "github.com/openbekci/openbekci-relay/internal/enroll"
	"github.com/openbekci/openbekci-relay/internal/httpapi"
	"github.com/openbekci/openbekci-relay/internal/metrics"
	"github.com/openbekci/openbekci-relay/internal/push"
	"github.com/openbekci/openbekci-relay/internal/store"
)

const appID = "org.openbekci.app"

// fakeSender records what it was asked to send and answers by token prefix.
type fakeSender struct {
	mu   sync.Mutex
	msgs []push.Message
}

func (f *fakeSender) Send(ctx context.Context, m push.Message) push.Result {
	f.mu.Lock()
	f.msgs = append(f.msgs, m)
	f.mu.Unlock()
	switch {
	case strings.HasPrefix(m.Token, "dead"):
		return push.Result{Status: push.StatusInvalidToken, Code: "unregistered"}
	case strings.HasPrefix(m.Token, "slow"):
		<-ctx.Done()
		return push.Result{Status: push.StatusError, Code: "provider_unreachable", Retryable: true}
	case strings.HasPrefix(m.Token, "panic"):
		panic("sender bug")
	case strings.HasPrefix(m.Token, "boom"):
		return push.Result{Status: push.StatusError, Code: "provider_unavailable", Retryable: true}
	}
	return push.OK
}

func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.msgs) }

type harness struct {
	t      *testing.T
	ts     *httptest.Server
	st     *store.Store
	fcm    *fakeSender
	apns   *fakeSender
	srv    store.Server
	now    atomic.Int64
	logBuf *syncBuf
	cfg    config.Config
	api    *httpapi.Server
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type verifierFunc func(ctx context.Context, baseURL, challenge string) error

func (f verifierFunc) Verify(ctx context.Context, b, c string) error { return f(ctx, b, c) }

func newHarness(t *testing.T, mutate func(*config.Config), verify httpapi.Verifier) *harness {
	t.Helper()
	h := &harness{t: t, fcm: &fakeSender{}, apns: &fakeSender{}, logBuf: &syncBuf{}}
	h.now.Store(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC).Unix())
	clock := func() time.Time { return time.Unix(h.now.Load(), 0) }
	var err error
	h.st, err = store.Open(filepath.Join(t.TempDir(), "relay.db"), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.st.Close() })
	h.cfg = config.Config{
		Enrollment: config.EnrollInvite, RatePerSec: 1000, Burst: 1000, DailyQuota: 100000, UnverifiedDailyQuota: 5,
		MaxBodyBytes: 256 << 10, MaxBatch: 500, ClockSkew: 5 * time.Minute, EnrollPerMinPerIP: 10,
		SendTimeout: 5 * time.Second, SendConcurrency: 8,
	}
	if mutate != nil {
		mutate(&h.cfg)
	}
	reg := push.NewRegistry()
	reg.Set(appID, push.KindFCM, h.fcm)
	reg.Set(appID, push.KindAPNs, h.apns)
	h.api = httpapi.New(httpapi.Deps{
		Cfg: h.cfg, Store: h.st, Senders: reg, Verifier: verify, Metrics: metrics.New(), Now: clock,
		Log: slog.New(slog.NewJSONHandler(h.logBuf, nil)),
	})
	h.ts = httptest.NewServer(h.api.Handler())
	t.Cleanup(h.ts.Close)
	h.srv, err = h.st.CreateServer(context.Background(), store.NewServerParams{AppID: appID, Verified: true, DailyQuota: h.cfg.DailyQuota})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var nonceN atomic.Int64

func (h *harness) auth(body []byte, secret string) (hdr string, nonce string) {
	nonce = "nonce-" + strconv.FormatInt(nonceN.Add(1), 10) + "-abcdefghij"
	ts := strconv.FormatInt(h.now.Load(), 10)
	return httpapi.AuthScheme + " " + h.srv.ID + ":" + ts + ":" + nonce + ":" + httpapi.ComputeMAC(secret, ts, nonce, body), nonce
}

// reply is the part of a response the tests look at (the body is already closed).
type reply struct{ StatusCode int }

func (h *harness) post(body []byte, authHeader string) (*reply, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/send", bytes.NewReader(body))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return &reply{StatusCode: resp.StatusCode}, b
}

func (h *harness) send(body string) (*reply, []byte) {
	hdr, _ := h.auth([]byte(body), h.srv.Secret)
	return h.post([]byte(body), hdr)
}

func msg(kind, token, extraData string) string {
	d := `"instance_id":"i1","org_id":"o1","notification_id":"n1","type":"ticket.updated","collapse_key":"ticket:1","badge":3`
	if extraData != "" {
		d += "," + extraData
	}
	return `{"push_kind":"` + kind + `","token":"` + token + `","app_id":"` + appID + `","priority":"high","ttl_seconds":3600,"data":{` + d + `}}`
}

func batch(ms ...string) string { return `{"messages":[` + strings.Join(ms, ",") + `]}` }

func decode(t *testing.T, b []byte) httpapi.SendResponse {
	t.Helper()
	var r httpapi.SendResponse
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("bad response %s: %v", b, err)
	}
	return r
}

func errCode(t *testing.T, b []byte) string {
	t.Helper()
	var e struct{ Error struct{ Code string } }
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e.Error.Code
}

func TestSendRoutesAndReportsPerToken(t *testing.T) {
	h := newHarness(t, nil, nil)
	resp, b := h.send(batch(msg("fcm", "goodtoken1", ""), msg("apns", "deadtoken", ""), msg("fcm", "boomtoken", "")))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	r := decode(t, b)
	want := []push.Status{push.StatusOK, push.StatusInvalidToken, push.StatusError}
	for i, w := range want {
		if r.Results[i].Index != i || r.Results[i].Status != w {
			t.Errorf("result %d = %+v, want %s", i, r.Results[i], w)
		}
	}
	if r.Results[1].Code != "unregistered" || !r.Results[2].Retryable {
		t.Errorf("codes: %+v", r.Results)
	}
	if h.fcm.count() != 2 || h.apns.count() != 1 {
		t.Errorf("routing fcm=%d apns=%d", h.fcm.count(), h.apns.count())
	}
	m := h.fcm.msgs[0]
	if m.Data.InstanceID != "i1" || m.Data.CollapseKey != "ticket:1" || m.Data.Badge == nil || *m.Data.Badge != 3 || m.TTL != time.Hour {
		t.Errorf("parsed message wrong: %+v", m)
	}
	c, _ := h.st.Today(context.Background(), h.srv.ID)
	if c.Accepted != 3 || c.OK != 1 || c.InvalidToken != 1 || c.Error != 1 {
		t.Errorf("counters %+v", c)
	}
}

func TestDataAllowlistRejectsEverythingElse(t *testing.T) {
	h := newHarness(t, nil, nil)
	cases := map[string]string{
		"title key":     `"title":"Hello"`,
		"body key":      `"body":"secret"`,
		"nested":        `"extra":{"a":1}`,
		"case variant":  `"Instance_ID":"x"`,
		"empty-named":   `"":"x"`,
		"wrong type":    `"badge":"3"`, // duplicate key, the later string wins in a map but must still be a number
		"negative":      `"badge":-1`,
		"float badge":   `"badge":1.5`,
		"too long type": `"type":"` + strings.Repeat("x", 300) + `"`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			before := h.fcm.count()
			_, b := h.send(batch(msg("fcm", "tok-allowlist", extra)))
			r := decode(t, b)
			if len(r.Results) != 1 || r.Results[0].Status != push.StatusError {
				t.Fatalf("expected rejection, got %s", b)
			}
			if h.fcm.count() != before {
				t.Fatalf("rejected message was forwarded")
			}
		})
	}
	// The error names the key but never echoes a value.
	_, b := h.send(batch(msg("fcm", "tok-allowlist", `"body":"very-secret-text"`)))
	if strings.Contains(string(b), "very-secret-text") || decode(t, b).Results[0].Code != "disallowed_data_key" {
		t.Errorf("response: %s", b)
	}
	// A bad message does not block its neighbours.
	_, b = h.send(batch(msg("fcm", "tok-a", `"body":"x"`), msg("fcm", "tok-b", "")))
	r := decode(t, b)
	if r.Results[0].Status != push.StatusError || r.Results[1].Status != push.StatusOK {
		t.Errorf("neighbour handling: %s", b)
	}
}

func TestMessageShapeRejections(t *testing.T) {
	h := newHarness(t, nil, nil)
	d := `"data":{"instance_id":"i","notification_id":"n","type":"t"}`
	bad := []string{
		`{"push_kind":"web","token":"x",` + d + `}`,
		`{"push_kind":"fcm","token":"",` + d + `}`,
		`{"push_kind":"fcm","token":"x","unknown":1,` + d + `}`,
		`{"push_kind":"fcm","token":"x","priority":"urgent",` + d + `}`,
		`{"push_kind":"fcm","token":"x","ttl_seconds":-1,` + d + `}`,
		`{"push_kind":"fcm","token":"x"}`,
		`{"push_kind":"apns","token":"x","apns":{"alert":"hi"},` + d + `}`,
		`{"push_kind":"apns","token":"x","apns":{"generic_title_key":"Hello World"},` + d + `}`,
		`{"push_kind":"fcm","token":"x","app_id":"other.app",` + d + `}`,
		`{"push_kind":"fcm","token":"x","data":{"instance_id":"i"}}`,
		`"just a string"`,
	}
	for _, m := range bad {
		_, b := h.send(batch(m))
		if r := decode(t, b); len(r.Results) != 1 || r.Results[0].Status != push.StatusError {
			t.Errorf("accepted %s -> %s", m, b)
		}
	}
	if h.fcm.count()+h.apns.count() != 0 {
		t.Error("something was forwarded")
	}
	// Valid minimal message with defaults (app_id omitted, no priority/ttl/apns).
	_, b := h.send(batch(`{"push_kind":"apns","token":"x",` + d + `,"apns":{"mutable_content":true,"generic_title_key":"push.ticket_updated"}}`))
	if decode(t, b).Results[0].Status != push.StatusOK {
		t.Errorf("minimal message: %s", b)
	}
	got := h.apns.msgs[0]
	if got.AppID != appID || got.Priority != push.PriorityHigh || got.TTL != time.Hour || !got.APNs.MutableContent || got.APNs.GenericTitleKey != "push.ticket_updated" {
		t.Errorf("defaults: %+v", got)
	}
}

func TestAuth(t *testing.T) {
	h := newHarness(t, nil, nil)
	body := []byte(batch(msg("fcm", "tok", "")))

	t.Run("missing header", func(t *testing.T) {
		resp, b := h.post(body, "")
		if resp.StatusCode != 401 || errCode(t, b) != "unauthorized" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("wrong secret", func(t *testing.T) {
		hdr, _ := h.auth(body, "not-the-secret")
		resp, b := h.post(body, hdr)
		if resp.StatusCode != 401 || errCode(t, b) != "unauthorized" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("unknown server looks identical", func(t *testing.T) {
		ts := strconv.FormatInt(h.now.Load(), 10)
		hdr := httpapi.AuthScheme + " srv_unknown:" + ts + ":abcdefghijklmnopq:" + httpapi.ComputeMAC("x", ts, "abcdefghijklmnopq", body)
		resp, b := h.post(body, hdr)
		if resp.StatusCode != 401 || errCode(t, b) != "unauthorized" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("tampered body", func(t *testing.T) {
		hdr, _ := h.auth(body, h.srv.Secret)
		resp, _ := h.post(append(append([]byte{}, body...), ' '), hdr)
		if resp.StatusCode != 401 {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		for _, hdr := range []string{"Bearer abc", httpapi.AuthScheme + " a:b:c", httpapi.AuthScheme + " " + h.srv.ID + ":1:short:ff"} {
			if resp, _ := h.post(body, hdr); resp.StatusCode != 401 {
				t.Errorf("%q -> %d", hdr, resp.StatusCode)
			}
		}
	})
	t.Run("stale timestamp", func(t *testing.T) {
		nonce := "stale-nonce-0123456789"
		ts := strconv.FormatInt(h.now.Load()-6*60, 10)
		hdr := httpapi.AuthScheme + " " + h.srv.ID + ":" + ts + ":" + nonce + ":" + httpapi.ComputeMAC(h.srv.Secret, ts, nonce, body)
		resp, b := h.post(body, hdr)
		if resp.StatusCode != 401 || errCode(t, b) != "stale_timestamp" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("future timestamp", func(t *testing.T) {
		nonce := "future-nonce-012345678"
		ts := strconv.FormatInt(h.now.Load()+6*60, 10)
		hdr := httpapi.AuthScheme + " " + h.srv.ID + ":" + ts + ":" + nonce + ":" + httpapi.ComputeMAC(h.srv.Secret, ts, nonce, body)
		if resp, _ := h.post(body, hdr); resp.StatusCode != 401 {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
	t.Run("within skew ok", func(t *testing.T) {
		nonce := "skew-nonce-0123456789"
		ts := strconv.FormatInt(h.now.Load()-4*60, 10)
		hdr := httpapi.AuthScheme + " " + h.srv.ID + ":" + ts + ":" + nonce + ":" + httpapi.ComputeMAC(h.srv.Secret, ts, nonce, body)
		if resp, b := h.post(body, hdr); resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("replayed nonce", func(t *testing.T) {
		hdr, _ := h.auth(body, h.srv.Secret)
		if resp, b := h.post(body, hdr); resp.StatusCode != 200 {
			t.Fatalf("first: %d %s", resp.StatusCode, b)
		}
		resp, b := h.post(body, hdr)
		if resp.StatusCode != 401 || errCode(t, b) != "replayed_nonce" {
			t.Errorf("replay: %d %s", resp.StatusCode, b)
		}
	})
	t.Run("nonce can repeat after the window", func(t *testing.T) {
		hdr, _ := h.auth(body, h.srv.Secret)
		h.post(body, hdr)
		h.now.Add(11 * 60)
		_ = h.st.Purge(context.Background())
		// Same nonce but fresh timestamp has a different MAC, so rebuild.
		nonce := strings.Split(hdr, ":")[2]
		ts := strconv.FormatInt(h.now.Load(), 10)
		hdr2 := httpapi.AuthScheme + " " + h.srv.ID + ":" + ts + ":" + nonce + ":" + httpapi.ComputeMAC(h.srv.Secret, ts, nonce, body)
		if resp, b := h.post(body, hdr2); resp.StatusCode != 200 {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	if h.fcm.count() == 0 {
		t.Error("expected at least the successful cases to send")
	}
}

func TestDisabledAndRevokedServers(t *testing.T) {
	h := newHarness(t, nil, nil)
	body := batch(msg("fcm", "tok", ""))
	ctx := context.Background()
	if err := h.st.SetServerStatus(ctx, h.srv.ID, store.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	resp, b := h.send(body)
	if resp.StatusCode != 403 || errCode(t, b) != "server_disabled" {
		t.Errorf("disabled: %d %s", resp.StatusCode, b)
	}
	if err := h.st.SetServerStatus(ctx, h.srv.ID, store.StatusActive); err != nil {
		t.Fatal(err)
	}
	if resp, b := h.send(body); resp.StatusCode != 200 {
		t.Errorf("re-enabled: %d %s", resp.StatusCode, b)
	}
	if err := h.st.SetServerStatus(ctx, h.srv.ID, store.StatusRevoked); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.send(body); resp.StatusCode != 401 {
		t.Errorf("revoked secret still works: %d", resp.StatusCode)
	}
	if err := h.st.SetServerStatus(ctx, h.srv.ID, store.StatusActive); err == nil {
		t.Error("revoked server was re-enabled")
	}
}

func TestBatchAndBodyLimits(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.MaxBatch = 3; c.MaxBodyBytes = 4096 }, nil)
	m := msg("fcm", "tok", "")
	resp, b := h.send(batch(m, m, m))
	if resp.StatusCode != 200 {
		t.Fatalf("at limit: %d %s", resp.StatusCode, b)
	}
	resp, b = h.send(batch(m, m, m, m))
	if resp.StatusCode != 400 || errCode(t, b) != "batch_too_large" {
		t.Errorf("over batch: %d %s", resp.StatusCode, b)
	}
	resp, b = h.send(`{"messages":[]}`)
	if resp.StatusCode != 400 || errCode(t, b) != "empty_batch" {
		t.Errorf("empty: %d %s", resp.StatusCode, b)
	}
	huge := batch(msg("fcm", strings.Repeat("a", 3000), ""), msg("fcm", strings.Repeat("b", 3000), ""))
	resp, b = h.send(huge)
	if resp.StatusCode != 413 || errCode(t, b) != "payload_too_large" {
		t.Errorf("over body: %d %s", resp.StatusCode, b)
	}
	// Chunked bodies without Content-Length are capped too.
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/send", io.MultiReader(strings.NewReader(huge)))
	req.ContentLength = -1
	hdr, _ := h.auth([]byte(huge), h.srv.Secret)
	req.Header.Set("Authorization", hdr)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != 413 {
		t.Errorf("chunked over body: %d", r2.StatusCode)
	}
	for _, bad := range []string{`not json`, `{"messages":[],"extra":1}`, `{"msgs":[]}`} {
		if resp, _ := h.send(bad); resp.StatusCode != 400 {
			t.Errorf("%q -> %d", bad, resp.StatusCode)
		}
	}
}

func TestRateLimitBucket(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Burst = 2; c.RatePerSec = 0.0001 }, nil)
	m := msg("fcm", "tok", "")
	_, b := h.send(batch(m, m, m, m))
	r := decode(t, b)
	var ok, limited int
	for _, res := range r.Results {
		switch res.Status {
		case push.StatusOK:
			ok++
		case push.StatusRateLimited:
			limited++
			if res.Code != "rate_limited" || !res.Retryable {
				t.Errorf("limited result %+v", res)
			}
		}
	}
	if ok != 2 || limited != 2 || h.fcm.count() != 2 {
		t.Errorf("ok=%d limited=%d sent=%d", ok, limited, h.fcm.count())
	}
	// Rate limited messages do not eat daily quota.
	if c, _ := h.st.Today(context.Background(), h.srv.ID); c.Accepted != 2 || c.RateLimited != 2 {
		t.Errorf("counters %+v", c)
	}
}

func TestDailyQuota(t *testing.T) {
	h := newHarness(t, nil, nil)
	small, err := h.st.CreateServer(context.Background(), store.NewServerParams{AppID: appID, Verified: true, DailyQuota: 3})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = small
	m := msg("fcm", "tok", "")
	_, b := h.send(batch(m, m))
	if r := decode(t, b); r.Results[0].Status != push.StatusOK || r.Results[1].Status != push.StatusOK {
		t.Fatalf("first batch: %s", b)
	}
	_, b = h.send(batch(m, m))
	r := decode(t, b)
	if r.Results[0].Status != push.StatusOK || r.Results[1].Status != push.StatusRateLimited || r.Results[1].Code != "quota_exceeded" {
		t.Errorf("second batch: %s", b)
	}
	if h.fcm.count() != 3 {
		t.Errorf("sent %d, want 3", h.fcm.count())
	}
	// A new UTC day resets it.
	h.now.Add(24 * 3600)
	_, b = h.send(batch(m))
	if decode(t, b).Results[0].Status != push.StatusOK {
		t.Errorf("next day: %s", b)
	}
}

func TestAppIDIsBoundToServer(t *testing.T) {
	h := newHarness(t, nil, nil)
	other := strings.Replace(msg("fcm", "tok", ""), appID, "org.other.app", 1)
	_, b := h.send(batch(other))
	if r := decode(t, b); r.Results[0].Code != "app_not_allowed" {
		t.Errorf("%s", b)
	}
	if h.fcm.count() != 0 {
		t.Error("forwarded for another app")
	}
}

func TestLogsAndMetricsAreContentFree(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.send(batch(msg("fcm", "SUPERSECRETDEVICETOKEN", ""), msg("fcm", "tok", `"body":"LEAKYBODYTEXT"`)))
	logs := h.logBuf.String()
	for _, banned := range []string{"SUPERSECRETDEVICETOKEN", "LEAKYBODYTEXT", "ticket.updated", "ticket:1", h.srv.Secret} {
		if strings.Contains(logs, banned) {
			t.Errorf("log leaks %q:\n%s", banned, logs)
		}
	}
	if !strings.Contains(logs, h.srv.ID) || !strings.Contains(logs, `"messages":2`) {
		t.Errorf("log lacks server id or counts:\n%s", logs)
	}
	resp, err := http.Get(h.ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	ms := string(mb)
	if !strings.Contains(ms, `relay_messages_total{push_kind="fcm",result="ok",server_id="`+h.srv.ID+`"} 1`) ||
		!strings.Contains(ms, `result="rejected"`) {
		t.Errorf("metrics missing expected series:\n%s", ms)
	}
	if strings.Contains(ms, "SUPERSECRET") {
		t.Error("metrics leak token")
	}
}

func TestEnrollment(t *testing.T) {
	var verified []string
	verify := verifierFunc(func(_ context.Context, base, challenge string) error {
		verified = append(verified, base)
		if challenge != "good-challenge-0123456789" {
			return enroll.ErrMismatch
		}
		return nil
	})
	h := newHarness(t, nil, verify)
	ctx := context.Background()
	doEnroll := func(body string) (*reply, []byte) {
		resp, err := http.Post(h.ts.URL+"/v1/enrollments", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return &reply{StatusCode: resp.StatusCode}, b
	}
	req := func(code, challenge string, manual bool) string {
		b, _ := json.Marshal(map[string]any{"base_url": "https://bekci.example.org", "challenge": challenge, "app_id": appID, "invite_code": code, "manual": manual})
		return string(b)
	}

	t.Run("invite required by default", func(t *testing.T) {
		resp, b := doEnroll(req("", "good-challenge-0123456789", false))
		if resp.StatusCode != 403 || errCode(t, b) != "invite_required" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("unknown app", func(t *testing.T) {
		code, _, _ := h.st.CreateInvite(ctx, false, "", time.Hour)
		b, _ := json.Marshal(map[string]any{"base_url": "https://x.example", "challenge": "good-challenge-0123456789", "app_id": "nope", "invite_code": code})
		resp, body := doEnroll(string(b))
		if resp.StatusCode != 400 || errCode(t, body) != "unknown_app_id" {
			t.Errorf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("happy path then invite and challenge are one-shot, secret signs sends", func(t *testing.T) {
		code, _, _ := h.st.CreateInvite(ctx, false, "", time.Hour)
		resp, b := doEnroll(req(code, "good-challenge-0123456789", false))
		if resp.StatusCode != 201 {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		var er httpapi.EnrollResponse
		_ = json.Unmarshal(b, &er)
		if !strings.HasPrefix(er.ServerID, "srv_") || er.ServerSecret == "" || !er.Verified {
			t.Fatalf("response %+v", er)
		}
		// Reuse the same invite: refused.
		if resp, b := doEnroll(req(code, "good-challenge-0123456789", false)); resp.StatusCode != 403 || errCode(t, b) != "invite_invalid" {
			t.Errorf("invite reuse: %d %s", resp.StatusCode, b)
		}
		// Same challenge with a fresh invite: refused (a session closes once used).
		code2, _, _ := h.st.CreateInvite(ctx, false, "", time.Hour)
		if resp, b := doEnroll(req(code2, "good-challenge-0123456789", false)); resp.StatusCode != 409 || errCode(t, b) != "challenge_used" {
			t.Errorf("challenge reuse: %d %s", resp.StatusCode, b)
		}
		// The issued secret works on /v1/send.
		h.srv = store.Server{ID: er.ServerID, Secret: er.ServerSecret}
		if resp, b := h.send(batch(msg("fcm", "tok", ""))); resp.StatusCode != 200 {
			t.Errorf("send with issued secret: %d %s", resp.StatusCode, b)
		}
		srv, _ := h.st.Server(ctx, er.ServerID)
		if srv.DailyQuota != h.cfg.DailyQuota || !srv.Verified || srv.AppID != appID {
			t.Errorf("stored server %+v", srv)
		}
	})
	t.Run("challenge mismatch does not burn the invite", func(t *testing.T) {
		code, _, _ := h.st.CreateInvite(ctx, false, "", time.Hour)
		resp, b := doEnroll(req(code, "wrong-challenge-012345678", false))
		if resp.StatusCode != 422 || errCode(t, b) != "challenge_mismatch" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
		if _, err := h.st.PeekInvite(ctx, code); err != nil {
			t.Errorf("invite burned: %v", err)
		}
	})
	t.Run("expired invite", func(t *testing.T) {
		code, _, _ := h.st.CreateInvite(ctx, false, "", time.Minute)
		h.now.Add(120)
		resp, b := doEnroll(req(code, "good-challenge-0123456789", false))
		if resp.StatusCode != 403 || errCode(t, b) != "invite_invalid" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
	})
	t.Run("manual needs a manual invite and skips the fetch", func(t *testing.T) {
		n := len(verified)
		plain, _, _ := h.st.CreateInvite(ctx, false, "", time.Hour)
		if resp, b := doEnroll(req(plain, "", true)); resp.StatusCode != 403 || errCode(t, b) != "invite_not_manual" {
			t.Errorf("%d %s", resp.StatusCode, b)
		}
		man, _, _ := h.st.CreateInvite(ctx, true, "lan", time.Hour)
		resp, b := doEnroll(req(man, "", true))
		if resp.StatusCode != 201 {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		var er httpapi.EnrollResponse
		_ = json.Unmarshal(b, &er)
		if er.Verified || len(verified) != n {
			t.Errorf("manual enrollment verified=%v fetches=%d", er.Verified, len(verified)-n)
		}
		srv, _ := h.st.Server(ctx, er.ServerID)
		if srv.Verified || srv.DailyQuota != 5 {
			t.Errorf("unverified server %+v", srv)
		}
	})
	t.Run("closed", func(t *testing.T) {
		hc := newHarness(t, func(c *config.Config) { c.Enrollment = config.EnrollClosed }, verify)
		resp, err := http.Post(hc.ts.URL+"/v1/enrollments", "application/json", strings.NewReader(req("x", "good-challenge-0123456789", false)))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("closed: %d", resp.StatusCode)
		}
	})
	t.Run("open mode needs no invite", func(t *testing.T) {
		ho := newHarness(t, func(c *config.Config) { c.Enrollment = config.EnrollOpen }, verify)
		resp, err := http.Post(ho.ts.URL+"/v1/enrollments", "application/json", strings.NewReader(req("", "good-challenge-0123456789", false)))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Errorf("open: %d", resp.StatusCode)
		}
	})
	t.Run("per IP limit", func(t *testing.T) {
		hl := newHarness(t, func(c *config.Config) { c.EnrollPerMinPerIP = 2 }, verify)
		var last int
		for range 4 {
			resp, err := http.Post(hl.ts.URL+"/v1/enrollments", "application/json", strings.NewReader(req("", "x", false)))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			last = resp.StatusCode
		}
		if last != 429 {
			t.Errorf("fourth attempt: %d", last)
		}
	})
}

func get(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestMetricsTokenAndHealthz(t *testing.T) {
	h := newHarness(t, nil, nil)
	if code, _ := get(t, h.ts.URL+"/healthz", ""); code != 200 {
		t.Errorf("healthz %d", code)
	}
	if code, _ := get(t, h.ts.URL+"/metrics", ""); code != 200 {
		t.Errorf("open metrics %d", code)
	}
	h2 := newHarness(t, nil, nil)
	h2.cfg.MetricsToken = "m3trics"
	api := httpapi.New(httpapi.Deps{Cfg: h2.cfg, Store: h2.st, Senders: push.NewRegistry(), Metrics: metrics.New(), Log: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	ts := httptest.NewServer(api.Handler())
	defer ts.Close()
	if code, _ := get(t, ts.URL+"/metrics", ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := get(t, ts.URL+"/metrics", "wrong"); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	if code, body := get(t, ts.URL+"/metrics", "m3trics"); code != 200 || !strings.Contains(body, "relay_http_requests_total") {
		t.Errorf("with token: %d", code)
	}
}

func TestBatchDeadlineBoundsSlowProviderAndKeepsOrder(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.SendConcurrency = 1
		c.SendTimeout = 5 * time.Second
		c.RequestTimeout = 300 * time.Millisecond
	}, nil)
	start := time.Now()
	resp, b := h.send(batch(msg("fcm", "slow1", ""), msg("fcm", "slow2", ""), msg("fcm", "slow3", ""), msg("fcm", "okay", "")))
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("batch took %v; the request deadline did not bound it", took)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	r := decode(t, b)
	if len(r.Results) != 4 {
		t.Fatalf("results %+v", r.Results)
	}
	for i, res := range r.Results {
		if res.Index != i || res.Status != push.StatusError || !res.Retryable {
			t.Errorf("result %d = %+v, want retryable error at index %d", i, res, i)
		}
		if res.Code != "request_deadline" {
			t.Errorf("result %d code %q, want request_deadline", i, res.Code)
		}
	}
}

func TestPanickingSenderIsContained(t *testing.T) {
	h := newHarness(t, nil, nil)
	resp, b := h.send(batch(msg("fcm", "okay1", ""), msg("fcm", "panic1", ""), msg("fcm", "okay2", "")))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	r := decode(t, b)
	if r.Results[0].Status != push.StatusOK || r.Results[2].Status != push.StatusOK ||
		r.Results[1].Status != push.StatusError || r.Results[1].Code != "internal" {
		t.Errorf("results %+v", r.Results)
	}
}

func TestRateKeyNormalisesAddresses(t *testing.T) {
	same := [][]string{
		{"2001:db8:1:2::1", "2001:DB8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::1%eth0"},
		{"203.0.113.9", "::ffff:203.0.113.9"},
	}
	for _, g := range same {
		for _, a := range g[1:] {
			if httpapi.RateKey(a) != httpapi.RateKey(g[0]) {
				t.Errorf("RateKey(%q)=%q, want %q", a, httpapi.RateKey(a), httpapi.RateKey(g[0]))
			}
		}
	}
	if httpapi.RateKey("2001:db8:1:2::1") == httpapi.RateKey("2001:db8:1:3::1") {
		t.Error("different /64s share a key")
	}
	if httpapi.RateKey("203.0.113.9") == httpapi.RateKey("203.0.113.10") {
		t.Error("different IPv4 addresses share a key")
	}
}

func TestEnrollRateLimitCannotBeEvadedByRotatingWithinAnIPv6Prefix(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Enrollment = config.EnrollClosed
		c.EnrollPerMinPerIP = 2
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	}, nil)
	var limited int
	for i := range 6 {
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/enrollments", strings.NewReader(`{}`))
		// Same /64, a new address (and a new spelling) every time.
		req.Header.Set("X-Forwarded-For", "2001:db8:aa:bb::"+strconv.Itoa(i+1))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 4 {
		t.Errorf("%d of 6 requests limited, want 4 (2 allowed per prefix)", limited)
	}
}
