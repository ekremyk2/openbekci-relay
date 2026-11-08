package fcm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbekci/openbekci-relay/internal/push"
)

type fakeGoogle struct {
	t        *testing.T
	key      *rsa.PrivateKey
	tokenSrv *httptest.Server
	fcmSrv   *httptest.Server

	tokenCalls atomic.Int32
	mu         sync.Mutex
	sendBodies []map[string]any
	sendAuth   []string
	sendPaths  []string
	sendStatus func(call int) (int, string)
	sendCalls  atomic.Int32
	tokenHang  chan struct{} // when set, the token endpoint blocks until it is closed
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGoogle{t: t, key: k, sendStatus: func(int) (int, string) { return 200, `{"name":"projects/p/messages/1"}` }}
	g.tokenSrv = httptest.NewServer(http.HandlerFunc(g.token))
	g.fcmSrv = httptest.NewServer(http.HandlerFunc(g.send))
	t.Cleanup(func() { g.tokenSrv.Close(); g.fcmSrv.Close() })
	return g
}

func (g *fakeGoogle) creds() Credentials {
	der, _ := x509.MarshalPKCS8PrivateKey(g.key)
	return Credentials{
		ProjectID: "demo-project", ClientEmail: "relay@demo-project.iam.gserviceaccount.com", TokenURI: g.tokenSrv.URL + "/token",
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
}

func (g *fakeGoogle) token(w http.ResponseWriter, r *http.Request) {
	n := g.tokenCalls.Add(1)
	if g.tokenHang != nil {
		select {
		case <-g.tokenHang:
		case <-r.Context().Done():
		}
	}
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		http.Error(w, "bad grant", 400)
		return
	}
	// Verify the assertion: header, claims and RS256 signature.
	parts := strings.Split(r.Form.Get("assertion"), ".")
	if len(parts) != 3 {
		http.Error(w, "bad assertion", 400)
		return
	}
	var claims map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &claims)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&g.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil ||
		claims["iss"] != "relay@demo-project.iam.gserviceaccount.com" || claims["scope"] != scope || claims["aud"] != g.tokenSrv.URL+"/token" {
		http.Error(w, "bad claims", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.token-" + strconv.Itoa(int(n)), "expires_in": 3600, "token_type": "Bearer"})
}

func (g *fakeGoogle) send(w http.ResponseWriter, r *http.Request) {
	call := int(g.sendCalls.Add(1))
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	g.mu.Lock()
	g.sendBodies = append(g.sendBodies, body)
	g.sendAuth = append(g.sendAuth, r.Header.Get("Authorization"))
	g.sendPaths = append(g.sendPaths, r.URL.Path)
	g.mu.Unlock()
	code, resp := g.sendStatus(call)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, resp)
}

func intp(n int) *int { return &n }

func testMsg() push.Message {
	return push.Message{
		Kind: push.KindFCM, Token: "device-token-123", AppID: "org.openbekci.app", Priority: push.PriorityHigh, TTL: time.Hour,
		Data: push.Data{InstanceID: "inst", OrgID: "org", NotificationID: "n1", Type: "ticket.updated", CollapseKey: "ticket:9", Badge: intp(3)},
	}
}

func TestRequestShape(t *testing.T) {
	g := newFakeGoogle(t)
	s, err := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res := s.Send(t.Context(), testMsg()); res != push.OK {
		t.Fatalf("result %+v", res)
	}
	if g.sendPaths[0] != "/v1/projects/demo-project/messages:send" {
		t.Errorf("path %s", g.sendPaths[0])
	}
	if g.sendAuth[0] != "Bearer ya29.token-1" {
		t.Errorf("auth %q", g.sendAuth[0])
	}
	want := `{"message":{"android":{"collapse_key":"ticket:9","priority":"HIGH","ttl":"3600s"},"data":{"badge":"3","collapse_key":"ticket:9","instance_id":"inst","notification_id":"n1","org_id":"org","type":"ticket.updated"},"token":"device-token-123"}}`
	got, _ := json.Marshal(g.sendBodies[0])
	if string(got) != want {
		t.Errorf("body\n got %s\nwant %s", got, want)
	}
	// Content-free: no notification block, only allowlisted data keys.
	msg := g.sendBodies[0]["message"].(map[string]any)
	if _, has := msg["notification"]; has {
		t.Error("notification block present")
	}
	for k := range msg["data"].(map[string]any) {
		ok := false
		for _, a := range push.AllowedDataKeys {
			ok = ok || a == k
		}
		if !ok {
			t.Errorf("non-allowlisted key %q in FCM data", k)
		}
	}
}

func TestNormalPriorityAndMinimalData(t *testing.T) {
	m := testMsg()
	m.Priority = push.PriorityNormal
	m.Data = push.Data{InstanceID: "i", NotificationID: "n", Type: "t"}
	m.TTL = 0
	b, err := buildBody(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"message":{"android":{"priority":"NORMAL","ttl":"0s"},"data":{"instance_id":"i","notification_id":"n","type":"t"},"token":"device-token-123"}}` {
		t.Errorf("%s", b)
	}
}

func TestAccessTokenIsCachedAndRefreshed(t *testing.T) {
	g := newFakeGoogle(t)
	var now atomic.Int64
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL, Now: func() time.Time { return time.Unix(now.Load(), 0) }})
	for range 3 {
		s.Send(t.Context(), testMsg())
	}
	if g.tokenCalls.Load() != 1 {
		t.Errorf("token fetched %d times, want 1", g.tokenCalls.Load())
	}
	now.Add(3600 - 30) // inside the one-minute refresh margin
	s.Send(t.Context(), testMsg())
	if g.tokenCalls.Load() != 2 {
		t.Errorf("token not refreshed near expiry: %d", g.tokenCalls.Load())
	}
	if g.sendAuth[len(g.sendAuth)-1] != "Bearer ya29.token-2" {
		t.Errorf("auth %q", g.sendAuth[len(g.sendAuth)-1])
	}
}

func TestUnauthorizedRefreshesOnce(t *testing.T) {
	g := newFakeGoogle(t)
	g.sendStatus = func(call int) (int, string) {
		if call == 1 {
			return 401, `{"error":{"status":"UNAUTHENTICATED"}}`
		}
		return 200, `{}`
	}
	s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})
	if res := s.Send(t.Context(), testMsg()); res != push.OK {
		t.Errorf("result %+v", res)
	}
	if g.tokenCalls.Load() != 2 || g.sendCalls.Load() != 2 {
		t.Errorf("token calls %d send calls %d", g.tokenCalls.Load(), g.sendCalls.Load())
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
		{"unregistered", 404, `{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`, push.StatusInvalidToken, "unregistered", false},
		{"404 bare (wrong project id)", 404, `{"error":{"code":404,"status":"NOT_FOUND"}}`, push.StatusError, "provider_rejected", false},
		{"invalid token arg", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"fieldViolations":[{"field":"message.token","description":"bad"}]}]}}`, push.StatusInvalidToken, "invalid_argument_token", false},
		{"invalid other arg", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"fieldViolations":[{"field":"message.data","description":"bad"}]}]}}`, push.StatusError, "provider_rejected", false},
		{"throttled", 429, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`, push.StatusError, "provider_throttled", true},
		{"unavailable", 503, `{"error":{"status":"UNAVAILABLE"}}`, push.StatusError, "provider_unavailable", true},
		{"internal", 500, `not json`, push.StatusError, "provider_unavailable", true},
		{"forbidden", 403, `{"error":{"status":"PERMISSION_DENIED"}}`, push.StatusError, "provider_auth_failed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newFakeGoogle(t)
			g.sendStatus = func(int) (int, string) { return c.status, c.body }
			s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})
			res := s.Send(t.Context(), testMsg())
			if res.Status != c.want || res.Code != c.code || res.Retryable != c.retry {
				t.Errorf("got %+v", res)
			}
		})
	}
}

func TestTokenEndpointFailure(t *testing.T) {
	g := newFakeGoogle(t)
	g.tokenSrv.Close()
	s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})
	if res := s.Send(t.Context(), testMsg()); res.Status != push.StatusError || res.Code != "provider_auth_failed" || !res.Retryable {
		t.Errorf("%+v", res)
	}
	if g.sendCalls.Load() != 0 {
		t.Error("sent without a token")
	}
}

func TestParseCredentials(t *testing.T) {
	if _, err := ParseCredentials([]byte(`{`)); err == nil {
		t.Error("bad json accepted")
	}
	if _, err := ParseCredentials([]byte(`{"project_id":"p"}`)); err == nil {
		t.Error("incomplete accepted")
	}
	c, err := ParseCredentials([]byte(`{"project_id":"p","client_email":"e","private_key":"k"}`))
	if err != nil || c.TokenURI != defaultTokenURI {
		t.Errorf("%+v %v", c, err)
	}
	if _, err := New(Credentials{ProjectID: "p", ClientEmail: "e", PrivateKey: "nope"}, Options{}); err == nil {
		t.Error("bad key accepted")
	}
}

func TestConcurrentUnauthorizedSharesOneRefresh(t *testing.T) {
	g := newFakeGoogle(t)
	const n = 12
	g.sendStatus = func(call int) (int, string) {
		if call <= n { // every first attempt is rejected, as after a server-side revoke
			return 401, `{"error":{"status":"UNAUTHENTICATED"}}`
		}
		return 200, `{}`
	}
	s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := s.Send(t.Context(), testMsg()); res != push.OK {
				t.Errorf("result %+v", res)
			}
		}()
	}
	wg.Wait()
	// One exchange for the initial token and a shared one for the refresh; a
	// refresh per rejected request would be n+1.
	if got := g.tokenCalls.Load(); got > 3 {
		t.Errorf("%d token exchanges for %d concurrent 401s, want at most 3", got, n)
	}
}

func TestWaiterIsNotStalledByAnotherCallersTokenFetch(t *testing.T) {
	g := newFakeGoogle(t)
	g.tokenHang = make(chan struct{})
	t.Cleanup(func() { close(g.tokenHang) }) // runs before the servers are closed
	s, _ := New(g.creds(), Options{BaseURL: g.fcmSrv.URL})

	long, cancelLong := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelLong()
	go s.Send(long, testMsg()) // starts the exchange that hangs
	for g.tokenCalls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	short, cancelShort := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancelShort()
	start := time.Now()
	res := s.Send(short, testMsg())
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("a 150ms-deadline caller waited %v behind another caller's token fetch", took)
	}
	if res.Status != push.StatusError || res.Code != "provider_auth_failed" {
		t.Errorf("%+v", res)
	}
}
