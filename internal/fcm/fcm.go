// Package fcm sends content-free data messages through the FCM HTTP v1 API,
// authenticating with a Google service account (OAuth2 JWT bearer grant) and
// caching the access token.
package fcm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbekci/openbekci-relay/internal/push"
)

const (
	scope           = "https://www.googleapis.com/auth/firebase.messaging"
	defaultBaseURL  = "https://fcm.googleapis.com"
	defaultTokenURI = "https://oauth2.googleapis.com/token" //nolint:gosec // a public URL, not a credential
)

// Credentials is the subset of a service account JSON file the sender needs.
type Credentials struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// ParseCredentials decodes and sanity-checks a service account JSON document.
func ParseCredentials(raw []byte) (Credentials, error) {
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, errors.New("fcm: service account is not valid JSON")
	}
	if c.ProjectID == "" || c.ClientEmail == "" || c.PrivateKey == "" {
		return c, errors.New("fcm: service account needs project_id, client_email and private_key")
	}
	if c.TokenURI == "" {
		c.TokenURI = defaultTokenURI
	}
	return c, nil
}

// Options tune a Sender; zero values are production defaults.
type Options struct {
	BaseURL    string // FCM API origin (tests)
	HTTPClient *http.Client
	Now        func() time.Time
}

// Sender implements push.Sender for FCM.
type Sender struct {
	cred   Credentials
	key    *rsa.PrivateKey
	base   string
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	token    string
	expires  time.Time
	inflight *tokenFetch
}

// New builds a Sender from credentials.
func New(c Credentials, o Options) (*Sender, error) {
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return nil, errors.New("fcm: private_key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("fcm: private_key is not PKCS#8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("fcm: private_key is not RSA")
	}
	s := &Sender{cred: c, key: rk, base: o.BaseURL, client: o.HTTPClient, now: o.Now}
	if s.base == "" {
		s.base = defaultBaseURL
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Sender) assertion() (string, error) {
	now := s.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": s.cred.ClientEmail, "scope": scope, "aud": s.cred.TokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// tokenFetch is one in-flight OAuth exchange shared by every caller that
// needs a token while it runs.
type tokenFetch struct {
	done chan struct{}
	tok  string
	err  error
}

// accessToken returns a valid access token. stale is the token the caller just
// saw rejected (empty on the first attempt): a cached token different from it
// is already the refreshed one. At most one exchange runs at a time
// (single-flight); callers wait for it but give up when their own ctx ends, and
// the exchange itself is not tied to any one caller's context, so a short
// deadline on one message cannot fail the others.
func (s *Sender) accessToken(ctx context.Context, stale string) (string, error) {
	s.mu.Lock()
	if s.token != "" && s.token != stale && s.now().Before(s.expires) {
		tok := s.token
		s.mu.Unlock()
		return tok, nil
	}
	f := s.inflight
	if f == nil {
		f = &tokenFetch{done: make(chan struct{})}
		s.inflight = f
		go s.fetchToken(f) //nolint:gosec // detached on purpose: the shared exchange must outlive any one caller's ctx
	}
	s.mu.Unlock()
	select {
	case <-f.done:
		return f.tok, f.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (s *Sender) fetchToken(f *tokenFetch) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tok, life, err := s.exchange(ctx)
	s.mu.Lock()
	if err == nil {
		s.token = tok
		s.expires = s.now().Add(life)
	}
	s.inflight = nil
	s.mu.Unlock()
	f.tok, f.err = tok, err
	close(f.done)
}

// exchange performs the JWT-bearer grant and returns the token and how long to
// cache it.
func (s *Sender) exchange(ctx context.Context) (string, time.Duration, error) {
	as, err := s.assertion()
	if err != nil {
		return "", 0, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {as}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cred.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("oauth token endpoint returned %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", 0, errors.New("oauth token endpoint returned no access_token")
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 3600
	}
	// Refresh a minute early, but never cache for less than a second.
	life := time.Duration(tr.ExpiresIn)*time.Second - time.Minute
	if life < time.Second {
		life = time.Second
	}
	return tr.AccessToken, life, nil
}

// buildBody renders the FCM v1 request. The message is data-only: the app
// builds the notification locally from the ids, so no text transits FCM.
func buildBody(m push.Message) ([]byte, error) {
	data := map[string]string{
		"instance_id": m.Data.InstanceID, "notification_id": m.Data.NotificationID, "type": m.Data.Type,
	}
	if m.Data.OrgID != "" {
		data["org_id"] = m.Data.OrgID
	}
	if m.Data.CollapseKey != "" {
		data["collapse_key"] = m.Data.CollapseKey
	}
	if m.Data.Badge != nil {
		data["badge"] = strconv.Itoa(*m.Data.Badge)
	}
	prio := "NORMAL"
	if m.Priority == push.PriorityHigh {
		prio = "HIGH"
	}
	android := map[string]any{"priority": prio, "ttl": strconv.FormatInt(int64(m.TTL/time.Second), 10) + "s"}
	if m.Data.CollapseKey != "" {
		android["collapse_key"] = m.Data.CollapseKey
	}
	return json.Marshal(map[string]any{"message": map[string]any{
		"token": m.Token, "data": data, "android": android,
	}})
}

// Send implements push.Sender.
func (s *Sender) Send(ctx context.Context, m push.Message) push.Result {
	body, err := buildBody(m)
	if err != nil {
		return push.Result{Status: push.StatusError, Code: "encode_failed"}
	}
	stale := ""
	endpoint := s.base + "/v1/projects/" + url.PathEscape(s.cred.ProjectID) + "/messages:send"
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := s.accessToken(ctx, stale)
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "provider_auth_failed", Retryable: true}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "request_failed"}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "provider_unreachable", Retryable: true}
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			stale = tok
			continue // token revoked early: refresh once
		}
		return classify(resp.StatusCode, rb)
	}
	return push.Result{Status: push.StatusError, Code: "provider_auth_failed", Retryable: true}
}

// classify maps an FCM v1 response to a push.Result. Error bodies are read for
// the machine-readable status/errorCode only and are never logged or returned.
func classify(status int, body []byte) push.Result {
	if status == http.StatusOK {
		return push.OK
	}
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	code := e.Error.Status
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
	}
	switch {
	// 404 alone is not enough: a wrong project id also answers 404 NOT_FOUND,
	// and a misconfigured relay must not make instances drop healthy devices.
	case code == "UNREGISTERED":
		return push.Result{Status: push.StatusInvalidToken, Code: "unregistered"}
	case code == "INVALID_ARGUMENT" && status == http.StatusBadRequest && tokenFieldViolation(body):
		return push.Result{Status: push.StatusInvalidToken, Code: "invalid_argument_token"}
	case status == http.StatusTooManyRequests || code == "QUOTA_EXCEEDED":
		return push.Result{Status: push.StatusError, Code: "provider_throttled", Retryable: true}
	case status >= 500:
		return push.Result{Status: push.StatusError, Code: "provider_unavailable", Retryable: true}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return push.Result{Status: push.StatusError, Code: "provider_auth_failed"}
	default:
		return push.Result{Status: push.StatusError, Code: "provider_rejected"}
	}
}

// tokenFieldViolation reports whether a 400 INVALID_ARGUMENT names the token
// field as the offender (as opposed to a malformed request, which must not
// cause the instance to delete a healthy device).
func tokenFieldViolation(body []byte) bool {
	var e struct {
		Error struct {
			Details []struct {
				FieldViolations []struct {
					Field string `json:"field"`
				} `json:"fieldViolations"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	for _, d := range e.Error.Details {
		for _, v := range d.FieldViolations {
			if v.Field == "message.token" {
				return true
			}
		}
	}
	return false
}
