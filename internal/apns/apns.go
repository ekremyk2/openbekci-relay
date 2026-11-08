// Package apns sends content-free pushes over APNs HTTP/2 with token-based
// (.p8) provider authentication.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/openbekci/openbekci-relay/internal/push"
)

const (
	productionHost = "https://api.push.apple.com"
	sandboxHost    = "https://api.sandbox.push.apple.com"
	// Apple wants the provider token refreshed no more than hourly and no
	// less than every 20 minutes.
	tokenLife = 50 * time.Minute
)

// Config is the per-app APNs configuration.
type Config struct {
	KeyPEM  []byte // contents of the .p8 file
	KeyID   string
	TeamID  string
	Topic   string // bundle id
	Sandbox bool
}

// Options tune a Sender; zero values are production defaults.
type Options struct {
	BaseURL    string // overrides the APNs origin (tests)
	HTTPClient *http.Client
	Now        func() time.Time
}

// Sender implements push.Sender for APNs.
type Sender struct {
	cfg    Config
	key    *ecdsa.PrivateKey
	base   string
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	token   string
	issued  time.Time
	version int
}

// New builds a Sender from a config.
func New(c Config, o Options) (*Sender, error) {
	if c.KeyID == "" || c.TeamID == "" || c.Topic == "" {
		return nil, errors.New("apns: key id, team id and topic are required")
	}
	block, _ := pem.Decode(c.KeyPEM)
	if block == nil {
		return nil, errors.New("apns: key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("apns: key is not PKCS#8")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns: key is not an EC key")
	}
	s := &Sender{cfg: c, key: ek, base: o.BaseURL, client: o.HTTPClient, now: o.Now}
	if s.base == "" {
		s.base = productionHost
		if c.Sandbox {
			s.base = sandboxHost
		}
	}
	if s.client == nil {
		s.client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// providerToken returns the cached ES256 JWT, minting a new one when stale or
// when the caller saw ExpiredProviderToken for the version it used.
func (s *Sender) providerToken(staleVersion int) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Sub(s.issued) < tokenLife && s.version != staleVersion {
		return s.token, s.version, nil
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": s.cfg.KeyID})
	claims, _ := json.Marshal(map[string]any{"iss": s.cfg.TeamID, "iat": now.Unix()})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", 0, err
	}
	sig := make([]byte, 64) // JWS ES256: fixed-width r || s
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	s.token = signing + "." + b64(sig)
	s.issued = now
	s.version++
	return s.token, s.version, nil
}

// buildPayload renders the aps dictionary plus the allowlisted keys.
//
// With generic_title_key the push is a visible alert whose title is a
// localisation key only (title-loc-key); the device resolves the text. Without
// it the push is a silent background push (content-available) that makes the
// app fetch details itself.
func buildPayload(m push.Message) ([]byte, bool, error) {
	aps := map[string]any{}
	alert := m.APNs.GenericTitleKey != ""
	if alert {
		aps["alert"] = map[string]any{"title-loc-key": m.APNs.GenericTitleKey}
		if m.APNs.MutableContent {
			aps["mutable-content"] = 1
		}
	} else {
		aps["content-available"] = 1
	}
	if m.Data.Badge != nil {
		aps["badge"] = *m.Data.Badge
	}
	root := map[string]any{"aps": aps, "instance_id": m.Data.InstanceID, "notification_id": m.Data.NotificationID, "type": m.Data.Type}
	if m.Data.OrgID != "" {
		root["org_id"] = m.Data.OrgID
	}
	if m.Data.CollapseKey != "" {
		root["collapse_key"] = m.Data.CollapseKey
	}
	b, err := json.Marshal(root)
	return b, alert, err
}

// collapseID fits a collapse key into apns-collapse-id's 64-byte limit: short
// keys pass through, longer ones are replaced by their SHA-256 in hex (64
// chars), which is stable so collapsing still works.
func collapseID(k string) string {
	if len(k) <= 64 {
		return k
	}
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

// Send implements push.Sender.
func (s *Sender) Send(ctx context.Context, m push.Message) push.Result {
	body, alert, err := buildPayload(m)
	if err != nil {
		return push.Result{Status: push.StatusError, Code: "encode_failed"}
	}
	endpoint := s.base + "/3/device/" + url.PathEscape(m.Token)
	stale := 0
	for attempt := 0; attempt < 2; attempt++ {
		tok, ver, err := s.providerToken(stale)
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "provider_auth_failed"}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "request_failed"}
		}
		req.Header.Set("Authorization", "bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("apns-topic", s.cfg.Topic)
		pushType, prio := "background", "5" // background pushes must be priority 5
		if alert {
			pushType, prio = "alert", "10"
			if m.Priority == push.PriorityNormal {
				prio = "5"
			}
		}
		req.Header.Set("apns-push-type", pushType)
		req.Header.Set("apns-priority", prio)
		exp := "0"
		if m.TTL > 0 {
			exp = strconv.FormatInt(s.now().Add(m.TTL).Unix(), 10)
		}
		req.Header.Set("apns-expiration", exp)
		if m.Data.CollapseKey != "" {
			req.Header.Set("apns-collapse-id", collapseID(m.Data.CollapseKey))
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return push.Result{Status: push.StatusError, Code: "provider_unreachable", Retryable: true}
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		var e struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(rb, &e)
		if resp.StatusCode == http.StatusForbidden && e.Reason == "ExpiredProviderToken" && attempt == 0 {
			stale = ver
			continue
		}
		return classify(resp.StatusCode, e.Reason)
	}
	return push.Result{Status: push.StatusError, Code: "provider_auth_failed", Retryable: true}
}

// classify maps an APNs status and reason to a push.Result. Only tokens Apple
// says are dead become invalid_token; configuration problems such as
// DeviceTokenNotForTopic stay errors so a misconfigured relay cannot make
// instances delete healthy devices.
func classify(status int, reason string) push.Result {
	switch {
	case status == http.StatusOK:
		return push.OK
	case status == http.StatusGone || reason == "Unregistered" || reason == "BadDeviceToken":
		return push.Result{Status: push.StatusInvalidToken, Code: "unregistered"}
	case status == http.StatusTooManyRequests:
		return push.Result{Status: push.StatusError, Code: "provider_throttled", Retryable: true}
	case status >= 500:
		return push.Result{Status: push.StatusError, Code: "provider_unavailable", Retryable: true}
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return push.Result{Status: push.StatusError, Code: "provider_auth_failed"}
	case reason == "DeviceTokenNotForTopic":
		return push.Result{Status: push.StatusError, Code: "topic_mismatch"}
	default:
		return push.Result{Status: push.StatusError, Code: "provider_rejected"}
	}
}
