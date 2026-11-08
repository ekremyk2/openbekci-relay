// Package httpapi is the relay's HTTP surface: POST /v1/send (HMAC), POST
// /v1/enrollments, /healthz and /metrics.
package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/openbekci/openbekci-relay/internal/config"
	"github.com/openbekci/openbekci-relay/internal/enroll"
	"github.com/openbekci/openbekci-relay/internal/metrics"
	"github.com/openbekci/openbekci-relay/internal/push"
	"github.com/openbekci/openbekci-relay/internal/store"
)

// AuthScheme is the Authorization scheme of /v1/send.
const AuthScheme = "Relay-HMAC"

// Verifier checks an enrollment challenge against a base URL.
type Verifier interface {
	Verify(ctx context.Context, baseURL, challenge string) error
}

// Deps are the Server's collaborators. Now may be nil.
type Deps struct {
	Cfg      config.Config
	Store    *store.Store
	Senders  *push.Registry
	Verifier Verifier
	Log      *slog.Logger
	Metrics  *metrics.Metrics
	Now      func() time.Time
}

// Server serves the relay API.
type Server struct {
	Deps
	mu       sync.Mutex
	buckets  map[string]*rate.Limiter // per server id
	reqs     map[string]*rate.Limiter // per server id, authenticated requests
	enrollIP map[string]*rate.Limiter // per client IP
}

// New builds a Server.
func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Verifier == nil {
		d.Verifier = &enroll.Verifier{}
	}
	return &Server{Deps: d, buckets: map[string]*rate.Limiter{}, reqs: map[string]*rate.Limiter{}, enrollIP: map[string]*rate.Limiter{}}
}

// Handler returns the routed, instrumented handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/send", s.wrap("send", s.handleSend))
	mux.Handle("POST /v1/enrollments", s.wrap("enroll", s.handleEnroll))
	mux.Handle("GET /healthz", s.wrap("healthz", s.handleHealthz))
	mux.Handle("GET /metrics", s.wrap("metrics", s.handleMetrics))
	return mux
}

// reqInfo is filled by handlers and logged once per request. It holds ids,
// counts and error classes only.
type reqInfo struct {
	serverID string
	messages int
	counts   map[string]int
	errClass string
}

type ctxKey struct{}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

type handler func(w http.ResponseWriter, r *http.Request, info *reqInfo)

func (s *Server) wrap(route string, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &reqInfo{counts: map[string]int{}}
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		h(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)), info)
		d := time.Since(start)
		s.Metrics.Requests.WithLabelValues(route, strconv.Itoa(sw.code)).Inc()
		s.Metrics.Duration.WithLabelValues(route).Observe(d.Seconds())
		if route == "healthz" || route == "metrics" {
			return
		}
		attrs := []any{"route", route, "status", sw.code, "duration_ms", d.Milliseconds()}
		if info.serverID != "" {
			attrs = append(attrs, "server_id", info.serverID)
		}
		if route == "send" {
			attrs = append(attrs, "messages", info.messages)
			for _, k := range []string{"ok", "invalid_token", "rate_limited", "error", "rejected"} {
				attrs = append(attrs, k, info.counts[k])
			}
		}
		if info.errClass != "" {
			attrs = append(attrs, "error_class", info.errClass)
		}
		lvl := slog.LevelInfo
		if sw.code >= 500 {
			lvl = slog.LevelError
		} else if sw.code >= 400 {
			lvl = slog.LevelWarn
		}
		s.Log.Log(r.Context(), lvl, "request", attrs...)
	})
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *Server) fail(w http.ResponseWriter, info *reqInfo, status int, code, msg string) {
	info.errClass = code
	var e apiError
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	if err := s.Store.Ping(r.Context()); err != nil {
		s.fail(w, info, http.StatusServiceUnavailable, "db_unavailable", "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	if t := s.Cfg.MetricsToken; t != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !hmac.Equal([]byte(got), []byte(t)) {
			s.fail(w, info, http.StatusUnauthorized, "unauthorized", "metrics token required")
			return
		}
	}
	promhttp.HandlerFor(s.Metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// ComputeMAC returns the hex HMAC-SHA256 the Authorization header carries:
// hmac(secret, ts "." nonce "." hex(sha256(body))). Exported for clients and
// tests.
func ComputeMAC(secret, ts, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + nonce + "." + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(m.Sum(nil))
}

func validNonce(n string) bool {
	if len(n) < 16 || len(n) > 64 {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (s *Server) limiter(id string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.buckets[id]
	if !ok {
		l = rate.NewLimiter(rate.Limit(s.Cfg.RatePerSec), s.Cfg.Burst)
		s.buckets[id] = l
	}
	return l
}

// Result is one element of the send response.
type Result struct {
	Index     int         `json:"index"`
	Status    push.Status `json:"status"`
	Code      string      `json:"code,omitempty"`
	Retryable bool        `json:"retryable,omitempty"`
}

// SendResponse is the body of a 200 from /v1/send.
type SendResponse struct {
	Results []Result `json:"results"`
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	if r.ContentLength > s.Cfg.MaxBodyBytes {
		s.fail(w, info, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Cfg.MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.fail(w, info, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return
		}
		s.fail(w, info, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}

	srv, ok := s.authenticate(w, r, info, body)
	if !ok {
		return
	}
	info.serverID = srv.ID

	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	{
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			s.fail(w, info, http.StatusBadRequest, "bad_request", "body must be {\"messages\":[...]}")
			return
		}
	}
	if len(req.Messages) == 0 {
		s.fail(w, info, http.StatusBadRequest, "empty_batch", "messages must not be empty")
		return
	}
	if len(req.Messages) > s.Cfg.MaxBatch {
		s.fail(w, info, http.StatusBadRequest, "batch_too_large", "too many messages in one request (max "+strconv.Itoa(s.Cfg.MaxBatch)+")")
		return
	}
	info.messages = len(req.Messages)

	results := make([]Result, len(req.Messages))
	parsed := make([]push.Message, len(req.Messages))
	rejected := make([]bool, len(req.Messages))
	var pending []int
	for i, raw := range req.Messages {
		results[i].Index = i
		m, err := push.ParseMessage(raw, srv.AppID)
		if err != nil {
			var ve *push.ValidationError
			code := "invalid_message"
			if errors.As(err, &ve) {
				code = ve.Code
			}
			results[i] = Result{Index: i, Status: push.StatusError, Code: code}
			rejected[i] = true
			continue
		}
		if m.AppID != srv.AppID {
			results[i] = Result{Index: i, Status: push.StatusError, Code: "app_not_allowed"}
			rejected[i] = true
			continue
		}
		if s.Senders.Lookup(m.AppID, m.Kind) == nil {
			results[i] = Result{Index: i, Status: push.StatusError, Code: "provider_not_configured"}
			rejected[i] = true
			continue
		}
		parsed[i] = m
		pending = append(pending, i)
	}

	// Token bucket per message, then the daily quota for what is left.
	lim := s.limiter(srv.ID)
	var admitted []int
	for _, i := range pending {
		if lim.Allow() {
			admitted = append(admitted, i)
		} else {
			results[i] = Result{Index: i, Status: push.StatusRateLimited, Code: "rate_limited", Retryable: true}
		}
	}
	grant, err := s.Store.Reserve(r.Context(), srv.ID, len(admitted), srv.DailyQuota)
	if err != nil {
		s.Log.Error("quota reserve failed", "server_id", srv.ID, "error_class", "store_error")
		s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	for _, i := range admitted[grant:] {
		results[i] = Result{Index: i, Status: push.StatusRateLimited, Code: "quota_exceeded", Retryable: true}
	}
	admitted = admitted[:grant]

	dctx, cancelDispatch := context.WithTimeout(r.Context(), s.requestTimeout())
	s.dispatch(dctx, parsed, results, admitted)
	cancelDispatch()

	var okN, invN, errN, rlN int
	for i, res := range results {
		if res.Status == "" {
			results[i] = Result{Index: i, Status: push.StatusError, Code: "internal"}
			res = results[i]
		}
		label := string(res.Status)
		switch {
		case rejected[i]:
			label = "rejected"
			info.counts["rejected"]++
		case res.Status == push.StatusOK:
			okN++
		case res.Status == push.StatusInvalidToken:
			invN++
		case res.Status == push.StatusRateLimited:
			rlN++
		default:
			errN++
		}
		if !rejected[i] {
			info.counts[string(res.Status)]++
		}
		kind := string(parsed[i].Kind)
		if kind == "" {
			kind = "unknown"
		}
		s.Metrics.Messages.WithLabelValues(srv.ID, kind, label).Inc()
	}
	if err := s.Store.Record(context.WithoutCancel(r.Context()), srv.ID, okN, invN, errN, rlN); err != nil {
		s.Log.Error("counter update failed", "server_id", srv.ID, "error_class", "store_error")
	}
	writeJSON(w, http.StatusOK, SendResponse{Results: results})
}

// dispatch sends the admitted messages concurrently (bounded) and writes the
// outcomes into results at their indexes. ctx carries the whole-batch
// deadline: messages that have not finished (or not started) when it ends are
// reported as retryable request_deadline errors, so a slow provider cannot
// hold the response past the server's write timeout.
func (s *Server) dispatch(ctx context.Context, msgs []push.Message, results []Result, idx []int) {
	sem := make(chan struct{}, s.Cfg.SendConcurrency)
	var wg sync.WaitGroup
	for _, i := range idx {
		if ctx.Err() != nil { // select picks randomly when both cases are ready
			results[i] = Result{Index: i, Status: push.StatusError, Code: "request_deadline", Retryable: true}
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = Result{Index: i, Status: push.StatusError, Code: "request_deadline", Retryable: true}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// A panicking sender must not take the whole relay down: the
			// goroutine is not covered by net/http's per-request recover.
			defer func() {
				if recover() != nil {
					s.Log.Error("sender panicked", "error_class", "sender_panic")
					results[i] = Result{Index: i, Status: push.StatusError, Code: "internal"}
				}
			}()
			m := msgs[i]
			cctx, cancel := context.WithTimeout(ctx, s.Cfg.SendTimeout)
			defer cancel()
			start := time.Now()
			res := s.Senders.Lookup(m.AppID, m.Kind).Send(cctx, m)
			if ctx.Err() != nil && res.Status != push.StatusOK && res.Status != push.StatusInvalidToken {
				res = push.Result{Status: push.StatusError, Code: "request_deadline", Retryable: true}
			}
			s.Metrics.ProviderTime.WithLabelValues(string(m.Kind)).Observe(time.Since(start).Seconds())
			outcome := "ok"
			switch res.Status {
			case push.StatusOK:
			case push.StatusInvalidToken:
				outcome = "invalid_token"
			default:
				outcome = "error"
			}
			s.Metrics.Provider.WithLabelValues(string(m.Kind), outcome).Inc()
			if res.Status == "" {
				res.Status, res.Code = push.StatusError, "internal"
			}
			results[i] = Result{Index: i, Status: res.Status, Code: res.Code, Retryable: res.Retryable}
		}()
	}
	wg.Wait()
}

// authenticate verifies the Relay-HMAC header. Until the MAC verifies, every
// failure is the same generic 401 so a prober learns nothing about which
// server ids exist.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, info *reqInfo, body []byte) (store.Server, bool) {
	deny := func(reason string) (store.Server, bool) {
		s.Metrics.AuthFailures.WithLabelValues(reason).Inc()
		s.fail(w, info, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return store.Server{}, false
	}
	h := r.Header.Get("Authorization")
	rest, found := strings.CutPrefix(h, AuthScheme+" ")
	if !found {
		return deny("missing")
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 4 {
		return deny("malformed")
	}
	id, ts, nonce, mac := parts[0], parts[1], parts[2], parts[3]
	if !validNonce(nonce) {
		return deny("malformed")
	}
	srv, err := s.Store.Server(r.Context(), id)
	secret := srv.Secret
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
			return store.Server{}, false
		}
		secret = "x" // compute a MAC anyway: no timing signal for unknown ids
	}
	want := ComputeMAC(secret, ts, nonce, body)
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(mac))) || err != nil {
		return deny("bad_mac")
	}
	info.serverID = srv.ID

	// From here the caller is authentic, so specific errors are safe.
	if srv.Status != store.StatusActive {
		s.Metrics.AuthFailures.WithLabelValues("disabled").Inc()
		s.fail(w, info, http.StatusForbidden, "server_disabled", "this server is disabled on the relay")
		return store.Server{}, false
	}
	tsec, perr := strconv.ParseInt(ts, 10, 64)
	skew := s.Now().Sub(time.Unix(tsec, 0))
	if perr != nil || skew > s.Cfg.ClockSkew || skew < -s.Cfg.ClockSkew {
		s.Metrics.AuthFailures.WithLabelValues("stale_timestamp").Inc()
		s.fail(w, info, http.StatusUnauthorized, "stale_timestamp", "timestamp outside the accepted window; check the server clock")
		return store.Server{}, false
	}
	if !s.requestLimiter(srv.ID).Allow() {
		s.Metrics.AuthFailures.WithLabelValues("rate_limited").Inc()
		w.Header().Set("Retry-After", "1")
		s.fail(w, info, http.StatusTooManyRequests, "rate_limited", "too many requests for this server")
		return store.Server{}, false
	}
	if err := s.Store.UseNonce(r.Context(), srv.ID, nonce, 2*s.Cfg.ClockSkew); err != nil {
		if errors.Is(err, store.ErrReplay) {
			s.Metrics.AuthFailures.WithLabelValues("replay").Inc()
			s.fail(w, info, http.StatusUnauthorized, "replayed_nonce", "nonce already used")
		} else {
			s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
		}
		return store.Server{}, false
	}
	return srv, true
}

// ClientIP returns the caller's address, honouring X-Forwarded-For only when
// the direct peer is a trusted proxy (the rightmost untrusted hop is used).
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	isTrusted := func(h string) bool {
		a, err := netip.ParseAddr(strings.TrimSpace(h))
		if err != nil {
			return false
		}
		for _, p := range trusted {
			if p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	}
	if !isTrusted(host) {
		return host
	}
	xff := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(xff) - 1; i >= 0; i-- {
		h := strings.TrimSpace(xff[i])
		if h == "" {
			continue
		}
		if !isTrusted(h) {
			return h
		}
	}
	return host
}

// defaultRequestTimeout bounds one /v1/send batch when the config leaves
// RequestTimeout unset. It stays below the HTTP server's write timeout.
const defaultRequestTimeout = 60 * time.Second

func (s *Server) requestTimeout() time.Duration {
	if s.Cfg.RequestTimeout > 0 {
		return s.Cfg.RequestTimeout
	}
	return defaultRequestTimeout
}

// requestLimiter bounds authenticated requests per server (same rate and burst
// as the message bucket, so one request costs at most one message's worth).
// Every authenticated request stores a nonce row before any other work, so
// without this a server holding a valid secret could grow the nonce table at
// wire speed for the whole ten-minute retention.
func (s *Server) requestLimiter(id string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.reqs[id]
	if !ok {
		l = rate.NewLimiter(rate.Limit(s.Cfg.RatePerSec), s.Cfg.Burst)
		s.reqs[id] = l
	}
	return l
}
