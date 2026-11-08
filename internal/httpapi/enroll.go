package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/openbekci/openbekci-relay/internal/config"
	"github.com/openbekci/openbekci-relay/internal/enroll"
	"github.com/openbekci/openbekci-relay/internal/store"
)

const (
	maxEnrollBody = 8 << 10
	challengeTTL  = 24 * time.Hour // how long a used challenge is remembered
)

type enrollRequest struct {
	BaseURL    string `json:"base_url"`
	Challenge  string `json:"challenge"`
	AppID      string `json:"app_id"`
	InviteCode string `json:"invite_code"`
	Manual     bool   `json:"manual"`
}

// EnrollResponse is the body of a 201 from /v1/enrollments.
type EnrollResponse struct {
	ServerID     string `json:"server_id"`
	ServerSecret string `json:"server_secret"`
	Verified     bool   `json:"verified"`
}

// maxEnrollLimiters bounds the per-IP limiter map.
const maxEnrollLimiters = 10000

// RateKey is the key a client address is rate limited under: IPv4-mapped
// addresses collapse to IPv4, letter case and zone ids do not matter, and an
// IPv6 address is reduced to its /64 (one subscriber typically controls a
// whole /64, so per-address keys would be free to rotate). Unparseable input
// is returned unchanged.
func RateKey(ip string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// enrollLimiter returns the limiter for a client address, or nil when the map
// is full of active clients (the caller then refuses the request: failing
// closed beats letting an address-churning flood reset everyone's budget).
func (s *Server) enrollLimiter(ip string) *rate.Limiter {
	key := RateKey(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.enrollIP[key]
	if ok {
		return l
	}
	if len(s.enrollIP) >= maxEnrollLimiters {
		// Drop only idle clients (full bucket = nothing to remember).
		for k, v := range s.enrollIP {
			if v.Tokens() >= float64(s.Cfg.EnrollPerMinPerIP) {
				delete(s.enrollIP, k)
			}
		}
		if len(s.enrollIP) >= maxEnrollLimiters {
			return nil
		}
	}
	per := float64(s.Cfg.EnrollPerMinPerIP)
	l = rate.NewLimiter(rate.Limit(per/60), s.Cfg.EnrollPerMinPerIP)
	s.enrollIP[key] = l
	return l
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	result := func(res string) { s.Metrics.Enrollments.WithLabelValues(res).Inc() }
	if l := s.enrollLimiter(ClientIP(r, s.Cfg.TrustedProxies)); l == nil || !l.Allow() {
		result("rate_limited")
		w.Header().Set("Retry-After", "60")
		s.fail(w, info, http.StatusTooManyRequests, "rate_limited", "too many enrollment attempts")
		return
	}
	if s.Cfg.Enrollment == config.EnrollClosed {
		result("closed")
		s.fail(w, info, http.StatusForbidden, "enrollment_closed", "this relay is not accepting enrollments")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	if err != nil {
		s.fail(w, info, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}
	var req enrollRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, info, http.StatusBadRequest, "bad_request", "body must be a JSON object with base_url, challenge, app_id, invite_code, manual")
		return
	}
	if !s.Senders.HasApp(req.AppID) {
		result("unknown_app")
		s.fail(w, info, http.StatusBadRequest, "unknown_app_id", "app_id is not served by this relay")
		return
	}

	var invite store.Invite
	haveInvite := req.InviteCode != ""
	if haveInvite {
		invite, err = s.Store.PeekInvite(r.Context(), req.InviteCode)
		if err != nil {
			if errors.Is(err, store.ErrInviteInvalid) {
				result("invite_invalid")
				s.fail(w, info, http.StatusForbidden, "invite_invalid", "invite code is unknown, used or expired")
			} else {
				s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
			}
			return
		}
	} else if s.Cfg.Enrollment == config.EnrollInvite {
		result("invite_required")
		s.fail(w, info, http.StatusForbidden, "invite_required", "this relay requires an invite code")
		return
	}

	p := store.EnrollParams{
		NewServerParams: store.NewServerParams{AppID: req.AppID, BaseURL: req.BaseURL, Verified: true, DailyQuota: s.Cfg.DailyQuota},
		InviteCode:      req.InviteCode,
		ChallengeTTL:    challengeTTL,
	}
	if req.Manual {
		if !haveInvite || !invite.Manual {
			result("invite_not_manual")
			s.fail(w, info, http.StatusForbidden, "invite_not_manual", "manual enrollment needs an invite issued as manual")
			return
		}
		p.Verified, p.DailyQuota = false, s.Cfg.UnverifiedDailyQuota
		if u, err := url.Parse(req.BaseURL); err != nil || u.Hostname() == "" {
			p.BaseURL = "" // manual: base_url is informational only
		}
	} else {
		if l := len(req.Challenge); l < 16 || l > 256 {
			s.fail(w, info, http.StatusBadRequest, "bad_challenge", "challenge must be 16 to 256 characters")
			return
		}
		if err := s.Verifier.Verify(r.Context(), req.BaseURL, req.Challenge); err != nil {
			code, status := "discovery_unreachable", http.StatusUnprocessableEntity
			switch {
			case errors.Is(err, enroll.ErrBadURL):
				code, status = "invalid_base_url", http.StatusBadRequest
			case errors.Is(err, enroll.ErrBlockedTarget):
				code = "base_url_blocked"
			case errors.Is(err, enroll.ErrBadDocument):
				code = "discovery_invalid"
			case errors.Is(err, enroll.ErrMismatch):
				code = "challenge_mismatch"
			}
			result(code)
			s.fail(w, info, status, code, err.Error())
			return
		}
		p.ChallengeHash = store.ChallengeHash(req.Challenge)
	}

	srv, err := s.Store.CommitEnrollment(r.Context(), p)
	switch {
	case errors.Is(err, store.ErrInviteInvalid):
		result("invite_invalid")
		s.fail(w, info, http.StatusForbidden, "invite_invalid", "invite code is unknown, used or expired")
		return
	case errors.Is(err, store.ErrChallengeUsed):
		result("challenge_used")
		s.fail(w, info, http.StatusConflict, "challenge_used", "challenge was already used")
		return
	case err != nil:
		s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	info.serverID = srv.ID
	result("ok")
	s.Log.Info("server enrolled", "server_id", srv.ID, "app_id", srv.AppID, "verified", srv.Verified)
	writeJSON(w, http.StatusCreated, EnrollResponse{ServerID: srv.ID, ServerSecret: srv.Secret, Verified: srv.Verified})
}
