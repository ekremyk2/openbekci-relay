package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openbekci/openbekci-relay/internal/config"
	"github.com/openbekci/openbekci-relay/internal/enroll"
	"github.com/openbekci/openbekci-relay/internal/store"
)

type beginRequest struct {
	AppID      string `json:"app_id"`
	InviteCode string `json:"invite_code"`
}

// BeginResponse is the body of a 201 from /v1/enrollments/begin.
type BeginResponse struct {
	EnrollmentID    string `json:"enrollment_id"`
	EnrollmentToken string `json:"enrollment_token"`
	Challenge       string `json:"challenge"`
	ExpiresAt       string `json:"expires_at"` // RFC 3339, UTC
}

type completeRequest struct {
	EnrollmentID    string `json:"enrollment_id"`
	EnrollmentToken string `json:"enrollment_token"`
	BaseURL         string `json:"base_url"`
	Manual          bool   `json:"manual"`
}

// enrollGate applies the per-IP limit and the closed-mode check shared by both
// enrollment steps. It writes the error response itself.
func (s *Server) enrollGate(w http.ResponseWriter, r *http.Request, info *reqInfo, result func(string)) bool {
	if l := s.enrollLimiter(ClientIP(r, s.Cfg.TrustedProxies)); l == nil || !l.Allow() {
		result("rate_limited")
		w.Header().Set("Retry-After", "60")
		s.fail(w, info, http.StatusTooManyRequests, "rate_limited", "too many enrollment attempts")
		return false
	}
	if s.Cfg.Enrollment == config.EnrollClosed {
		result("closed")
		s.fail(w, info, http.StatusForbidden, "enrollment_closed", "this relay is not accepting enrollments")
		return false
	}
	return true
}

// decodeStrict reads a small JSON body into v, rejecting unknown keys and
// trailing data.
func (s *Server) decodeStrict(w http.ResponseWriter, r *http.Request, info *reqInfo, v any, shape string) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	if err != nil {
		s.fail(w, info, http.StatusBadRequest, "bad_request", "could not read body")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		s.fail(w, info, http.StatusBadRequest, "bad_request", "body must be a JSON object with "+shape)
		return false
	}
	return true
}

func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	result := func(res string) { s.Metrics.Enrollments.WithLabelValues("begin_" + res).Inc() }
	if !s.enrollGate(w, r, info, result) {
		return
	}
	var req beginRequest
	if !s.decodeStrict(w, r, info, &req, "app_id, invite_code") {
		return
	}
	if !s.Senders.HasApp(req.AppID) {
		result("unknown_app")
		s.fail(w, info, http.StatusBadRequest, "unknown_app_id", "app_id is not served by this relay")
		return
	}
	var invite store.Invite
	if req.InviteCode != "" {
		var err error
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
	p, token, err := s.Store.BeginEnrollment(r.Context(), req.AppID, req.InviteCode, invite.Manual)
	switch {
	case errors.Is(err, store.ErrTooManyPending):
		result("too_many_pending")
		w.Header().Set("Retry-After", "60")
		s.fail(w, info, http.StatusTooManyRequests, "too_many_pending", "too many enrollments in progress; retry later")
		return
	case err != nil:
		s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	result("ok")
	writeJSON(w, http.StatusCreated, BeginResponse{
		EnrollmentID: p.ID, EnrollmentToken: token, Challenge: p.Challenge, ExpiresAt: p.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleEnrollComplete(w http.ResponseWriter, r *http.Request, info *reqInfo) {
	result := func(res string) { s.Metrics.Enrollments.WithLabelValues(res).Inc() }
	if !s.enrollGate(w, r, info, result) {
		return
	}
	var req completeRequest
	if !s.decodeStrict(w, r, info, &req, "enrollment_id, enrollment_token, base_url, manual") {
		return
	}
	invalid := func() {
		result("enrollment_invalid")
		s.fail(w, info, http.StatusForbidden, "enrollment_invalid", "enrollment is unknown, expired, finished or the token is wrong")
	}
	if len(req.EnrollmentID) > 64 || len(req.EnrollmentToken) > 128 {
		invalid()
		return
	}
	p, err := s.Store.OpenPending(r.Context(), req.EnrollmentID, req.EnrollmentToken)
	if errors.Is(err, store.ErrPendingInvalid) {
		invalid()
		return
	} else if err != nil {
		s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	params := store.EnrollParams{
		NewServerParams: store.NewServerParams{AppID: p.AppID, BaseURL: req.BaseURL, Verified: true, DailyQuota: s.Cfg.DailyQuota},
		InviteHash:      p.InviteHash,
		PendingID:       p.ID,
	}
	if req.Manual {
		if !p.Manual {
			result("invite_not_manual")
			s.fail(w, info, http.StatusForbidden, "invite_not_manual", "manual enrollment needs an invite issued as manual")
			return
		}
		params.Verified, params.DailyQuota = false, s.Cfg.UnverifiedDailyQuota
		if u, err := url.Parse(req.BaseURL); err != nil || u.Hostname() == "" {
			params.BaseURL = "" // manual: base_url is informational only
		}
	} else {
		// Count the attempt first (atomically): a pending enrollment survives
		// only MaxPendingAttempts failed fetches.
		if err := s.Store.ConsumeAttempt(r.Context(), p.ID); err != nil {
			if errors.Is(err, store.ErrPendingInvalid) {
				invalid()
			} else {
				s.fail(w, info, http.StatusInternalServerError, "internal", "internal error")
			}
			return
		}
		if err := s.Verifier.Verify(r.Context(), req.BaseURL, p.Challenge); err != nil {
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
	}

	srv, err := s.Store.CommitEnrollment(r.Context(), params)
	switch {
	case errors.Is(err, store.ErrPendingInvalid):
		invalid()
		return
	case errors.Is(err, store.ErrInviteInvalid):
		result("invite_invalid")
		s.fail(w, info, http.StatusForbidden, "invite_invalid", "invite code is unknown, used or expired")
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
