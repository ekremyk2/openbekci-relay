package httpapi

import (
	"net/netip"
	"strings"

	"golang.org/x/time/rate"
)

const (
	maxEnrollBody = 8 << 10
)

// EnrollResponse is the body of a 201 from /v1/enrollments/complete.
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
