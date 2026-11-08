// Package enroll verifies enrollment challenges by fetching an instance's
// discovery document under SSRF guards: DNS is resolved first and every
// resolved address is checked (private, loopback, link-local, metadata and
// other special ranges are refused) before the connection is made to that
// exact address; HTTPS only, no redirects, 64 KB body cap, 5 s total timeout.
package enroll

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxBody is the discovery document size cap.
	MaxBody = 64 << 10
	// Timeout is the total budget for the fetch, DNS included.
	Timeout   = 5 * time.Second
	wellKnown = "/.well-known/openbekci.json"
)

// Errors returned by Verify. They carry no remote content.
var (
	ErrBadURL        = errors.New("base_url must be an https URL with a host, no credentials, query or fragment")
	ErrBlockedTarget = errors.New("base_url resolves to a disallowed address")
	ErrUnreachable   = errors.New("discovery document could not be fetched")
	ErrBadDocument   = errors.New("discovery document is not valid")
	ErrMismatch      = errors.New("challenge does not match")
)

var blocked = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	// IPv6 forms that embed or tunnel an IPv4 address (IPv4-compatible,
	// NAT64, 6to4, Teredo) are refused outright: the embedded address may be
	// loopback or metadata and some stacks route them there.
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
	"::1/128", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	"192.88.99.0/24",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// Blocked reports whether ip is in a range the relay must never contact.
// IPv4-mapped IPv6 addresses are unmapped first.
func Blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Verifier fetches and checks discovery documents.
type Verifier struct {
	// Resolver and TLSConfig/AllowBlocked exist for tests; production leaves
	// them zero.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	TLSConfig    *tls.Config
	AllowBlocked bool
}

// ParseBaseURL validates base_url and returns the discovery document URL.
func ParseBaseURL(base string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Hostname(), "%") {
		return nil, ErrBadURL
	}
	u.Path = strings.TrimRight(u.Path, "/") + wellKnown
	u.RawPath = ""
	return u, nil
}

// Verify fetches <base>/.well-known/openbekci.json and checks that
// relay_enrollment.challenge equals challenge.
func (v *Verifier) Verify(ctx context.Context, baseURL, challenge string) error {
	u, err := ParseBaseURL(baseURL)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	resolver := v.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: Timeout}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   v.TLSConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, ErrBadURL
			}
			var ips []netip.Addr
			if a, perr := netip.ParseAddr(host); perr == nil {
				ips = []netip.Addr{a}
			} else if ips, err = resolver.LookupNetIP(ctx, "ip", host); err != nil || len(ips) == 0 {
				return nil, ErrUnreachable
			}
			// Reject if ANY answer is disallowed (defeats mixed answers), then
			// connect to the checked address itself, not to the name, so a
			// second DNS lookup cannot rebind to a different address.
			if !v.AllowBlocked {
				for _, ip := range ips {
					if Blocked(ip) {
						return nil, ErrBlockedTarget
					}
				}
			}
			var last error
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ErrBadURL
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openbekci-relay-enroll")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedTarget) {
			return ErrBlockedTarget
		}
		return ErrUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrUnreachable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return ErrUnreachable
	}
	if len(body) > MaxBody {
		return fmt.Errorf("%w: body over %d bytes", ErrBadDocument, MaxBody)
	}
	var doc struct {
		RelayEnrollment struct {
			Challenge string `json:"challenge"`
		} `json:"relay_enrollment"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.RelayEnrollment.Challenge == "" {
		return fmt.Errorf("%w: no relay_enrollment.challenge", ErrBadDocument)
	}
	if subtle.ConstantTimeCompare([]byte(doc.RelayEnrollment.Challenge), []byte(challenge)) != 1 {
		return ErrMismatch
	}
	return nil
}
