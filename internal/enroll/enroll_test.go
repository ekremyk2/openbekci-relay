package enroll

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestBlocked(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"224.0.0.1", "255.255.255.255", "192.0.0.1", "198.18.0.1", "::1", "fe80::1", "fd00:ec2::254", "fc00::1", "::",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "ff02::1", "2001:db8::1",
	} {
		if !Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s wrongly blocked", s)
		}
	}
}

func TestParseBaseURL(t *testing.T) {
	good := map[string]string{
		"https://bekci.example.org":      "https://bekci.example.org/.well-known/openbekci.json",
		"https://bekci.example.org/":     "https://bekci.example.org/.well-known/openbekci.json",
		"https://bekci.example.org:8443": "https://bekci.example.org:8443/.well-known/openbekci.json",
		"https://example.org/bekci/":     "https://example.org/bekci/.well-known/openbekci.json",
	}
	for in, want := range good {
		u, err := ParseBaseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%s -> %v %v", in, u, err)
		}
	}
	for _, in := range []string{"http://x.example", "ftp://x.example", "https://", "https://u:p@x.example", "https://x.example?a=b", "https://x.example#f", "x.example", "", "https://%zz"} {
		if _, err := ParseBaseURL(in); !errors.Is(err, ErrBadURL) {
			t.Errorf("%q accepted (%v)", in, err)
		}
	}
}

// start serves a document over TLS on loopback and returns a verifier that
// resolves "bekci.test" to it. AllowBlocked lets the test reach loopback.
func start(t *testing.T, h http.HandlerFunc) (*Verifier, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	// The httptest certificate is for 127.0.0.1 / example.com; dial the real
	// address but present whatever name the URL has.
	v := &Verifier{
		Resolver:     fakeResolver{"bekci.test": {netip.MustParseAddr("127.0.0.1")}},
		TLSConfig:    &tls.Config{InsecureSkipVerify: true},
		AllowBlocked: true,
	}
	return v, "https://bekci.test:" + u.Port()
}

func doc(challenge string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openbekci.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"api":"v1","relay_enrollment":{"challenge":"` + challenge + `"}}`))
	}
}

func TestVerify(t *testing.T) {
	v, base := start(t, doc("the-right-challenge-123"))
	if err := v.Verify(t.Context(), base, "the-right-challenge-123"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := v.Verify(t.Context(), base, "the-wrong-challenge-123"); !errors.Is(err, ErrMismatch) {
		t.Errorf("mismatch: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	t.Run("no pending challenge", func(t *testing.T) {
		v, base := start(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"api":"v1"}`)) })
		if err := v.Verify(t.Context(), base, "x"); !errors.Is(err, ErrBadDocument) {
			t.Errorf("%v", err)
		}
	})
	t.Run("not json", func(t *testing.T) {
		v, base := start(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) })
		if err := v.Verify(t.Context(), base, "x"); !errors.Is(err, ErrBadDocument) {
			t.Errorf("%v", err)
		}
	})
	t.Run("redirects are not followed", func(t *testing.T) {
		hits := 0
		v, base := start(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				hits++
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		})
		if err := v.Verify(t.Context(), base, "x"); !errors.Is(err, ErrUnreachable) {
			t.Errorf("%v", err)
		}
		if hits != 0 {
			t.Error("redirect followed")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		v, base := start(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
		if err := v.Verify(t.Context(), base, "x"); !errors.Is(err, ErrUnreachable) {
			t.Errorf("%v", err)
		}
	})
	t.Run("body over 64 KB", func(t *testing.T) {
		v, base := start(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"relay_enrollment":{"challenge":"` + strings.Repeat("a", MaxBody) + `"}}`))
		})
		if err := v.Verify(t.Context(), base, "x"); !errors.Is(err, ErrBadDocument) {
			t.Errorf("%v", err)
		}
	})
	t.Run("plain http refused before any request", func(t *testing.T) {
		if err := (&Verifier{}).Verify(t.Context(), "http://bekci.example.org", "x"); !errors.Is(err, ErrBadURL) {
			t.Errorf("%v", err)
		}
	})
}

func TestSSRFGuardsOnDial(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; _, _ = w.Write([]byte(`{}`)) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port := u.Port()
	v := &Verifier{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Resolver: fakeResolver{
			"loopback.test": {netip.MustParseAddr("127.0.0.1")},
			"private.test":  {netip.MustParseAddr("10.0.0.5")},
			"meta.test":     {netip.MustParseAddr("169.254.169.254")},
			"mixed.test":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")},
			"mapped.test":   {netip.MustParseAddr("::ffff:127.0.0.1")},
			"v6.test":       {netip.MustParseAddr("fd00:ec2::254")},
		},
	}
	for _, host := range []string{"loopback.test", "private.test", "meta.test", "mixed.test", "mapped.test", "v6.test"} {
		err := v.Verify(t.Context(), "https://"+host+":"+port, "x")
		if !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: %v", host, err)
		}
	}
	// IP literals are checked too, without any DNS.
	for _, lit := range []string{"https://127.0.0.1:" + port, "https://[::1]:" + port, "https://169.254.169.254", "https://192.168.0.1"} {
		if err := v.Verify(t.Context(), lit, "x"); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: %v", lit, err)
		}
	}
	// A name that does not resolve is unreachable, not blocked.
	if err := v.Verify(t.Context(), "https://nxdomain.test", "x"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("nxdomain: %v", err)
	}
	if hits != 0 {
		t.Errorf("server was contacted %d times despite guards", hits)
	}
}
