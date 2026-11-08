// Package config reads the relay configuration from RELAY_* environment
// variables. Every secret has a _FILE variant that reads the value from a file
// (Docker/Kubernetes secrets); setting both is an error.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Enrollment modes.
const (
	EnrollOpen   = "open"
	EnrollInvite = "invite"
	EnrollClosed = "closed"
)

// App is one white-label app: the credentials the relay holds for an app_id.
type App struct {
	ID string

	FCMCredentials []byte // service account JSON; nil when FCM is not served

	APNsKey     []byte // .p8 contents; nil when APNs is not served
	APNsKeyID   string
	APNsTeamID  string
	APNsTopic   string
	APNsSandbox bool
}

// Config is the full relay configuration.
type Config struct {
	Listen          string
	DBPath          string
	LogLevel        string
	ShutdownTimeout time.Duration

	Enrollment string

	RatePerSec float64
	Burst      int
	// DailyQuota is the default for verified servers, UnverifiedDailyQuota for
	// manually enrolled ones. Values <= 0 mean unlimited.
	DailyQuota           int64
	UnverifiedDailyQuota int64

	MaxBodyBytes int64
	MaxBatch     int
	ClockSkew    time.Duration

	EnrollPerMinPerIP int
	TrustedProxies    []netip.Prefix

	MetricsToken string

	SendTimeout     time.Duration
	SendConcurrency int

	// DevLogSender routes every app to the log sender instead of FCM/APNs.
	DevLogSender bool
	Apps         []App
}

const maxApps = 32

type env struct {
	get  func(string) (string, bool)
	read func(string) ([]byte, error)
	errs []error
}

func (e *env) fail(format string, a ...any) { e.errs = append(e.errs, fmt.Errorf(format, a...)) }

// str returns RELAY_<name> or its default.
func (e *env) str(name, def string) string {
	if v, ok := e.get(name); ok {
		return v
	}
	return def
}

// secret returns the value of name, or the contents of name_FILE (trailing
// newline trimmed). ok is false when neither is set.
func (e *env) secret(name string) (string, bool) {
	v, hasV := e.get(name)
	f, hasF := e.get(name + "_FILE")
	switch {
	case hasV && hasF:
		e.fail("RELAY_%s and RELAY_%s_FILE are both set", name, name)
	case hasF:
		b, err := e.read(f)
		if err != nil {
			e.fail("RELAY_%s_FILE: %w", name, err)
			return "", false
		}
		return strings.TrimRight(string(b), "\r\n"), true
	case hasV:
		return v, true
	}
	return "", false
}

func (e *env) dur(name string, def time.Duration) time.Duration {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		e.fail("RELAY_%s: want a positive duration like 5m", name)
		return def
	}
	return d
}

func (e *env) int64(name string, def int64) int64 {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		e.fail("RELAY_%s: want an integer", name)
		return def
	}
	return n
}

func (e *env) float(name string, def float64) float64 {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n <= 0 {
		e.fail("RELAY_%s: want a positive number", name)
		return def
	}
	return n
}

func (e *env) boolean(name string) bool {
	v, ok := e.get(name)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail("RELAY_%s: want true or false", name)
	}
	return b
}

// Load builds a Config from the process environment.
func Load() (Config, error) {
	return LoadFrom(func(k string) (string, bool) {
		v, ok := os.LookupEnv(k)
		return v, ok && v != ""
	}, os.ReadFile)
}

// LoadFrom builds a Config from the given lookup (keys are full names such as
// RELAY_LISTEN) and file reader. It is exported for tests.
func LoadFrom(lookup func(string) (string, bool), read func(string) ([]byte, error)) (Config, error) {
	return load(lookup, read, true)
}

// LoadAdmin is Load for the admin subcommands: apps are not required.
func LoadAdmin() (Config, error) {
	return load(func(k string) (string, bool) {
		v, ok := os.LookupEnv(k)
		return v, ok && v != ""
	}, os.ReadFile, false)
}

func load(lookup func(string) (string, bool), read func(string) ([]byte, error), withApps bool) (Config, error) {
	e := &env{get: lookup, read: read}
	// All names below are given without the RELAY_ prefix.
	pre := func(n string) string { return "RELAY_" + n }
	g := e.get
	e.get = func(k string) (string, bool) { return g(pre(k)) }

	c := Config{
		Listen:               e.str("LISTEN", ":8080"),
		DBPath:               e.str("DB_PATH", "/var/lib/openbekci-relay/relay.db"),
		LogLevel:             e.str("LOG_LEVEL", "info"),
		ShutdownTimeout:      e.dur("SHUTDOWN_TIMEOUT", 20*time.Second),
		Enrollment:           e.str("ENROLLMENT", EnrollInvite),
		RatePerSec:           e.float("RATE_PER_SEC", 60),
		Burst:                int(e.int64("BURST", 600)),
		DailyQuota:           e.int64("DAILY_QUOTA", 100000),
		UnverifiedDailyQuota: e.int64("UNVERIFIED_DAILY_QUOTA", 1000),
		MaxBodyBytes:         e.int64("MAX_BODY_BYTES", 256<<10),
		MaxBatch:             int(e.int64("MAX_BATCH", 500)),
		ClockSkew:            e.dur("CLOCK_SKEW", 5*time.Minute),
		EnrollPerMinPerIP:    int(e.int64("ENROLL_PER_MIN_PER_IP", 10)),
		SendTimeout:          e.dur("SEND_TIMEOUT", 10*time.Second),
		SendConcurrency:      int(e.int64("SEND_CONCURRENCY", 32)),
		DevLogSender:         e.boolean("DEV_LOG_SENDER"),
	}
	switch c.Enrollment {
	case EnrollOpen, EnrollInvite, EnrollClosed:
	default:
		e.fail("RELAY_ENROLLMENT: want open, invite or closed")
	}
	if c.Burst < 1 {
		e.fail("RELAY_BURST: must be at least 1")
	}
	if c.MaxBatch < 1 || c.SendConcurrency < 1 || c.EnrollPerMinPerIP < 1 {
		e.fail("RELAY_MAX_BATCH, RELAY_SEND_CONCURRENCY and RELAY_ENROLL_PER_MIN_PER_IP must be at least 1")
	}
	if c.MaxBodyBytes < 1024 {
		e.fail("RELAY_MAX_BODY_BYTES: must be at least 1024")
	}
	if v, ok := e.get("TRUSTED_PROXIES"); ok {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			p, err := netip.ParsePrefix(part)
			if err != nil {
				a, aerr := netip.ParseAddr(part)
				if aerr != nil {
					e.fail("RELAY_TRUSTED_PROXIES: %q is not a CIDR or address", part)
					continue
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			c.TrustedProxies = append(c.TrustedProxies, p)
		}
	}
	if t, ok := e.secret("METRICS_TOKEN"); ok {
		c.MetricsToken = t
	}

	// Apps: RELAY_APP_<n>_ID plus its credentials, n = 1..maxApps.
	seen := map[string]bool{}
	for n := 1; withApps && n <= maxApps; n++ {
		p := "APP_" + strconv.Itoa(n) + "_"
		id, ok := e.get(p + "ID")
		if !ok {
			continue
		}
		if seen[id] {
			e.fail("RELAY_%sID: app id %q configured twice", p, id)
			continue
		}
		seen[id] = true
		a := App{ID: id}
		if v, ok := e.secret(p + "FCM_CREDENTIALS"); ok {
			a.FCMCredentials = []byte(v)
		}
		if v, ok := e.secret(p + "APNS_KEY"); ok {
			a.APNsKey = []byte(v)
			a.APNsKeyID = e.str(p+"APNS_KEY_ID", "")
			a.APNsTeamID = e.str(p+"APNS_TEAM_ID", "")
			a.APNsTopic = e.str(p+"APNS_TOPIC", id)
			if a.APNsKeyID == "" || a.APNsTeamID == "" {
				e.fail("RELAY_%sAPNS_KEY needs RELAY_%sAPNS_KEY_ID and RELAY_%sAPNS_TEAM_ID", p, p, p)
			}
			if v, ok := e.get(p + "APNS_SANDBOX"); ok {
				b, err := strconv.ParseBool(v)
				if err != nil {
					e.fail("RELAY_%sAPNS_SANDBOX: want true or false", p)
				}
				a.APNsSandbox = b
			}
		}
		if a.FCMCredentials == nil && a.APNsKey == nil && !c.DevLogSender {
			e.fail("RELAY_%sID %q has no FCM or APNs credentials (set RELAY_DEV_LOG_SENDER=true for development)", p, id)
		}
		c.Apps = append(c.Apps, a)
	}
	if withApps && len(c.Apps) == 0 {
		e.fail("no app configured: set RELAY_APP_1_ID and credentials")
	}
	if len(e.errs) > 0 {
		return c, errors.Join(e.errs...)
	}
	return c, nil
}
