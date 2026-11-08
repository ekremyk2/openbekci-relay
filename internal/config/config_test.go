package config

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func reader(files map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, fs.ErrNotExist
	}
}

func TestDefaults(t *testing.T) {
	c, err := LoadFrom(lookup(map[string]string{"RELAY_APP_1_ID": "org.x.app", "RELAY_DEV_LOG_SENDER": "true"}), reader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.Enrollment != EnrollInvite || c.RatePerSec != 60 || c.Burst != 600 || c.MaxBodyBytes != 256<<10 ||
		c.ClockSkew != 5*time.Minute || c.MaxBatch != 500 || c.EnrollPerMinPerIP != 10 || !c.DevLogSender || len(c.Apps) != 1 {
		t.Errorf("%+v", c)
	}
}

func TestSecretsFromFilesAndInline(t *testing.T) {
	env := map[string]string{
		"RELAY_APP_1_ID":                   "org.x.app",
		"RELAY_APP_1_FCM_CREDENTIALS_FILE": "/run/secrets/fcm",
		"RELAY_APP_1_APNS_KEY_FILE":        "/run/secrets/apns",
		"RELAY_APP_1_APNS_KEY_ID":          "KID",
		"RELAY_APP_1_APNS_TEAM_ID":         "TEAM",
		"RELAY_APP_1_APNS_SANDBOX":         "true",
		"RELAY_APP_2_ID":                   "org.y.app",
		"RELAY_APP_2_APNS_KEY":             "inline-pem",
		"RELAY_APP_2_APNS_KEY_ID":          "K2",
		"RELAY_APP_2_APNS_TEAM_ID":         "T2",
		"RELAY_APP_2_APNS_TOPIC":           "org.y.topic",
		"RELAY_METRICS_TOKEN_FILE":         "/run/secrets/metrics",
		"RELAY_TRUSTED_PROXIES":            "10.0.0.0/8, 192.168.1.5",
	}
	c, err := LoadFrom(lookup(env), reader(map[string]string{
		"/run/secrets/fcm": `{"project_id":"p"}` + "\n", "/run/secrets/apns": "pem\n", "/run/secrets/metrics": "tok\r\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.Apps[0], c.Apps[1]
	if string(a.FCMCredentials) != `{"project_id":"p"}` || string(a.APNsKey) != "pem" || a.APNsTopic != "org.x.app" || !a.APNsSandbox {
		t.Errorf("app1 %+v", a)
	}
	if string(b.APNsKey) != "inline-pem" || b.APNsTopic != "org.y.topic" || b.FCMCredentials != nil {
		t.Errorf("app2 %+v", b)
	}
	if c.MetricsToken != "tok" || len(c.TrustedProxies) != 2 {
		t.Errorf("metrics/proxies: %q %v", c.MetricsToken, c.TrustedProxies)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no apps":           {},
		"app without creds": {"RELAY_APP_1_ID": "a"},
		"both secret forms": {"RELAY_APP_1_ID": "a", "RELAY_APP_1_FCM_CREDENTIALS": "{}", "RELAY_APP_1_FCM_CREDENTIALS_FILE": "/x"},
		"missing file":      {"RELAY_APP_1_ID": "a", "RELAY_APP_1_FCM_CREDENTIALS_FILE": "/nope"},
		"apns missing ids":  {"RELAY_APP_1_ID": "a", "RELAY_APP_1_APNS_KEY": "k"},
		"bad enrollment":    {"RELAY_APP_1_ID": "a", "RELAY_DEV_LOG_SENDER": "true", "RELAY_ENROLLMENT": "sometimes"},
		"bad duration":      {"RELAY_APP_1_ID": "a", "RELAY_DEV_LOG_SENDER": "true", "RELAY_CLOCK_SKEW": "soon"},
		"bad int":           {"RELAY_APP_1_ID": "a", "RELAY_DEV_LOG_SENDER": "true", "RELAY_BURST": "lots"},
		"bad proxy":         {"RELAY_APP_1_ID": "a", "RELAY_DEV_LOG_SENDER": "true", "RELAY_TRUSTED_PROXIES": "nope"},
		"duplicate app":     {"RELAY_APP_1_ID": "a", "RELAY_APP_2_ID": "a", "RELAY_DEV_LOG_SENDER": "true"},
		"tiny body cap":     {"RELAY_APP_1_ID": "a", "RELAY_DEV_LOG_SENDER": "true", "RELAY_MAX_BODY_BYTES": "10"},
	}
	for name, env := range cases {
		if _, err := LoadFrom(lookup(env), reader(nil)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := LoadFrom(lookup(map[string]string{"RELAY_APP_1_ID": "a", "RELAY_APP_1_FCM_CREDENTIALS_FILE": "/nope"}), reader(nil))
	if !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "{") {
		t.Errorf("file error: %v", err)
	}
}
