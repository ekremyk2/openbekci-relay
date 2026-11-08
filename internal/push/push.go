// Package push defines the content-free message model, the payload allowlist
// and the Sender interface that FCM, APNs, the log sender and test fakes
// implement.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

// Kind is the push transport a token belongs to.
type Kind string

// Push kinds.
const (
	KindFCM  Kind = "fcm"
	KindAPNs Kind = "apns"
)

// Priority is the delivery urgency requested by the instance.
type Priority string

// Priorities.
const (
	PriorityHigh   Priority = "high"
	PriorityNormal Priority = "normal"
)

// Status is the per-message outcome reported back to the instance.
type Status string

// Per-message statuses.
const (
	StatusOK           Status = "ok"
	StatusInvalidToken Status = "invalid_token"
	StatusRateLimited  Status = "rate_limited"
	StatusError        Status = "error"
)

// Limits applied during validation.
const (
	MaxTokenLen    = 4096
	MaxFieldLen    = 256
	MaxBadge       = 99999
	DefaultTTL     = time.Hour
	MaxTTLSeconds  = 28 * 24 * 3600
	maxTitleKeyLen = 128
)

// Data is the content-free payload. These six keys are the whole allowlist.
type Data struct {
	InstanceID     string
	OrgID          string
	NotificationID string
	Type           string
	CollapseKey    string
	Badge          *int
}

// APNsOptions are the APNs-specific knobs. GenericTitleKey is a localisation
// key resolved on the device, never text.
type APNsOptions struct {
	MutableContent  bool
	GenericTitleKey string
}

// Message is a validated message ready for a Sender.
type Message struct {
	Kind     Kind
	Token    string
	AppID    string
	Priority Priority
	TTL      time.Duration
	Data     Data
	APNs     APNsOptions
}

// Result is what a Sender reports for one message.
type Result struct {
	Status    Status
	Code      string // short machine-readable error class, no provider text
	Retryable bool
}

// OK is the success result.
var OK = Result{Status: StatusOK}

// Sender delivers one message to a provider.
type Sender interface {
	Send(ctx context.Context, m Message) Result
}

// AllowedDataKeys is the exact data allowlist, in documentation order.
var AllowedDataKeys = []string{"instance_id", "org_id", "notification_id", "type", "collapse_key", "badge"}

var titleKeyRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ValidationError describes why a message was rejected. It never contains the
// token or any value from the payload, only key names and limits.
type ValidationError struct{ Code, Msg string }

func (e *ValidationError) Error() string { return e.Code + ": " + e.Msg }

func bad(code, format string, a ...any) error {
	return &ValidationError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

type rawMessage struct {
	PushKind   string          `json:"push_kind"`
	Token      string          `json:"token"`
	AppID      string          `json:"app_id"`
	Priority   string          `json:"priority"`
	TTLSeconds *int64          `json:"ttl_seconds"`
	Data       json.RawMessage `json:"data"`
	APNs       json.RawMessage `json:"apns"`
}

// ParseMessage strictly decodes and validates one element of the messages
// array. Unknown message keys, unknown data keys, wrongly typed values and
// over-long values are rejected. defaultAppID is used when the message omits
// app_id.
func ParseMessage(raw json.RawMessage, defaultAppID string) (Message, error) {
	var rm rawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rm); err != nil {
		return Message{}, bad("invalid_message", "message is not a valid object with known keys")
	}
	var m Message
	switch Kind(rm.PushKind) {
	case KindFCM, KindAPNs:
		m.Kind = Kind(rm.PushKind)
	default:
		return m, bad("invalid_push_kind", "push_kind must be fcm or apns")
	}
	if rm.Token == "" || len(rm.Token) > MaxTokenLen || !utf8.ValidString(rm.Token) {
		return m, bad("invalid_token_format", "token missing or too long")
	}
	m.Token = rm.Token
	m.AppID = rm.AppID
	if m.AppID == "" {
		m.AppID = defaultAppID
	}
	if len(m.AppID) > MaxFieldLen {
		return m, bad("invalid_app_id", "app_id too long")
	}
	switch Priority(rm.Priority) {
	case "":
		m.Priority = PriorityHigh
	case PriorityHigh, PriorityNormal:
		m.Priority = Priority(rm.Priority)
	default:
		return m, bad("invalid_priority", "priority must be high or normal")
	}
	m.TTL = DefaultTTL
	if rm.TTLSeconds != nil {
		if *rm.TTLSeconds < 0 || *rm.TTLSeconds > MaxTTLSeconds {
			return m, bad("invalid_ttl", "ttl_seconds out of range 0..%d", MaxTTLSeconds)
		}
		m.TTL = time.Duration(*rm.TTLSeconds) * time.Second
	}
	d, err := parseData(rm.Data)
	if err != nil {
		return m, err
	}
	m.Data = d
	if len(rm.APNs) > 0 && string(rm.APNs) != "null" {
		o, err := parseAPNs(rm.APNs)
		if err != nil {
			return m, err
		}
		m.APNs = o
	}
	return m, nil
}

func parseData(raw json.RawMessage) (Data, error) {
	var d Data
	if len(raw) == 0 || string(raw) == "null" {
		return d, bad("invalid_data", "data is required")
	}
	var kv map[string]json.RawMessage
	if err := json.Unmarshal(raw, &kv); err != nil {
		return d, bad("invalid_data", "data must be an object")
	}
	str := func(key string, dst *string) error {
		v, ok := kv[key]
		if !ok {
			return nil
		}
		delete(kv, key)
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return bad("invalid_data", "data.%s must be a string", key)
		}
		if len(s) > MaxFieldLen || !utf8.ValidString(s) {
			return bad("invalid_data", "data.%s too long", key)
		}
		*dst = s
		return nil
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"instance_id", &d.InstanceID}, {"org_id", &d.OrgID}, {"notification_id", &d.NotificationID},
		{"type", &d.Type}, {"collapse_key", &d.CollapseKey},
	} {
		if err := str(f.key, f.dst); err != nil {
			return d, err
		}
	}
	if v, ok := kv["badge"]; ok {
		delete(kv, "badge")
		var n int
		if err := json.Unmarshal(v, &n); err != nil || n < 0 || n > MaxBadge {
			return d, bad("invalid_data", "data.badge must be an integer 0..%d", MaxBadge)
		}
		d.Badge = &n
	}
	for k := range kv {
		// Key names are safe to echo: they are what the allowlist is about.
		// Values are never echoed.
		return d, bad("disallowed_data_key", "data key %q is not in the allowlist", truncate(k, 40))
	}
	if d.InstanceID == "" || d.NotificationID == "" || d.Type == "" {
		return d, bad("invalid_data", "data.instance_id, data.notification_id and data.type are required")
	}
	return d, nil
}

func parseAPNs(raw json.RawMessage) (APNsOptions, error) {
	var in struct {
		MutableContent  bool   `json:"mutable_content"`
		GenericTitleKey string `json:"generic_title_key"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return APNsOptions{}, bad("invalid_apns", "apns must be an object with mutable_content and generic_title_key only")
	}
	if _, err := dec.Token(); err != io.EOF {
		return APNsOptions{}, bad("invalid_apns", "trailing data after apns object")
	}
	if in.GenericTitleKey != "" && (len(in.GenericTitleKey) > maxTitleKeyLen || !titleKeyRE.MatchString(in.GenericTitleKey)) {
		return APNsOptions{}, bad("invalid_apns", "generic_title_key must be a localisation key ([A-Za-z0-9_.-], max %d)", maxTitleKeyLen)
	}
	return APNsOptions{MutableContent: in.MutableContent, GenericTitleKey: in.GenericTitleKey}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
