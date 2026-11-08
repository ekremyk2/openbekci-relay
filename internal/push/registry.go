package push

import (
	"context"
	"log/slog"
)

// Registry maps an app_id to the senders configured for it.
type Registry struct {
	apps map[string]map[Kind]Sender
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{apps: map[string]map[Kind]Sender{}} }

// Set registers the sender for (appID, kind).
func (r *Registry) Set(appID string, kind Kind, s Sender) {
	if r.apps[appID] == nil {
		r.apps[appID] = map[Kind]Sender{}
	}
	r.apps[appID][kind] = s
}

// HasApp reports whether appID is configured.
func (r *Registry) HasApp(appID string) bool { _, ok := r.apps[appID]; return ok }

// Lookup returns the sender for (appID, kind), or nil.
func (r *Registry) Lookup(appID string, kind Kind) Sender { return r.apps[appID][kind] }

// Apps lists configured app ids.
func (r *Registry) Apps() []string {
	out := make([]string, 0, len(r.apps))
	for k := range r.apps {
		out = append(out, k)
	}
	return out
}

// LogSender is the development sender: it logs that a message would have been
// sent (kind, app id, priority only) and reports ok. It never logs the token
// or any payload value.
type LogSender struct{ Log *slog.Logger }

// Send implements Sender.
func (l LogSender) Send(ctx context.Context, m Message) Result {
	l.Log.InfoContext(ctx, "log sender: message accepted", "push_kind", string(m.Kind), "app_id", m.AppID, "priority", string(m.Priority))
	return OK
}
