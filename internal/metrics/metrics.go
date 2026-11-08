// Package metrics holds the Prometheus collectors. Labels are limited to the
// server id, provider, push kind and coarse result classes; there is never a
// token, app payload or address in a label.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the collector set.
type Metrics struct {
	Registry *prometheus.Registry

	Requests     *prometheus.CounterVec   // route, code
	AuthFailures *prometheus.CounterVec   // reason
	Messages     *prometheus.CounterVec   // server_id, push_kind, result
	Provider     *prometheus.CounterVec   // provider, outcome
	ProviderTime *prometheus.HistogramVec // provider
	Enrollments  *prometheus.CounterVec   // result
	Duration     *prometheus.HistogramVec // route
}

// New registers the collectors on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry:     prometheus.NewRegistry(),
		Requests:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "relay_http_requests_total", Help: "HTTP requests by route and status code."}, []string{"route", "code"}),
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "relay_auth_failures_total", Help: "Rejected /v1/send authentications by reason."}, []string{"reason"}),
		Messages:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "relay_messages_total", Help: "Messages by server id, push kind and result (ok, invalid_token, rate_limited, error, rejected)."}, []string{"server_id", "push_kind", "result"}),
		Provider:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "relay_provider_requests_total", Help: "Provider calls by provider (fcm, apns) and outcome (ok, invalid_token, error)."}, []string{"provider", "outcome"}),
		ProviderTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "relay_provider_request_seconds", Help: "Provider call latency.", Buckets: prometheus.DefBuckets}, []string{"provider"}),
		Enrollments:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "relay_enrollments_total", Help: "Enrollment attempts by result."}, []string{"result"}),
		Duration:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "relay_http_request_seconds", Help: "HTTP request latency by route.", Buckets: prometheus.DefBuckets}, []string{"route"}),
	}
	m.Registry.MustRegister(m.Requests, m.AuthFailures, m.Messages, m.Provider, m.ProviderTime, m.Enrollments, m.Duration,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}
