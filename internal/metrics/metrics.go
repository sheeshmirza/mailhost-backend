// Package metrics provides Prometheus-compatible telemetry for enterprise observability.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// counter stores an atomically updated uint64 metric.
type counter struct{ val uint64 }

func (c *counter) inc()         { atomic.AddUint64(&c.val, 1) }
func (c *counter) add(n uint64) { atomic.AddUint64(&c.val, n) }
func (c *counter) get() uint64  { return atomic.LoadUint64(&c.val) }

// Registry stores process-local counters exposed in Prometheus format.
type Registry struct {
	mu           sync.RWMutex
	httpRequests map[string]*counter // "method:status" -> count
	httpDuration map[string]*counter // "method" -> total duration ms
	emailEvents  map[string]*counter // "status" -> count
	inboundMsgs  counter
	startTime    time.Time
}

// Default is the process-wide metrics registry used by the HTTP API.
var Default = NewRegistry()

// NewRegistry creates an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		httpRequests: make(map[string]*counter),
		httpDuration: make(map[string]*counter),
		emailEvents:  make(map[string]*counter),
		startTime:    time.Now(),
	}
}

// RecordHTTP records one completed HTTP request and its duration.
func (r *Registry) RecordHTTP(method string, status int, duration time.Duration) {
	switch method {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
	default:
		method = "OTHER"
	}
	key := fmt.Sprintf("%s:%d", method, status)
	r.mu.RLock()
	c, ok := r.httpRequests[key]
	d, dok := r.httpDuration[method]
	r.mu.RUnlock()

	if !ok {
		r.mu.Lock()
		if c = r.httpRequests[key]; c == nil {
			c = &counter{}
			r.httpRequests[key] = c
		}
		r.mu.Unlock()
	}
	c.inc()

	if !dok {
		r.mu.Lock()
		if d = r.httpDuration[method]; d == nil {
			d = &counter{}
			r.httpDuration[method] = d
		}
		r.mu.Unlock()
	}
	d.add(uint64(duration.Milliseconds()))
}

// RecordEmail increments the counter for an email lifecycle status.
func (r *Registry) RecordEmail(status string) {
	r.mu.RLock()
	c, ok := r.emailEvents[status]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if c = r.emailEvents[status]; c == nil {
			c = &counter{}
			r.emailEvents[status] = c
		}
		r.mu.Unlock()
	}
	c.inc()
}

// RecordInbound increments the inbound message counter.
func (r *Registry) RecordInbound() {
	r.inboundMsgs.inc()
}

// WritePrometheus writes current metrics in Prometheus exposition text format.
func (r *Registry) WritePrometheus(w io.Writer) {
	fmt.Fprintf(w, "# HELP mailhost_uptime_seconds Number of seconds the service has been running.\n")
	fmt.Fprintf(w, "# TYPE mailhost_uptime_seconds gauge\n")
	fmt.Fprintf(w, "mailhost_uptime_seconds %d\n\n", int64(time.Since(r.startTime).Seconds()))

	fmt.Fprintf(w, "# HELP mailhost_http_requests_total Total number of HTTP requests processed.\n")
	fmt.Fprintf(w, "# TYPE mailhost_http_requests_total counter\n")
	r.mu.RLock()
	for k, c := range r.httpRequests {
		method, status, ok := strings.Cut(k, ":")
		if !ok {
			method, status = k, "0"
		}
		fmt.Fprintf(w, "mailhost_http_requests_total{method=\"%s\",status=\"%s\"} %d\n", method, status, c.get())
	}

	fmt.Fprintf(w, "\n# HELP mailhost_http_duration_ms_total Cumulative duration of HTTP requests in milliseconds.\n")
	fmt.Fprintf(w, "# TYPE mailhost_http_duration_ms_total counter\n")
	for m, d := range r.httpDuration {
		fmt.Fprintf(w, "mailhost_http_duration_ms_total{method=\"%s\"} %d\n", m, d.get())
	}

	fmt.Fprintf(w, "\n# HELP mailhost_email_events_total Total count of outbound email delivery outcomes.\n")
	fmt.Fprintf(w, "# TYPE mailhost_email_events_total counter\n")
	for status, c := range r.emailEvents {
		fmt.Fprintf(w, "mailhost_email_events_total{status=\"%s\"} %d\n", status, c.get())
	}
	r.mu.RUnlock()

	fmt.Fprintf(w, "\n# HELP mailhost_inbound_emails_total Total incoming emails received by the SMTP MTA.\n")
	fmt.Fprintf(w, "# TYPE mailhost_inbound_emails_total counter\n")
	fmt.Fprintf(w, "mailhost_inbound_emails_total %d\n", r.inboundMsgs.get())
}

// Handler returns an HTTP handler serving Prometheus metrics.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Default.WritePrometheus(w)
	}
}
