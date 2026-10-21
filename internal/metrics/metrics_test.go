package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsConcurrency(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup

	// Concurrently record HTTP requests
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.RecordHTTP(http.MethodGet, http.StatusOK, 10*time.Millisecond)
			reg.RecordHTTP("CUSTOM_WEIRD", http.StatusBadRequest, 5*time.Millisecond)
			reg.RecordEmail("delivered")
			reg.RecordEmail("bounced")
			reg.RecordInbound()
		}()
	}

	wg.Wait()

	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "mailhost_http_requests_total{method=\"GET\",status=\"200\"} 50") {
		t.Errorf("expected 50 GET 200 requests, got:\n%s", out)
	}
	if !strings.Contains(out, "mailhost_http_requests_total{method=\"OTHER\",status=\"400\"} 50") {
		t.Errorf("expected 50 OTHER 400 requests, got:\n%s", out)
	}
	if !strings.Contains(out, "mailhost_email_events_total{status=\"delivered\"} 50") {
		t.Errorf("expected 50 delivered events, got:\n%s", out)
	}
	if !strings.Contains(out, "mailhost_email_events_total{status=\"bounced\"} 50") {
		t.Errorf("expected 50 bounced events, got:\n%s", out)
	}
	if !strings.Contains(out, "mailhost_inbound_emails_total 50") {
		t.Errorf("expected 50 inbound emails, got:\n%s", out)
	}
}

func TestMetricsHandler(t *testing.T) {
	Default.RecordInbound()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %s", contentType)
	}
	if !strings.Contains(rr.Body.String(), "mailhost_uptime_seconds") {
		t.Error("expected mailhost_uptime_seconds in output")
	}
}

func TestWritePrometheusMalformedKey(t *testing.T) {
	reg := NewRegistry()
	reg.mu.Lock()
	c := &counter{}
	c.inc()
	reg.httpRequests["UNKNOWN"] = c
	reg.mu.Unlock()

	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), `mailhost_http_requests_total{method="UNKNOWN",status="0"} 1`) {
		t.Errorf("expected malformed key fallback in prometheus output, got:\n%s", buf.String())
	}
}

