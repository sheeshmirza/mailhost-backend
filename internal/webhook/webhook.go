// Package webhook posts signed JSON events to user URLs, refusing internal destinations (SSRF).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"
)

// IsPublicIP verifies that an IP address is a valid public, globally routable address,
// blocking all private, loopback, link-local, cloud metadata, multicast, and reserved ranges.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
	if ip4 := ip.To4(); ip4 != nil {
		if !ip4.IsGlobalUnicast() || ip4.IsPrivate() || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() || ip4.IsInterfaceLocalMulticast() {
			return false
		}
		// Block cloud metadata & link-local 169.254.0.0/16 (e.g. AWS/GCP/Azure 169.254.169.254)
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
		// Block 0.0.0.0/8 and broadcast 255.255.255.255
		if ip4[0] == 0 || (ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255) {
			return false
		}
		// Block Carrier-Grade NAT (CGNAT) 100.64.0.0/10
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return false
		}
		// Block documentation & benchmarking ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15
		if (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) ||
			(ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) {
			return false
		}
		return true
	}

	// IPv6 checks
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// Unique Local Address (fc00::/7)
	if len(ip) == 16 && (ip[0]&0xfe == 0xfc) {
		return false
	}
	// Unspecified address (::)
	if ip.IsUnspecified() {
		return false
	}
	return true
}

// DenyInternal runs after DNS resolution, so it also blocks DNS-rebinding to internal and metadata ranges.
func DenyInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if !IsPublicIP(ip) {
		return fmt.Errorf("security: refusing to connect to non-public address %s", host)
	}
	return nil
}

// Client posts signed webhook events using an SSRF-resistant HTTP transport.
type Client struct{ http *http.Client }

// New creates a webhook client that rejects connections to non-public addresses.
func New() *Client {
	return NewWithSecurity(false)
}

// NewWithSecurity creates a webhook client that rejects connections to non-public addresses unless allowPrivate is true.
func NewWithSecurity(allowPrivate bool) *Client {
	var control func(network, address string, c syscall.RawConn) error
	if !allowPrivate {
		control = DenyInternal
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: control}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &Client{http: &http.Client{
		Transport:     tr,
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// NewWithHTTP returns a Client using the provided http.Client.
func NewWithHTTP(client *http.Client) *Client {
	return &Client{http: client}
}

func ValidateURL(raw string) error {
	return ValidateURLWithPrivate(raw, false)
}

func ValidateURLWithPrivate(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 {
		return errors.New("invalid URL")
	}
	validScheme := u.Scheme == "https" || (allowPrivate && u.Scheme == "http")
	if !validScheme || u.Host == "" || u.User != nil {
		if allowPrivate {
			return errors.New("webhook URL must be an http or https URL without credentials")
		}
		return errors.New("webhook URL must be an https URL without credentials")
	}
	return nil
}

// Deliver POSTs the event with an HMAC-SHA256 signature over "timestamp.body", retrying 5xx/429/network errors.
func (c *Client) Deliver(ctx context.Context, target string, secret []byte, event any) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(ts + "."))
		mac.Write(body)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "mailhost-webhook/1")
		req.Header.Set("X-Mailhost-Timestamp", ts)
		req.Header.Set("X-Mailhost-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook: status %d", resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return lastErr
		}
	}
	return lastErr
}
