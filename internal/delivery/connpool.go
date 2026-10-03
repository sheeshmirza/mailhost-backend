package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"sync"
	"time"

	"mailhost/internal/webhook"
)

const (
	connMaxAge     = 30 * time.Second // most MTAs drop idle sessions after 30-300s
	connMaxUses    = 100
	maxIdlePerHost = 8
)

type pooledConn struct {
	c       *smtp.Client
	conn    net.Conn
	created time.Time
	uses    int
}

func (pc *pooledConn) transact(ctx context.Context, from, rcpt string, raw []byte) error {
	deadline := time.Now().Add(5 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	pc.conn.SetDeadline(deadline)
	pc.uses++
	if err := pc.c.Mail(from); err != nil {
		return err
	}
	if err := pc.c.Rcpt(rcpt); err != nil {
		return err
	}
	wc, err := pc.c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(raw); err != nil {
		return err
	}
	return wc.Close()
}

func (pc *pooledConn) close() {
	pc.conn.SetDeadline(time.Now().Add(5 * time.Second))
	pc.c.Quit()
	pc.c.Close()
}

type hostPool struct {
	mu       sync.Mutex
	sem      chan struct{}
	idle     []*pooledConn
	lastUsed time.Time
}

const poolShards = 64

type poolShard struct {
	sync.RWMutex
	hosts map[string]*hostPool
}

func hashStr(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// connPool keeps idle SMTP sessions per MX host and caps concurrent connections per host,
// which both avoids TCP+TLS handshakes per message and keeps us under provider throttles.
type connPool struct {
	shards     [poolShards]poolShard
	maxPerHost int
}

func newConnPool(maxPerHost int) *connPool {
	p := &connPool{maxPerHost: maxPerHost}
	for i := range p.shards {
		p.shards[i].hosts = make(map[string]*hostPool)
	}
	return p
}

func (p *connPool) shard(key string) *poolShard {
	return &p.shards[hashStr(key)%poolShards]
}

func (p *connPool) getHost(key string) *hostPool {
	shard := p.shard(key)

	shard.RLock()
	hp := shard.hosts[key]
	shard.RUnlock()
	if hp != nil {
		return hp
	}

	shard.Lock()
	defer shard.Unlock()
	if hp = shard.hosts[key]; hp != nil {
		return hp
	}
	semCap := p.maxPerHost
	if semCap <= 0 {
		semCap = 1
	}
	hp = &hostPool{
		sem:      make(chan struct{}, semCap),
		idle:     make([]*pooledConn, 0, maxIdlePerHost),
		lastUsed: time.Now(),
	}
	shard.hosts[key] = hp
	return hp
}

func (p *connPool) acquire(ctx context.Context, key string) (func(), error) {
	if p.maxPerHost <= 0 {
		return func() {}, nil
	}
	hp := p.getHost(key)
	hp.mu.Lock()
	hp.lastUsed = time.Now()
	hp.mu.Unlock()
	select {
	case hp.sem <- struct{}{}:
		return func() {
			hp.mu.Lock()
			hp.lastUsed = time.Now()
			hp.mu.Unlock()
			<-hp.sem
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *connPool) get(key string) *pooledConn {
	hp := p.getHost(key)
	hp.mu.Lock()
	hp.lastUsed = time.Now()
	defer hp.mu.Unlock()

	for n := len(hp.idle); n > 0; n = len(hp.idle) {
		pc := hp.idle[n-1]
		hp.idle = hp.idle[:n-1]
		if time.Since(pc.created) < connMaxAge {
			return pc
		}
		go pc.close()
	}
	return nil
}

func (p *connPool) put(key string, pc *pooledConn) {
	if pc.uses >= connMaxUses || time.Since(pc.created) >= connMaxAge {
		pc.close()
		return
	}
	hp := p.getHost(key)
	hp.mu.Lock()
	hp.lastUsed = time.Now()
	if len(hp.idle) >= maxIdlePerHost {
		hp.mu.Unlock()
		pc.close()
		return
	}
	hp.idle = append(hp.idle, pc)
	hp.mu.Unlock()
}

func (p *connPool) prune() {
	var stale []*pooledConn
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for hostKey, hp := range shard.hosts {
			hp.mu.Lock()
			kept := hp.idle[:0]
			for _, pc := range hp.idle {
				if time.Since(pc.created) < connMaxAge {
					kept = append(kept, pc)
				} else {
					stale = append(stale, pc)
				}
			}
			hp.idle = kept
			isIdleAndEmpty := len(hp.idle) == 0 && len(hp.sem) == 0 && time.Since(hp.lastUsed) > 10*time.Minute
			hp.mu.Unlock()
			if isIdleAndEmpty {
				delete(shard.hosts, hostKey)
			}
		}
		shard.Unlock()
	}
	for _, pc := range stale {
		pc.close()
	}
}

func (p *connPool) closeAll() {
	var all []*pooledConn
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for _, hp := range shard.hosts {
			hp.mu.Lock()
			all = append(all, hp.idle...)
			hp.idle = nil
			hp.mu.Unlock()
		}
		shard.hosts = make(map[string]*hostPool)
		shard.Unlock()
	}
	for _, pc := range all {
		pc.close()
	}
}

func (w *Worker) dial(ctx context.Context, host, port string) (*pooledConn, error) {
	d := net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !w.cfg.AllowPrivateDelivery {
		d.Control = webhook.DenyInternal
	}
	addr := net.JoinHostPort(host, port)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// Fallback to explicit IPv4 dial if dual-stack timed out
			if conn4, err4 := d.DialContext(ctx, "tcp4", addr); err4 == nil {
				conn = conn4
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Minute))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	fail := func(err error) (*pooledConn, error) {
		_ = c.Close()
		return nil, err
	}
	hostname := w.cfg.Hostname
	if hostname == "" {
		hostname = "localhost"
	}
	if err := c.Hello(hostname); err != nil {
		return fail(err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fail(fmt.Errorf("starttls %s: %w", host, err))
		}
	}
	return &pooledConn{c: c, conn: conn, created: time.Now()}, nil
}
