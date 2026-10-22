# Mailhost — Enterprise Email Infrastructure Platform

Mailhost is a high-performance, fault-tolerant, horizontally scalable email infrastructure platform written in Go. It combines an authenticated HTTP REST API, inbound MX receiver, authenticated SMTP submission, IMAP4rev1 and POP3 mailbox servers, direct MX outbound delivery workers, and AI-powered semantic vector search into a single, cohesive binary.

---

## 1. Architectural Overview & Role Distribution

Mailhost is compiled as a unified binary capable of executing all services in a single process or scaling out into specialized role clusters:

| Role | Environment Flag | Network Ports | Responsibilities |
|---|---|---|---|
| **API** | `ROLES=api` | `8080` (HTTP) | REST API, Webhooks engine, Open/Click tracking, React email rendering, AI MCP Server |
| **SMTP** | `ROLES=smtp` | `25` (MX), `587` (Submission) | Inbound mail receiver (MX), SASL-authenticated client submission, alias forwarding |
| **Worker** | `ROLES=worker` | None (Internal) | Outbound queue consumer, DKIM signer, connection pool, direct MX delivery engine |
| **IMAP** | `ROLES=imap` | `143` (STARTTLS) | IMAP4rev1 mailbox access, folder management, message fetching |
| **POP3** | `ROLES=pop` | `110` (STARTTLS) | POP3 mailbox access, message retrieval, message deletion |
| **All** | `ROLES=all` | All of the above | Monolithic execution for single-server or development deployments |

```
                       [ Public Internet ]
                                │
       ┌────────────────────────┼────────────────────────┐
       │ (Port 443 / 80)        │ (Port 25 / 587)        │ (Port 143 / 110)
       ▼                        ▼                        ▼
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ Reverse Proxy│         │ Inbound MTA  │         │ IMAP / POP3  │
│ (Caddy/Nginx)│         │ (Port 25/587)│         │ (143 / 110)  │
└──────┬───────┘         └──────┬───────┘         └──────┬───────┘
       │                        │                        │
       ▼                        ▼                        ▼
┌────────────────────────────────────────────────────────────────┐
│                   Mailhost Go Application Layer                │
│                 (ROLES=api,smtp,worker,imap,pop)               │
└──────┬────────────────────────┬────────────────────────┬───────┘
       │                        │                        │
       ▼                        ▼                        ▼
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  PostgreSQL  │         │   RabbitMQ   │         │    Redis     │
│ (State / DB) │         │ (Queue/AMQP) │         │(Cache/Limits)│
└──────────────┘         └──────────────┘         └──────────────┘
       │                                                 │
       ▼                                                 ▼
┌──────────────┐                                  ┌──────────────┐
│   MongoDB    │                                  │    Qdrant    │
│ (MIME Blobs) │                                  │(Vector Search│
└──────────────┘                                  └──────────────┘
```

---

## 2. Multi-Database Stack Integration

Mailhost leverages purpose-built database engines to achieve ultra-low latency and horizontal scale:

1. **PostgreSQL 14+ (Primary Relational State & Transactions)**:
   - Primary and read-replica connection pools (`pgxpool.Pool`) with connection life-cycle controls.
   - Manages accounts, domains, API keys, credentials, suppressions, webhooks, and audit logs.
   - Automated time-series range partitioning (`events_YYYYMM`) with automated monthly retention cleanup.
2. **MongoDB 6+ (Document & MIME Blob Store)**:
   - Stores raw RFC 5322 MIME message payloads and email attachments off-table, keeping PostgreSQL relational indexes compact and cache-friendly.
3. **Redis 6+ (Distributed Cache & Rate Limiter)**:
   - Distributed token-bucket rate limiting across API endpoints, session token blacklisting, and suppression lookups.
   - Provides Redis Streams messaging fallback when RabbitMQ is not deployed.
4. **RabbitMQ (Priority Outbound Delivery Broker)**:
   - Durable AMQP topic exchanges with dual-priority routing (`deliveries.transactional` vs `deliveries.bulk`).
   - Dead-letter routing, backpressure handling, and graceful worker drainage.
5. **Qdrant (Vector Engine & AI Semantic Search)**:
   - High-dimensional vector database for semantic search over transactional emails and rich HTML templates.
   - Tenant-isolated similarity clustering and highlighted match snippet previews.

---

## 3. Infrastructure Sizing & Hardware Requirements

| Deployment Tier | Daily Email Volume | Recommended Spec | Architecture Topology |
|---|---|---|---|
| **Starter** | < 100,000 / day | 2 vCPU, 4 GB RAM | Single Node (`ROLES=all`), PostgreSQL & Redis |
| **Production Standard** | 100,000 - 2M / day | 4 vCPU, 8 GB RAM (x3 nodes) | 2x API/SMTP nodes, 2x Worker nodes, Dedicated PostgreSQL & RabbitMQ |
| **High Throughput** | > 2M / day | 8 vCPU, 16 GB RAM (xN nodes) | Dedicated auto-scaling worker fleet, PostgreSQL primary + replica, RabbitMQ cluster, MongoDB, Qdrant |

---

## 4. Production Deployment: Native Systemd (Bare Metal / VM)

### Step 1: Compile the Production Binary
Build a standalone, statically linked binary:
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/mailhost main.go
sudo chmod 755 /usr/local/bin/mailhost
```

### Step 2: Grant Low-Port Binding Privileges
Allow the non-root application binary to bind to privileged network ports (`25`, `110`, `143`, `587`):
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mailhost
```

### Step 3: Create Dedicated System User and Configuration Directory
```bash
sudo useradd -r -s /bin/false mailhost
sudo mkdir -p /etc/mailhost
sudo chown -R mailhost:mailhost /etc/mailhost
```

### Step 4: Configure Production Environment
Copy `.env.example` to `/etc/mailhost/.env` and restrict file permissions:
```bash
sudo cp .env.example /etc/mailhost/.env
sudo chmod 600 /etc/mailhost/.env
sudo chown mailhost:mailhost /etc/mailhost/.env
sudo nano /etc/mailhost/.env
```

### Step 5: Install Systemd Service Unit
Create `/etc/systemd/system/mailhost.service`:
```ini
[Unit]
Description=Mailhost Enterprise Mail Server
After=network.target postgresql.service redis.service rabbitmq-server.service
Wants=postgresql.service redis.service rabbitmq-server.service

[Service]
Type=simple
User=mailhost
Group=mailhost
WorkingDirectory=/etc/mailhost
EnvironmentFile=/etc/mailhost/.env
ExecStart=/usr/local/bin/mailhost
Restart=always
RestartSec=5s
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Step 6: Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable mailhost
sudo systemctl start mailhost
sudo systemctl status mailhost
```

---

## 5. Network, Firewall & DNS Configuration

### A. Reverse DNS (rDNS / PTR Record)
Coordinate with your hosting provider to configure the **PTR record** for your static public IP:
```
<YOUR_PUBLIC_IP> -> mail.yourdomain.com
```

### B. Forward DNS Records
Configure records matching your `MAIL_HOSTNAME`:

| Record Type | Hostname / Name | Value / Destination | TTL | Purpose |
|---|---|---|---|---|
| **A** | `mail` | `<PUBLIC_IP>` | 300 | API, tracking links, MX target, SMTP/IMAP/POP3 |
| **PTR** | `<PUBLIC_IP>` | `mail.yourdomain.com` | - | Configured at hosting provider; must match `MAIL_HOSTNAME` |

**Sending Domain Verification Records** (returned by `POST /v1/domains`):

| Type | Name | Value | Required | Purpose |
|---|---|---|---|---|
| **TXT** | `_mailhost.yourdomain.com` | `mailhost-verification=<token>` | Yes | Domain ownership proof |
| **TXT** | `<selector>._domainkey.yourdomain.com` | `v=DKIM1; k=rsa; p=<public_key>` | Yes | Cryptographic DKIM signature verification |
| **TXT** | `yourdomain.com` | `v=spf1 a:mail.yourdomain.com ~all` | Recommended | SPF alignment |
| **MX** | `yourdomain.com` | `mail.yourdomain.com` (priority 10) | Optional | Inbound MX routing |
| **TXT** | `_dmarc.yourdomain.com` | `v=DMARC1; p=quarantine;` | Recommended | DMARC policy enforcement |

### C. Firewall Configuration (UFW)
```bash
# Public Mail Protocols
ufw allow 25/tcp comment "SMTP Inbound MX"
ufw allow 587/tcp comment "SMTP Authenticated Submission"
ufw allow 143/tcp comment "IMAP STARTTLS"
ufw allow 110/tcp comment "POP3 STARTTLS"

# Public Web / API
ufw allow 80/tcp comment "HTTP (ACME Challenge / Redirect)"
ufw allow 443/tcp comment "HTTPS (API & Tracking)"

# Internal Services (Restrict to Localhost / Private Network):
# 5432 (Postgres), 6379 (Redis), 5672 (RabbitMQ), 27017 (MongoDB), 6333 (Qdrant), 6060 (Pprof)
```

---

## 6. Cryptographic Security & Reverse Proxy

### Master Key Generation
Mailhost uses a 32-byte master key for XSalsa20-Poly1305 symmetric encryption of sensitive credentials at rest (DKIM private keys, webhook secrets) and HMAC-SHA256 signature verification for tracking links.
Generate a key:
```bash
openssl rand -hex 32
```
Add the output to `/etc/mailhost/.env` as `MASTER_KEY`.

### TLS Certificates
Login on ports `587`, `143`, and `110` is strictly **refused until the client upgrades via STARTTLS**. Obtain a valid certificate using Certbot:
```bash
sudo certbot certonly --standalone -d mail.yourdomain.com
```
Configure paths in `/etc/mailhost/.env`:
```ini
TLS_CERT_FILE=/etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
TLS_KEY_FILE=/etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
```

### Reverse Proxy Configuration (Caddy / NGINX)
Serve the HTTP API over HTTPS (`port 443 -> :8080`):

**Caddyfile**:
```caddy
mail.yourdomain.com {
    tls /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

**NGINX Configuration**:
```nginx
server {
    listen 443 ssl http2;
    server_name mail.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem;

    client_max_body_size 60M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```
Set `TRUSTED_PROXY_CIDRS=127.0.0.1/32` in `/etc/mailhost/.env` so client IP addresses are accurately resolved for rate limiting and audit logging.

---

## 7. Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `HOSTNAME` | `mail.example.com` | Public FQDN used in SMTP EHLO/HELO and tracking links. |
| `MAIL_HOSTNAME` | Unset | Hostname override taking precedence over `HOSTNAME`. |
| `ROLES` | `all` | Comma-separated roles: `api`, `smtp`, `worker`, `imap`, `pop`, or `all`. |
| `HTTP_ADDR` | `:8080` | Bind address for REST API and webhook endpoints. |
| `SMTP_ADDR` | `:25` | Bind address for inbound MX server. |
| `SUBMISSION_ADDR`| `:587` | Bind address for authenticated SMTP submission. |
| `IMAP_ADDR` | `:143` | Bind address for IMAP4rev1 server. |
| `POP3_ADDR` | `:110` | Bind address for POP3 server. |
| `DEBUG_ADDR` | `127.0.0.1:6060` | Bind address for Go pprof diagnostics. |
| `MASTER_KEY` | None (Required) | 64-hex-character cryptographic key for Secretbox encryption. |
| `DATABASE_URL` | None (Required) | PostgreSQL connection URI. |
| `DATABASE_READ_URL` | Unset | Optional read replica PostgreSQL connection URI. |
| `DB_MAX_CONNS` | `50` | Maximum connections in PostgreSQL pool. |
| `RETENTION_MONTHS` | `12` | Monthly event partitions to retain before auto-detaching (0 = forever). |
| `REDIS_URL` | Unset | Redis connection URI for caching and distributed rate limiting. |
| `RABBITMQ_URL` | Unset | RabbitMQ AMQP connection URI for priority delivery queues. |
| `MONGODB_URI` | Unset | MongoDB connection URI for raw MIME blob offloading. |
| `MONGODB_DATABASE` | `mailhost` | MongoDB database name. |
| `QDRANT_URL` | Unset | Qdrant vector database HTTP URI for AI semantic search. |
| `QDRANT_API_KEY` | Unset | Optional API key for Qdrant vector database. |
| `TLS_CERT_FILE` | Unset | Path to PEM certificate chain. |
| `TLS_KEY_FILE` | Unset | Path to PEM private key. |
| `WORKERS` | `16` | Number of concurrent outbound delivery worker goroutines. |
| `POLL_INTERVAL` | `1s` | Idle polling interval for outbound delivery. |
| `MAX_ATTEMPTS` | `10` | Maximum delivery attempts before marking as permanent bounce. |
| `MAX_CONNS_PER_HOST` | `10` | Maximum simultaneous SMTP connections to any single remote MX. |
| `DEST_RATE_LIMIT_RPS`| `10.0` | Maximum outbound sends per second per remote destination MX. |
| `ALLOW_PRIVATE_DELIVERY` | `false` | Must be `false` in production to prevent SSRF vulnerabilities. |
| `RATE_LIMIT_RPS` | `100.0` | Global per-key API rate limit (requests/sec). |
| `RATE_LIMIT_BURST`| `200` | Global per-key API burst capacity. |
| `MAX_MESSAGE_BYTES`| `26214400` | Maximum email message size in bytes (25 MiB). |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1/32` | CIDR blocks trusted for `X-Forwarded-For` real client IP extraction. |

---

## 8. Observability & Health Checks

```bash
# 1. Liveness check (shallow probe)
curl -s http://127.0.0.1:8080/healthz
# Response: {"status":"ok"}

# 2. Readiness check (deep probe: verifies DB, Redis, and secretbox)
curl -s http://127.0.0.1:8080/readyz
# Response: {"status":"ready"}

# 3. Prometheus metrics scraping (authenticated with Bearer API Key)
curl -s -H "Authorization: Bearer <API_KEY>" http://127.0.0.1:8080/metrics

# 4. STARTTLS Verification on Mail Ports
openssl s_client -starttls smtp -connect mail.yourdomain.com:587 -brief </dev/null
openssl s_client -starttls imap -connect mail.yourdomain.com:143 -brief </dev/null
openssl s_client -starttls pop3 -connect mail.yourdomain.com:110 -brief </dev/null
```

---

## 9. IP Warming & Deliverability Ramp-Up Schedule

When deploying on a freshly allocated public IP, email sending volume must be ramped up gradually to establish positive IP reputation with Spamhaus, Gmail, Outlook, and Yahoo:

| Week | Maximum Volume / Day | Recommended Traffic |
|---|---|---|
| **Week 1** | 2,000 / day | Critical transactional emails only (password resets, OTPs, receipts) |
| **Week 2** | 5,000 / day | High-engagement active user notifications |
| **Week 3** | 15,000 / day | Onboarding drips & product activity summaries |
| **Week 4** | 50,000 / day | Marketing digests and product updates |
| **Week 5+** | 100,000+ / day | Full production sending volume |

---

## 10. Automated Testing & Verification

Run the complete Go test suite with the Go race detector enabled across all 19 packages:
```bash
go test -race -count=1 ./internal/...
```
All packages run cleanly with zero failures and zero race conditions.
