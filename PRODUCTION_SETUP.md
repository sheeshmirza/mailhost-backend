# Mailhost Production Deployment & Setup Guide

This guide provides a comprehensive, step-by-step procedure for deploying Mailhost into an enterprise production environment. It covers infrastructure sizing, DNS & deliverability, cryptographic security, containerized and native systemd deployment, database clustering, and observability.

---

## 1. Architectural Overview & Role Distribution

Mailhost is compiled as a unified, highly optimized Go binary capable of running all roles concurrently or horizontally scaled into specialized clusters:

| Role | Environment Flag | Ports | Responsibilities |
|---|---|---|---|
| **API** | `ROLES=api` | `8080` (HTTP) | REST API, Webhooks dispatch, Tracking engine, React email rendering, MCP Server |
| **SMTP** | `ROLES=smtp` | `25` (MX), `587` (Submission) | Inbound mail receiver (MX), SASL authenticated client submission, alias forwarding |
| **Worker** | `ROLES=worker` | None (Internal) | Outbound queue consumers, DKIM signer, connection pool, direct MX delivery engine |
| **IMAP** | `ROLES=imap` | `143` (STARTTLS) | IMAP4rev1 mailbox access, folder listing, message fetching |
| **POP3** | `ROLES=pop` | `110` (STARTTLS) | POP3 mailbox access, message retrieval, message deletion |
| **All** | `ROLES=all` | All above | Monolithic execution for small to medium scale deployments |

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
                                │
                                ▼
                         ┌──────────────┐
                         │   MongoDB    │
                         │ (Blob Store) │
                         └──────────────┘
```

---

## 2. Infrastructure Sizing & Hardware Requirements

| Deployment Tier | Daily Email Volume | Recommended Spec | Architecture Topology |
|---|---|---|---|
| **Starter** | < 100,000 / day | 2 vCPU, 4 GB RAM | Single Node (`ROLES=all`), Managed PostgreSQL & Redis |
| **Production Standard** | 100,000 - 2M / day | 4 vCPU, 8 GB RAM (x3 nodes) | 2x API/SMTP nodes, 2x Worker nodes, Dedicated DB & RabbitMQ |
| **High Throughput** | > 2M / day | 8 vCPU, 16 GB RAM (xN nodes) | Dedicated auto-scaling worker fleet, PostgreSQL primary + read replica, RabbitMQ cluster, MongoDB replica set |

---

## 3. Step 1: Network & DNS Configuration (Critical for Deliverability)

Deliverability to major inbox providers (Gmail, Microsoft 365, Yahoo) strictly requires correct DNS records and PTR records matching the server's public IP.

### A. Reverse DNS (rDNS / PTR Record)
- Coordinate with your hosting provider (AWS, GCP, DigitalOcean, Hetzner) to set the **PTR record** for your static public IP:
  ```
  <YOUR_SERVER_PUBLIC_IP> -> mail.yourdomain.com
  ```

### B. Forward DNS Records
Replace `yourdomain.com` and `mail.yourdomain.com` with your production domain and server hostname.

**Server records** (once, for `MAIL_HOSTNAME`):

| Record Type | Hostname / Name | Value / Destination | TTL | Purpose |
|---|---|---|---|---|
| **A** | `mail` | `<PUBLIC_IP>` | 300 | API, tracking links, MX target, SMTP/IMAP/POP3 |
| **PTR** | `<PUBLIC_IP>` | `mail.yourdomain.com` | - | Set at your hosting provider; must match `MAIL_HOSTNAME` |

**Per sending domain** — create the domain with `POST /v1/domains`, then publish exactly the `records` array
it returns (also available via `GET /v1/domains/{id}`). `POST /v1/domains/{id}/verify` only succeeds when the
**required** ones resolve:

| Type | Name | Value | Required |
|---|---|---|---|
| TXT | `_mailhost.yourdomain.com` | `mailhost-verification=<token>` | yes (ownership) |
| TXT | `<selector>._domainkey.yourdomain.com` | `v=DKIM1; k=rsa; p=<public key>` (exact value from API) | yes (DKIM) |
| TXT | `yourdomain.com` | `v=spf1 a:mail.yourdomain.com ~all` | recommended |
| MX | `yourdomain.com` | `mail.yourdomain.com` (priority 10) | only if receiving mail |
| TXT | `_dmarc.yourdomain.com` | `v=DMARC1; p=none;` → tighten to `quarantine` once aligned | recommended |

A verified domain name can belong to only one account.

### C. Firewall Rules (UFW / Security Groups)
Open only required ports:
```bash
# Public Mail Protocols
ufw allow 25/tcp comment "SMTP Inbound MX"
ufw allow 587/tcp comment "SMTP Authenticated Submission"
ufw allow 143/tcp comment "IMAP STARTTLS"
ufw allow 110/tcp comment "POP3 STARTTLS"

# Public Web / API
ufw allow 80/tcp comment "HTTP (ACME Challenge)"
ufw allow 443/tcp comment "HTTPS (API & Webhooks)"

# Restrict Backend Ports to Internal Network or Localhost:
# 5432 (Postgres), 6379 (Redis), 5672/15672 (RabbitMQ), 27017 (MongoDB), 6060 (Pprof)
```

---

## 4. Step 2: Cryptographic Secrets & Environment Setup

A ready-made production env file, `.env.production`, is provided (git-ignored). It is consumed by
`docker-compose.prod.yml`.

```bash
./scripts/init-prod-env.sh      # generates MASTER_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD; chmod 600
$EDITOR .env.production         # replace the remaining CHANGE_ME / example.com values (the script lists them)
```

Values you must set by hand:

| Variable | Why |
|---|---|
| `MAIL_HOSTNAME` / `HOSTNAME` | Public FQDN. Always set `MAIL_HOSTNAME`: inside Docker, `HOSTNAME` defaults to the container ID. |
| `AUTH_EMAIL_SMTP_ADDR`, `AUTH_EMAIL_SMTP_USERNAME`, `AUTH_EMAIL_SMTP_PASSWORD`, `AUTH_EMAIL_FROM` | Verification / password-reset mail. Use a provider on port 587 (STARTTLS is used automatically; credentials are only sent over TLS). **Required**: invited members can only join an organization after verifying their email. |
| `SUPPORT_EMAIL` | Shown in API docs. |

Settings that must keep their production values:

```ini
ALLOW_PRIVATE_DELIVERY=false   # true allows webhooks and outbound delivery to private networks (SSRF risk)
SKIP_DNS_VERIFICATION=false    # true verifies domains without DNS lookups
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16   # API is only reachable through the reverse proxy
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
```

**Back up `MASTER_KEY`** (password manager / secrets vault). It encrypts DKIM private keys and webhook secrets at
rest and signs click-tracking links; losing it makes every stored DKIM key unusable.

Using managed PostgreSQL/Redis instead of the bundled containers: add `DATABASE_URL` / `REDIS_URL` to
`.env.production` (they override the compose defaults), e.g.
`DATABASE_URL=postgres://mailhost:PASS@db.internal:5432/mailhost?sslmode=verify-full&sslrootcert=/certs/pg-ca.pem`.
`RABBITMQ_URL` and `MONGODB_URI` are optional; without them the queue uses Redis Streams and message bodies stay in PostgreSQL.

---

## 5. Step 3: TLS / SSL Certificates

Mailhost provides STARTTLS on SMTP (25, 587), IMAP (143) and POP3 (110). Login on 587/143/110 is **refused
until the client has upgraded to TLS**, so a certificate is mandatory. Implicit-TLS ports (465/993/995) are
not implemented. The same certificate serves HTTPS via Caddy.

```bash
sudo apt-get install -y certbot
# Port 80 must be free during issuance (run this before starting Caddy).
sudo certbot certonly --standalone -d mail.yourdomain.com
```

The container runs as uid/gid `10001`, which cannot read `/etc/letsencrypt/live` directly. Copy the files into
`./certs` with a deploy hook (also used on every renewal):

```bash
cd /opt/mailhost   # repository checkout
sudo tee /etc/letsencrypt/renewal-hooks/deploy/mailhost.sh >/dev/null <<'EOF'
#!/bin/sh
set -e
D=/etc/letsencrypt/live/mail.yourdomain.com
install -D -m 0644 -o root -g 10001 "$D/fullchain.pem" /opt/mailhost/certs/fullchain.pem
install -D -m 0640 -o root -g 10001 "$D/privkey.pem"   /opt/mailhost/certs/privkey.pem
# Certificates are loaded at startup, so restart (there is no hot reload).
cd /opt/mailhost && docker compose -f docker-compose.prod.yml --env-file .env.production restart mailhost caddy || true
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/mailhost.sh
sudo RENEWED_LINEAGE=x /etc/letsencrypt/renewal-hooks/deploy/mailhost.sh   # first copy

# Renewal uses --standalone too, so stop Caddy around it:
sudo sed -i 's/^authenticator.*/authenticator = standalone/' /etc/letsencrypt/renewal/mail.yourdomain.com.conf
echo 'pre_hook = docker compose -f /opt/mailhost/docker-compose.prod.yml --env-file /opt/mailhost/.env.production stop caddy' | sudo tee -a /etc/letsencrypt/renewal/mail.yourdomain.com.conf
echo 'post_hook = docker compose -f /opt/mailhost/docker-compose.prod.yml --env-file /opt/mailhost/.env.production start caddy' | sudo tee -a /etc/letsencrypt/renewal/mail.yourdomain.com.conf
sudo certbot renew --dry-run
```

---

## 6. Step 4: Reverse Proxy Setup for HTTP API (Port 443 -> 8080)

The API **must** be served at `https://MAIL_HOSTNAME`: open-tracking pixels, click-tracking redirects and
one-click unsubscribe links are generated as `https://<MAIL_HOSTNAME>/v1/...`.

`docker-compose.prod.yml` already runs Caddy with [deploy/Caddyfile](deploy/Caddyfile):

```caddy
{$MAIL_HOSTNAME} {
	tls /certs/fullchain.pem /certs/privkey.pem
	encode gzip
	reverse_proxy mailhost:8080
}
```

Port 8080 is not published to the host. The app only trusts `X-Forwarded-For` from `TRUSTED_PROXY_CIDRS`;
without it every request looks like it comes from the proxy, so login throttling and audit-log IPs break.

If you use Nginx instead, keep `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, set
`client_max_body_size 60M;` (batch/bulk requests can exceed the 25 MB message limit), and set
`TRUSTED_PROXY_CIDRS` to the proxy's address (e.g. `127.0.0.1/32`).

---

## 7. Step 5: Database Provisioning & Maintenance

### PostgreSQL Setup
1. Create the database and user:
   ```sql
   CREATE USER mailhost_user WITH PASSWORD 'YourStrongPassword';
   CREATE DATABASE mailhost OWNER mailhost_user;
   GRANT ALL PRIVILEGES ON DATABASE mailhost TO mailhost_user;
   ```
2. **Schema Migrations**:
   Mailhost automatically applies schema migrations (`schema.sql`) and maintains monthly event partitions on startup via PostgreSQL advisory locks. No manual SQL script application is required.

3. **Event Partition Retention**:
   The `RETENTION_MONTHS` setting (default: 12) automatically detaches and drops older monthly event tables during daily maintenance runs, keeping database disk usage bounded and predictable.

---

## 8. Step 6: Production Deployment Options

### Option A: Docker Compose Deployment (recommended)

`docker-compose.prod.yml` runs PostgreSQL, Redis (password protected, AOF on), Mailhost and Caddy. Databases sit
on an internal-only network; only 25/587/143/110 (Mailhost) and 80/443 (Caddy) are published.

```bash
# Docker Engine 20.10+ is required (lets the non-root container bind ports < 1024).
sudo mkdir -p /opt/mailhost && sudo chown $USER /opt/mailhost
git clone <repo-url> /opt/mailhost && cd /opt/mailhost
./scripts/init-prod-env.sh && $EDITOR .env.production      # Step 2
# certificates in ./certs                                     # Step 3
docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build
docker compose -f docker-compose.prod.yml --env-file .env.production ps
docker compose -f docker-compose.prod.yml --env-file .env.production logs -f mailhost
```

Upgrades: `git pull && docker compose -f docker-compose.prod.yml --env-file .env.production up -d --build mailhost`
(schema migrations run automatically under an advisory lock).

Backups: schedule `docker compose -f docker-compose.prod.yml --env-file .env.production exec -T postgres pg_dump -U mailhost -Fc mailhost > mailhost-$(date +%F).dump`
and copy the dumps plus `.env.production` off-host.

### Option B: Native Systemd Deployment (Bare Metal / High-Performance VM)

1. Build the production binary:
   ```bash
   CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/mailhost main.go
   sudo chmod 755 /usr/local/bin/mailhost
   ```
2. Allow non-root binding to low ports (< 1024 for ports 25, 110, 143, 587):
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mailhost
   ```
3. Create dedicated system user:
   ```bash
   sudo useradd -r -s /bin/false mailhost
   ```
4. Create systemd service unit `/etc/systemd/system/mailhost.service`:
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
5. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable mailhost
   sudo systemctl start mailhost
   sudo systemctl status mailhost
   ```

---

## 9. Step 7: Post-Deployment Verification & Testing

```bash
# 1. Health (through the proxy)
curl -s https://mail.yourdomain.com/healthz
curl -s https://mail.yourdomain.com/readyz      # {"status":"ready"} means DB, Redis and secretbox are OK

# 2. TLS on mail ports
openssl s_client -starttls smtp -connect mail.yourdomain.com:587 -brief </dev/null
openssl s_client -starttls imap -connect mail.yourdomain.com:143 -brief </dev/null
openssl s_client -starttls pop3 -connect mail.yourdomain.com:110 -brief </dev/null

# 3. Not an open relay (expect 550 relay access denied)
swaks --server mail.yourdomain.com --to someone@gmail.com --from test@example.org --quit-after RCPT

# 4. First tenant: register, verify email, add + verify domain, send a test mail
curl -s -X POST https://mail.yourdomain.com/v1/users/register -H 'Content-Type: application/json' \
  -d '{"email":"you@yourdomain.com","password":"<strong password>","organization_name":"Prod"}'
# -> keep the returned api_key; publish DNS records from POST /v1/domains, then POST /v1/domains/{id}/verify

# 5. Metrics (needs an API key)
curl -s -H "Authorization: Bearer <API_KEY>" https://mail.yourdomain.com/metrics | head
```

Check a message sent to a Gmail account: "Show original" must show `SPF: PASS`, `DKIM: PASS`, `DMARC: PASS`.

### Full end-to-end suite (run against the local stack before every release)

```bash
./scripts/gen-dev-certs.sh                 # self-signed cert so STARTTLS/AUTH can be tested locally
docker compose up -d --build               # Postgres, Redis, RabbitMQ, MongoDB, Mailpit, Mailhost
python3 tests/e2e/run_e2e.py               # stdlib only; exits non-zero on any failure
```

Every request and response (method, URL, headers, body, status) plus SMTP/IMAP/POP3 transcripts are written to
`tests/e2e/results/<timestamp>/requests_responses.txt`, with a pass/fail list in `summary.txt`. Mailpit
(<http://localhost:8025>) shows every delivered message. Do not run the suite against production: it creates
accounts and sends mail.

### Production go-live checklist

- [ ] `ALLOW_PRIVATE_DELIVERY=false`, `SKIP_DNS_VERIFICATION=false`, unique `MASTER_KEY` backed up, `.env.production` is `chmod 600`
- [ ] `MAIL_HOSTNAME` has A + matching PTR record; certificate valid for it
- [ ] Outbound TCP 25 allowed by hosting provider/firewall for direct MX delivery
- [ ] `AUTH_EMAIL_*` configured and a verification email received
- [ ] Ports 5432/6379/8080/6060 not reachable from the internet
- [ ] Open-relay test returns 550; 587/143/110 refuse login before STARTTLS
- [ ] Daily `pg_dump` backups copied off-host and a restore tested
- [ ] `/metrics` scraped and alerts on `/readyz` failures and queue backlog

---

## 10. Step 8: IP Warming & Deliverability Schedule

When deploying on a newly provisioned public IP, send volume **must** be ramped up gradually to establish IP reputation with Spamhaus, Gmail, and Outlook.

| Week | Maximum Volume / Day | Recommended Traffic |
|---|---|---|
| **Week 1** | 2,000 / day | Transactional emails only (password resets, verifications) |
| **Week 2** | 5,000 / day | High-engagement active user emails |
| **Week 3** | 15,000 / day | Onboarding drips & notification digests |
| **Week 4** | 50,000 / day | Regular newsletter & marketing broadcasts |
| **Week 5+** | 100,000+ / day | Full production volume |

### Essential Deliverability Tools:
- **Google Postmaster Tools**: Register your sending domain and IP to monitor spam rate, IP reputation, and DKIM/SPF alignment.
- **Microsoft SNDS (Smart Network Data Services)**: Register IP ranges to monitor complaint ratios and junk mail filtering.
