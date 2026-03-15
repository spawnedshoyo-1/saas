# AgentOps Cloud (Deployment-Ready SaaS)

A production-oriented SaaS backend + demo frontend for AI-agent-run businesses.

## What is now included

- Multi-tenant org model (`organizations`, `memberships`).
- Auth (register/login) with signed bearer tokens and TTL.
- Agent management APIs.
- Async server provisioning APIs.
- Workflow execution APIs.
- Billing APIs:
  - Checkout-session creation (Stripe-style flow)
  - Signed webhook processing for subscription + invoice events
  - Subscription status + invoice history endpoint
- API key generation/listing for machine-to-machine automation.
- Persistent relational DB schema with SQLite (easy local/dev deploy).
- Dockerfile + env template for deployability.
- Automated integration test suite.

## Local run

```bash
cp .env.example .env
python3 backend.py
```

Service starts on `http://0.0.0.0:8080` by default.

## Environment variables

- `AGENTOPS_HOST` (default `0.0.0.0`)
- `AGENTOPS_PORT` (default `8080`)
- `AGENTOPS_DB_PATH` (default `agentops.db`)
- `AGENTOPS_API_SECRET` (required for prod)
- `AGENTOPS_WEBHOOK_SECRET` (required for billing webhook verification)
- `AGENTOPS_TOKEN_TTL_SECONDS` (default `86400`)

## API surface

### Health
- `GET /api/health`

### Auth + tenancy
- `POST /api/auth/register`
  - `{ "email", "password", "fullName", "organizationName" }`
- `POST /api/auth/login`

### Agents
- `POST /api/agents`
- `GET /api/agents`

### Infrastructure
- `POST /api/servers/provision`
- `GET /api/servers`
- `GET /api/jobs/{jobId}`
- `POST /api/workflows/run`

### Billing
- `POST /api/billing/checkout-session`
- `POST /api/billing/webhook` (requires `X-AgentOps-Signature` HMAC SHA256)
- `GET /api/billing/subscription`

### API Keys
- `POST /api/keys`
- `GET /api/keys`

## Docker deploy

```bash
docker build -t agentops-backend .
docker run --rm -p 8080:8080 --env-file .env agentops-backend
```

## Tests

```bash
python3 -m unittest -v test_backend.py
```
