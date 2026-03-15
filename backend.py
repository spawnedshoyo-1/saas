#!/usr/bin/env python3
"""Deployment-ready AgentOps Cloud backend.

Features:
- Auth (register/login) with signed bearer tokens.
- Multi-tenant organizations and membership.
- Agent + server provisioning + workflow APIs.
- Billing with subscription plans and webhook processing.
- API key management for automation clients.
- SQLite persistence with transactional writes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse


@dataclass
class Settings:
    host: str = os.environ.get("AGENTOPS_HOST", "0.0.0.0")
    port: int = int(os.environ.get("AGENTOPS_PORT", "8080"))
    db_path: str = os.environ.get("AGENTOPS_DB_PATH", "agentops.db")
    api_secret: str = os.environ.get("AGENTOPS_API_SECRET", "dev-secret-change-me")
    webhook_secret: str = os.environ.get("AGENTOPS_WEBHOOK_SECRET", "dev-webhook-secret")
    token_ttl_seconds: int = int(os.environ.get("AGENTOPS_TOKEN_TTL_SECONDS", "86400"))


@dataclass
class AppContext:
    settings: Settings

    def get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.settings.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn


def now_ts() -> int:
    return int(time.time())


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def issue_token(user_id: str, org_id: str, secret: str) -> str:
    ts = str(now_ts())
    nonce = secrets.token_hex(8)
    payload = f"{user_id}.{org_id}.{ts}.{nonce}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = f"{payload}.{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def verify_token(token: str, secret: str, max_age_seconds: int) -> Optional[Tuple[str, str]]:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        user_id, org_id, ts_str, nonce, sig = decoded.split(".", 4)
        payload = f"{user_id}.{org_id}.{ts_str}.{nonce}"
        expected = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if now_ts() - int(ts_str) > max_age_seconds:
            return None
        return user_id, org_id
    except Exception:
        return None


def json_response(handler: BaseHTTPRequestHandler, code: int, payload: Dict[str, Any]) -> None:
    blob = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(blob)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgentOps-Signature")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
    handler.end_headers()
    handler.wfile.write(blob)


def error_response(handler: BaseHTTPRequestHandler, code: int, message: str) -> None:
    json_response(handler, code, {"error": message})


def read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8"))


def init_db(ctx: AppContext) -> None:
    conn = ctx.get_conn()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              plan TEXT NOT NULL,
              subscription_status TEXT NOT NULL,
              stripe_customer_id TEXT,
              stripe_subscription_id TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              full_name TEXT NOT NULL,
              created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memberships (
              user_id TEXT NOT NULL,
              org_id TEXT NOT NULL,
              role TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              PRIMARY KEY(user_id, org_id),
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              label TEXT NOT NULL,
              key_hash TEXT NOT NULL,
              active INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              name TEXT NOT NULL,
              role TEXT NOT NULL,
              model TEXT NOT NULL,
              config_json TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS servers (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              agent_id TEXT,
              region TEXT NOT NULL,
              cpu INTEGER NOT NULL,
              memory_gb INTEGER NOT NULL,
              status TEXT NOT NULL,
              endpoint_url TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
              FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workflows (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              server_id TEXT NOT NULL,
              trigger_type TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
              FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
              FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              server_id TEXT,
              job_type TEXT NOT NULL,
              status TEXT NOT NULL,
              detail TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
              FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invoices (
              id TEXT PRIMARY KEY,
              org_id TEXT NOT NULL,
              amount_cents INTEGER NOT NULL,
              currency TEXT NOT NULL,
              status TEXT NOT NULL,
              external_ref TEXT,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            )
            """
        )
    conn.close()


def require_auth(handler: BaseHTTPRequestHandler, ctx: AppContext) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, "Missing bearer token"
    token = auth.replace("Bearer ", "", 1).strip()
    parsed = verify_token(token, ctx.settings.api_secret, ctx.settings.token_ttl_seconds)
    if not parsed:
        return None, None, "Invalid or expired token"
    user_id, org_id = parsed
    return user_id, org_id, None


def ensure_org_plan_active(conn: sqlite3.Connection, org_id: str) -> bool:
    row = conn.execute(
        "SELECT subscription_status FROM organizations WHERE id=?", (org_id,)
    ).fetchone()
    return bool(row and row["subscription_status"] in {"trialing", "active"})


def create_api_key_pair() -> Tuple[str, str]:
    raw_key = f"aops_live_{secrets.token_urlsafe(24)}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, key_hash


def verify_webhook_signature(raw_body: bytes, provided_sig: str, secret: str) -> bool:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, provided_sig)


def async_finalize_server(ctx: AppContext, job_id: str, server_id: str) -> None:
    def worker() -> None:
        time.sleep(1.0)
        conn = ctx.get_conn()
        try:
            stamp = now_ts()
            with conn:
                conn.execute(
                    "UPDATE jobs SET status=?, detail=?, updated_at=? WHERE id=?",
                    ("done", "Server provisioned.", stamp, job_id),
                )
                conn.execute(
                    "UPDATE servers SET status=?, endpoint_url=?, updated_at=? WHERE id=?",
                    ("active", f"https://{server_id}.agentopscloud.app", stamp, server_id),
                )
        finally:
            conn.close()

    threading.Thread(target=worker, daemon=True).start()


def make_handler(ctx: AppContext):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentOpsHTTP/2.0"

        def do_OPTIONS(self) -> None:
            json_response(self, 200, {"ok": True})

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                return json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "service": "agentops-backend",
                        "version": "2.0.0",
                        "time": now_ts(),
                    },
                )
            if parsed.path == "/api/agents":
                return self.list_agents()
            if parsed.path == "/api/servers":
                return self.list_servers()
            if parsed.path.startswith("/api/jobs/"):
                return self.get_job(parsed.path.split("/")[-1])
            if parsed.path == "/api/billing/subscription":
                return self.get_subscription()
            if parsed.path == "/api/keys":
                return self.list_api_keys()
            return error_response(self, 404, "Not found")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/auth/register":
                return self.register()
            if parsed.path == "/api/auth/login":
                return self.login()
            if parsed.path == "/api/agents":
                return self.create_agent()
            if parsed.path == "/api/servers/provision":
                return self.provision_server()
            if parsed.path == "/api/workflows/run":
                return self.run_workflow()
            if parsed.path == "/api/billing/checkout-session":
                return self.create_checkout_session()
            if parsed.path == "/api/billing/webhook":
                return self.billing_webhook()
            if parsed.path == "/api/keys":
                return self.create_api_key()
            return error_response(self, 404, "Not found")

        def register(self) -> None:
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            email = (payload.get("email") or "").strip().lower()
            password = payload.get("password") or ""
            full_name = (payload.get("fullName") or "").strip()
            org_name = (payload.get("organizationName") or "").strip()
            if not (email and password and full_name and org_name):
                return error_response(self, 400, "email, password, fullName, organizationName required")
            if len(password) < 8:
                return error_response(self, 400, "Password must be at least 8 characters")

            user_id = f"usr_{uuid.uuid4().hex[:10]}"
            org_id = f"org_{uuid.uuid4().hex[:10]}"
            stamp = now_ts()
            conn = ctx.get_conn()
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO organizations(id, name, plan, subscription_status, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                        (org_id, org_name, "starter", "trialing", stamp, stamp),
                    )
                    conn.execute(
                        "INSERT INTO users(id, email, password_hash, full_name, created_at) VALUES(?,?,?,?,?)",
                        (user_id, email, hash_password(password), full_name, stamp),
                    )
                    conn.execute(
                        "INSERT INTO memberships(user_id, org_id, role, created_at) VALUES(?,?,?,?)",
                        (user_id, org_id, "owner", stamp),
                    )
            except sqlite3.IntegrityError:
                conn.close()
                return error_response(self, 409, "Email already registered")
            conn.close()

            token = issue_token(user_id, org_id, ctx.settings.api_secret)
            return json_response(
                self,
                201,
                {
                    "token": token,
                    "user": {"id": user_id, "email": email, "fullName": full_name},
                    "organization": {"id": org_id, "name": org_name, "plan": "starter", "subscriptionStatus": "trialing"},
                },
            )

        def login(self) -> None:
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            email = (payload.get("email") or "").strip().lower()
            password = payload.get("password") or ""
            if not (email and password):
                return error_response(self, 400, "email and password required")

            conn = ctx.get_conn()
            row = conn.execute("SELECT id, password_hash, full_name FROM users WHERE email=?", (email,)).fetchone()
            if not row or row["password_hash"] != hash_password(password):
                conn.close()
                return error_response(self, 401, "Invalid credentials")
            membership = conn.execute(
                "SELECT org_id FROM memberships WHERE user_id=? ORDER BY created_at LIMIT 1", (row["id"],)
            ).fetchone()
            org = conn.execute(
                "SELECT id, name, plan, subscription_status FROM organizations WHERE id=?", (membership["org_id"],)
            ).fetchone()
            conn.close()

            token = issue_token(row["id"], org["id"], ctx.settings.api_secret)
            return json_response(
                self,
                200,
                {
                    "token": token,
                    "user": {"id": row["id"], "email": email, "fullName": row["full_name"]},
                    "organization": {
                        "id": org["id"],
                        "name": org["name"],
                        "plan": org["plan"],
                        "subscriptionStatus": org["subscription_status"],
                    },
                },
            )

        def create_agent(self) -> None:
            user_id, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            name = (payload.get("name") or "").strip()
            role = (payload.get("role") or "").strip()
            model = (payload.get("model") or "gpt-4.1").strip()
            config = payload.get("config") or {}
            if not (name and role):
                return error_response(self, 400, "name and role required")

            agent_id = f"agt_{uuid.uuid4().hex[:10]}"
            stamp = now_ts()
            conn = ctx.get_conn()
            with conn:
                conn.execute(
                    "INSERT INTO agents(id, org_id, name, role, model, config_json, created_at) VALUES(?,?,?,?,?,?,?)",
                    (agent_id, org_id, name, role, model, json.dumps(config), stamp),
                )
            conn.close()
            return json_response(
                self,
                201,
                {"agent": {"id": agent_id, "name": name, "role": role, "model": model, "config": config, "createdAt": stamp}},
            )

        def list_agents(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            conn = ctx.get_conn()
            rows = conn.execute(
                "SELECT id, name, role, model, config_json, created_at FROM agents WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
            conn.close()
            agents = [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "role": r["role"],
                    "model": r["model"],
                    "config": json.loads(r["config_json"]),
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]
            return json_response(self, 200, {"agents": agents})

        def provision_server(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            agent_id = payload.get("agentId")
            region = (payload.get("region") or "us-east-1").strip()
            cpu = int(payload.get("cpu") or 2)
            memory_gb = int(payload.get("memoryGb") or 4)
            if cpu < 1 or memory_gb < 1:
                return error_response(self, 400, "cpu and memoryGb must be positive")

            conn = ctx.get_conn()
            if not ensure_org_plan_active(conn, org_id):
                conn.close()
                return error_response(self, 402, "Subscription inactive. Upgrade or pay invoice.")
            if agent_id:
                match = conn.execute(
                    "SELECT id FROM agents WHERE id=? AND org_id=?", (agent_id, org_id)
                ).fetchone()
                if not match:
                    conn.close()
                    return error_response(self, 404, "Agent not found")

            server_id = f"srv_{uuid.uuid4().hex[:10]}"
            job_id = f"job_{uuid.uuid4().hex[:10]}"
            stamp = now_ts()
            with conn:
                conn.execute(
                    """
                    INSERT INTO servers(id, org_id, agent_id, region, cpu, memory_gb, status, endpoint_url, created_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (server_id, org_id, agent_id, region, cpu, memory_gb, "provisioning", None, stamp, stamp),
                )
                conn.execute(
                    "INSERT INTO jobs(id, org_id, server_id, job_type, status, detail, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (job_id, org_id, server_id, "provision_server", "running", "Provisioning started", stamp, stamp),
                )
            conn.close()
            async_finalize_server(ctx, job_id, server_id)
            return json_response(self, 202, {"job": {"id": job_id, "status": "running", "serverId": server_id}})

        def list_servers(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            query = parse_qs(urlparse(self.path).query)
            status = (query.get("status") or [None])[0]
            conn = ctx.get_conn()
            if status:
                rows = conn.execute(
                    "SELECT id, agent_id, region, cpu, memory_gb, status, endpoint_url, created_at, updated_at FROM servers WHERE org_id=? AND status=? ORDER BY created_at DESC",
                    (org_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, agent_id, region, cpu, memory_gb, status, endpoint_url, created_at, updated_at FROM servers WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            conn.close()
            servers = [
                {
                    "id": r["id"],
                    "agentId": r["agent_id"],
                    "region": r["region"],
                    "cpu": r["cpu"],
                    "memoryGb": r["memory_gb"],
                    "status": r["status"],
                    "endpointUrl": r["endpoint_url"],
                    "createdAt": r["created_at"],
                    "updatedAt": r["updated_at"],
                }
                for r in rows
            ]
            return json_response(self, 200, {"servers": servers})

        def get_job(self, job_id: str) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            conn = ctx.get_conn()
            row = conn.execute(
                "SELECT id, server_id, job_type, status, detail, created_at, updated_at FROM jobs WHERE id=? AND org_id=?",
                (job_id, org_id),
            ).fetchone()
            conn.close()
            if not row:
                return error_response(self, 404, "Job not found")
            return json_response(
                self,
                200,
                {
                    "job": {
                        "id": row["id"],
                        "serverId": row["server_id"],
                        "type": row["job_type"],
                        "status": row["status"],
                        "detail": row["detail"],
                        "createdAt": row["created_at"],
                        "updatedAt": row["updated_at"],
                    }
                },
            )

        def run_workflow(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            agent_id = payload.get("agentId")
            server_id = payload.get("serverId")
            trigger_type = (payload.get("triggerType") or "scheduled").strip()
            if not agent_id or not server_id:
                return error_response(self, 400, "agentId and serverId required")

            conn = ctx.get_conn()
            agent = conn.execute("SELECT id FROM agents WHERE id=? AND org_id=?", (agent_id, org_id)).fetchone()
            server = conn.execute("SELECT id, status FROM servers WHERE id=? AND org_id=?", (server_id, org_id)).fetchone()
            if not agent:
                conn.close()
                return error_response(self, 404, "Agent not found")
            if not server:
                conn.close()
                return error_response(self, 404, "Server not found")
            if server["status"] != "active":
                conn.close()
                return error_response(self, 409, "Server must be active")

            workflow_id = f"wfk_{uuid.uuid4().hex[:10]}"
            stamp = now_ts()
            with conn:
                conn.execute(
                    "INSERT INTO workflows(id, org_id, agent_id, server_id, trigger_type, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (workflow_id, org_id, agent_id, server_id, trigger_type, "running", stamp, stamp),
                )
            conn.close()
            return json_response(self, 201, {"workflow": {"id": workflow_id, "status": "running", "createdAt": stamp}})

        def create_checkout_session(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")

            plan = (payload.get("plan") or "growth").strip()
            if plan not in {"starter", "growth", "scale"}:
                return error_response(self, 400, "Unsupported plan")

            session_id = f"cs_test_{uuid.uuid4().hex[:14]}"
            conn = ctx.get_conn()
            stamp = now_ts()
            with conn:
                conn.execute(
                    "UPDATE organizations SET plan=?, updated_at=? WHERE id=?",
                    (plan, stamp, org_id),
                )
            conn.close()
            return json_response(
                self,
                201,
                {
                    "checkoutSession": {
                        "id": session_id,
                        "provider": "stripe",
                        "status": "created",
                        "plan": plan,
                        "url": f"https://checkout.stripe.com/pay/{session_id}",
                    }
                },
            )

        def get_subscription(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            conn = ctx.get_conn()
            org = conn.execute(
                "SELECT id, name, plan, subscription_status, stripe_customer_id, stripe_subscription_id, created_at, updated_at FROM organizations WHERE id=?",
                (org_id,),
            ).fetchone()
            invoices = conn.execute(
                "SELECT id, amount_cents, currency, status, external_ref, created_at FROM invoices WHERE org_id=? ORDER BY created_at DESC LIMIT 10",
                (org_id,),
            ).fetchall()
            conn.close()
            return json_response(
                self,
                200,
                {
                    "subscription": {
                        "organizationId": org["id"],
                        "organizationName": org["name"],
                        "plan": org["plan"],
                        "status": org["subscription_status"],
                        "stripeCustomerId": org["stripe_customer_id"],
                        "stripeSubscriptionId": org["stripe_subscription_id"],
                        "updatedAt": org["updated_at"],
                    },
                    "invoices": [
                        {
                            "id": i["id"],
                            "amountCents": i["amount_cents"],
                            "currency": i["currency"],
                            "status": i["status"],
                            "externalRef": i["external_ref"],
                            "createdAt": i["created_at"],
                        }
                        for i in invoices
                    ],
                },
            )

        def billing_webhook(self) -> None:
            sig = self.headers.get("X-AgentOps-Signature", "")
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            if not verify_webhook_signature(raw, sig, ctx.settings.webhook_secret):
                return error_response(self, 401, "Invalid webhook signature")
            try:
                event = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")

            event_type = event.get("type")
            data = event.get("data") or {}
            org_id = data.get("organizationId")
            if not org_id:
                return error_response(self, 400, "organizationId required in data")

            conn = ctx.get_conn()
            org = conn.execute("SELECT id FROM organizations WHERE id=?", (org_id,)).fetchone()
            if not org:
                conn.close()
                return error_response(self, 404, "Organization not found")

            stamp = now_ts()
            with conn:
                if event_type == "subscription.activated":
                    conn.execute(
                        "UPDATE organizations SET subscription_status=?, stripe_customer_id=?, stripe_subscription_id=?, updated_at=? WHERE id=?",
                        ("active", data.get("customerId"), data.get("subscriptionId"), stamp, org_id),
                    )
                elif event_type == "subscription.canceled":
                    conn.execute(
                        "UPDATE organizations SET subscription_status=?, updated_at=? WHERE id=?",
                        ("canceled", stamp, org_id),
                    )
                elif event_type == "invoice.paid":
                    conn.execute(
                        "INSERT INTO invoices(id, org_id, amount_cents, currency, status, external_ref, created_at) VALUES(?,?,?,?,?,?,?)",
                        (
                            f"inv_{uuid.uuid4().hex[:10]}",
                            org_id,
                            int(data.get("amountCents") or 0),
                            data.get("currency") or "usd",
                            "paid",
                            data.get("invoiceId"),
                            stamp,
                        ),
                    )
                elif event_type == "invoice.payment_failed":
                    conn.execute(
                        "INSERT INTO invoices(id, org_id, amount_cents, currency, status, external_ref, created_at) VALUES(?,?,?,?,?,?,?)",
                        (
                            f"inv_{uuid.uuid4().hex[:10]}",
                            org_id,
                            int(data.get("amountCents") or 0),
                            data.get("currency") or "usd",
                            "failed",
                            data.get("invoiceId"),
                            stamp,
                        ),
                    )
                    conn.execute(
                        "UPDATE organizations SET subscription_status=?, updated_at=? WHERE id=?",
                        ("past_due", stamp, org_id),
                    )
                else:
                    conn.close()
                    return error_response(self, 400, f"Unhandled event type: {event_type}")
            conn.close()
            return json_response(self, 200, {"received": True})

        def create_api_key(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            try:
                payload = read_json_body(self)
            except json.JSONDecodeError:
                return error_response(self, 400, "Invalid JSON")
            label = (payload.get("label") or "default").strip()
            key_id = f"key_{uuid.uuid4().hex[:10]}"
            raw_key, key_hash = create_api_key_pair()
            stamp = now_ts()
            conn = ctx.get_conn()
            with conn:
                conn.execute(
                    "INSERT INTO api_keys(id, org_id, label, key_hash, active, created_at) VALUES(?,?,?,?,?,?)",
                    (key_id, org_id, label, key_hash, 1, stamp),
                )
            conn.close()
            return json_response(
                self,
                201,
                {"apiKey": {"id": key_id, "label": label, "key": raw_key, "createdAt": stamp}},
            )

        def list_api_keys(self) -> None:
            _, org_id, err = require_auth(self, ctx)
            if err:
                return error_response(self, 401, err)
            conn = ctx.get_conn()
            keys = conn.execute(
                "SELECT id, label, active, created_at FROM api_keys WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
            conn.close()
            return json_response(
                self,
                200,
                {
                    "apiKeys": [
                        {"id": k["id"], "label": k["label"], "active": bool(k["active"]), "createdAt": k["created_at"]}
                        for k in keys
                    ]
                },
            )

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def run_server(settings: Optional[Settings] = None) -> None:
    settings = settings or Settings()
    ctx = AppContext(settings=settings)
    init_db(ctx)
    srv = ThreadingHTTPServer((settings.host, settings.port), make_handler(ctx))
    print(f"AgentOps backend listening on http://{settings.host}:{settings.port}")
    srv.serve_forever()


if __name__ == "__main__":
    run_server()
