import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib import error, request

from backend import AppContext, Settings, init_db, make_handler


WEBHOOK_SECRET = "test-webhook-secret"


def call_json(method, url, payload=None, token=None, headers=None):
    data = None
    req_headers = {"Content-Type": "application/json"}
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if headers:
        req_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = request.Request(url, method=method, data=data, headers=req_headers)
    try:
        with request.urlopen(req, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class BackendAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(delete=False)
        cls.tmp.close()
        settings = Settings(db_path=cls.tmp.name, api_secret="test-api-secret", webhook_secret=WEBHOOK_SECRET)
        cls.ctx = AppContext(settings=settings)
        init_db(cls.ctx)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.ctx))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        os.unlink(cls.tmp.name)

    def register_user(self, email="founder@example.com"):
        status, data = call_json(
            "POST",
            f"{self.base}/api/auth/register",
            {
                "email": email,
                "password": "strongpass123",
                "fullName": "Founder One",
                "organizationName": "Acme AI",
            },
        )
        self.assertEqual(status, 201)
        return data["token"], data["organization"]["id"]

    def test_full_provisioning_and_workflow_flow(self):
        token, _ = self.register_user()

        status, data = call_json(
            "POST",
            f"{self.base}/api/agents",
            {"name": "Revenue Agent", "role": "upsell", "model": "gpt-4.1", "config": {"channel": "email"}},
            token=token,
        )
        self.assertEqual(status, 201)
        agent_id = data["agent"]["id"]

        status, data = call_json(
            "POST",
            f"{self.base}/api/servers/provision",
            {"agentId": agent_id, "region": "us-west-2", "cpu": 2, "memoryGb": 4},
            token=token,
        )
        self.assertEqual(status, 202)
        job_id = data["job"]["id"]
        server_id = data["job"]["serverId"]

        time.sleep(1.2)
        status, data = call_json("GET", f"{self.base}/api/jobs/{job_id}", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(data["job"]["status"], "done")

        status, data = call_json("GET", f"{self.base}/api/servers?status=active", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(data["servers"][0]["id"], server_id)

        status, data = call_json(
            "POST",
            f"{self.base}/api/workflows/run",
            {"agentId": agent_id, "serverId": server_id, "triggerType": "event"},
            token=token,
        )
        self.assertEqual(status, 201)
        self.assertEqual(data["workflow"]["status"], "running")

    def test_billing_webhook_and_subscription_visibility(self):
        token, org_id = self.register_user("billing@example.com")

        status, data = call_json(
            "POST",
            f"{self.base}/api/billing/checkout-session",
            {"plan": "growth"},
            token=token,
        )
        self.assertEqual(status, 201)
        self.assertEqual(data["checkoutSession"]["plan"], "growth")

        event = {
            "type": "subscription.activated",
            "data": {"organizationId": org_id, "customerId": "cus_123", "subscriptionId": "sub_123"},
        }
        raw = json.dumps(event).encode("utf-8")
        sig = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()

        status, _ = call_json(
            "POST",
            f"{self.base}/api/billing/webhook",
            payload=event,
            headers={"X-AgentOps-Signature": sig},
        )
        self.assertEqual(status, 200)

        invoice_event = {
            "type": "invoice.paid",
            "data": {"organizationId": org_id, "amountCents": 19900, "currency": "usd", "invoiceId": "in_123"},
        }
        raw = json.dumps(invoice_event).encode("utf-8")
        sig = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        status, _ = call_json(
            "POST",
            f"{self.base}/api/billing/webhook",
            payload=invoice_event,
            headers={"X-AgentOps-Signature": sig},
        )
        self.assertEqual(status, 200)

        status, data = call_json("GET", f"{self.base}/api/billing/subscription", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(data["subscription"]["status"], "active")
        self.assertEqual(data["subscription"]["plan"], "growth")
        self.assertEqual(len(data["invoices"]), 1)

    def test_api_key_management(self):
        token, _ = self.register_user("keys@example.com")
        status, data = call_json("POST", f"{self.base}/api/keys", {"label": "CI Runner"}, token=token)
        self.assertEqual(status, 201)
        self.assertTrue(data["apiKey"]["key"].startswith("aops_live_"))

        status, data = call_json("GET", f"{self.base}/api/keys", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(data["apiKeys"]), 1)
        self.assertEqual(data["apiKeys"][0]["label"], "CI Runner")

    def test_auth_required(self):
        status, data = call_json("GET", f"{self.base}/api/agents")
        self.assertEqual(status, 401)
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main()
