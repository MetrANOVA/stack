#!/usr/bin/env python3
"""
MetrANOVA Auth Wizard

All-in-one setup tool for MetrANOVA auth stack.  Manages K8s secrets,
ClickHouse authz configuration, and Keycloak groups.

Usage:
    python3 auth_wizard.py [--namespace metranova] [--release metranova-auth]
    python3 auth_wizard.py --no-tui --dry-run    # headless / CI
    python3 auth_wizard.py --export-csv secrets.csv
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import secrets
import signal
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# ── Ports used for local port-forwards ────────────────────────────────────────

PF_CH_LOCAL_PORT  = 19440   # ClickHouse TLS
PF_KC_LOCAL_PORT  = 19080   # Keycloak HTTP (management port via Envoy or direct)

TLP_LEVELS  = ["tlp:clear", "tlp:green", "tlp:amber", "tlp:red"]
TLP_NUMERIC = {lvl: i for i, lvl in enumerate(TLP_LEVELS)}

# ── Secret field definitions (step 0) ─────────────────────────────────────────

@dataclass
class SecretField:
    key: str          # "secret-name/field-key"
    label: str
    description: str
    group: str
    generate: object  # callable
    value: str = ""
    confirmed: bool = False
    sensitive: bool = True


def gen_password(length=24):
    alphabet = string.ascii_letters + string.digits + "!@#%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_token():
    return secrets.token_urlsafe(32)


def gen_fernet():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def gen_hex():
    return secrets.token_hex(32)


def gen_selfsigned_tls():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        crt = os.path.join(d, "tls.crt")
        key = os.path.join(d, "tls.key")
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", crt,
            "-days", "365", "-nodes",
            "-subj", "/CN=metranova-auth",
            "-addext", "subjectAltName=DNS:metranova-auth,DNS:localhost",
        ], capture_output=True)
        if result.returncode != 0:
            return ""
        return open(crt).read() + "---KEY---\n" + open(key).read()


def make_fields(release: str) -> list[SecretField]:
    return [
        SecretField(
            key="clickhouse-users/admin-password",
            label="ClickHouse admin password",
            description="Full-access admin password for ClickHouse.",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/pipeline-password",
            label="ClickHouse pipeline password",
            description="Password for the pipeline ingest user.",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/grafana-password",
            label="ClickHouse Grafana password",
            description="Password for the Grafana read-only user.",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/KEYCLOAK_ADMIN_PASSWORD",
            label="Keycloak admin password",
            description="Password for the Keycloak admin account.",
            group="Keycloak",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_OIDC_CLIENT_SECRET",
            label="Envoy OIDC client secret",
            description="OAuth2 client secret for the Envoy proxy.",
            group="Envoy",
            generate=gen_token,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_HMAC_SECRET",
            label="Envoy HMAC secret",
            description="HMAC signing secret for Envoy session cookies.",
            group="Envoy",
            generate=gen_hex,
        ),
        SecretField(
            key=f"{release}-secrets/CROSS_INSTANCE_CLIENT_SECRET",
            label="Cross-instance OIDC client secret",
            description="Client secret for federated cross-instance queries.",
            group="Keycloak",
            generate=gen_token,
        ),
        SecretField(
            key=f"{release}-tls/combined",
            label="TLS certificate + key",
            description="Self-signed TLS certificate for Envoy. Replace with a real cert in production.",
            group="TLS",
            generate=gen_selfsigned_tls,
            sensitive=False,
        ),
    ]


# ── Port-forward management ────────────────────────────────────────────────────

class PortForward:
    """Manages a kubectl port-forward subprocess."""

    def __init__(self, namespace: str, target: str, remote_port: int, local_port: int):
        self.namespace = namespace
        self.target = target        # e.g. "svc/metranova-auth-clickhouse"
        self.remote_port = remote_port
        self.local_port = local_port
        self._proc: Optional[subprocess.Popen] = None

    def start(self, timeout: float = 10.0) -> bool:
        """Start the port-forward. Returns True if port becomes reachable."""
        self._proc = subprocess.Popen(
            ["kubectl", "port-forward", "-n", self.namespace,
             self.target, f"{self.local_port}:{self.remote_port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.25)
        return False

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()


# ── ClickHouse client wrapper ──────────────────────────────────────────────────

class ClickHouseClient:
    def __init__(self, host: str = "127.0.0.1", port: int = PF_CH_LOCAL_PORT,
                 user: str = "default", password: str = ""):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self._base_cmd = [
            "clickhouse-client",
            "--host", host, "--secure", "--port", str(port),
            "--user", user, "--password", password,
            "--accept-invalid-certificate",
        ]

    def query(self, sql: str) -> str:
        result = subprocess.run(
            self._base_cmd + ["--query", sql],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        return result.stdout.strip()

    def multiquery(self, sql: str) -> str:
        result = subprocess.run(
            self._base_cmd + ["--multiquery"],
            input=sql, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        return result.stdout.strip()

    def ping(self) -> bool:
        try:
            self.query("SELECT 1")
            return True
        except Exception:
            return False


# ── Keycloak Admin API client ──────────────────────────────────────────────────

class KeycloakClient:
    def __init__(self, base_url: str, realm: str = "metranova",
                 admin_user: str = "admin", admin_password: str = ""):
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.admin_user = admin_user
        self.admin_password = admin_password
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        data = urllib.parse.urlencode({
            "client_id": "admin-cli",
            "username": self.admin_user,
            "password": self.admin_password,
            "grant_type": "password",
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data=data, method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())["access_token"]

    def _request(self, method: str, path: str, body=None) -> dict | list | None:
        if not self._token:
            self._token = self._get_token()
        url = f"{self.base_url}/admin/realms/{self.realm}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self._token = None
                return self._request(method, path, body)
            raise

    def ping(self) -> bool:
        try:
            self._get_token()
            return True
        except Exception:
            return False

    def list_groups(self) -> list[dict]:
        return self._request("GET", "/groups") or []

    def create_group(self, name: str) -> str:
        """Create a group and return its ID. Idempotent — returns existing ID."""
        existing = [g for g in self.list_groups() if g["name"] == name]
        if existing:
            return existing[0]["id"]
        self._request("POST", "/groups", {"name": name})
        return next(g["id"] for g in self.list_groups() if g["name"] == name)

    def delete_group(self, group_id: str):
        self._request("DELETE", f"/groups/{group_id}")

    def list_realm_roles(self) -> list[dict]:
        return self._request("GET", "/roles") or []


# ── K8s / cluster helpers ──────────────────────────────────────────────────────

def kubectl_get_secret_field(secret_name: str, field: str, namespace: str) -> str:
    """Return the decoded value of a secret field, or '' if not found."""
    result = subprocess.run(
        ["kubectl", "get", "secret", secret_name, "-n", namespace,
         "-o", f"jsonpath={{.data.{field}}}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return ""
    try:
        return base64.b64decode(result.stdout.strip()).decode()
    except Exception:
        return ""


def load_keycloak_admin_password(release: str, namespace: str) -> str:
    return kubectl_get_secret_field(f"{release}-secrets", "KEYCLOAK_ADMIN_PASSWORD", namespace)


def load_ch_admin_password(namespace: str) -> str:
    return kubectl_get_secret_field("clickhouse-users", "admin-password", namespace)


def cluster_is_reachable(namespace: str) -> bool:
    result = subprocess.run(
        ["kubectl", "get", "namespace", namespace],
        capture_output=True, text=True,
    )
    return result.returncode == 0


# ── Secret bootstrap helpers (step 0) ─────────────────────────────────────────

def group_fields(fields: list[SecretField]) -> dict:
    groups: dict[str, dict] = {}
    for f in fields:
        if f.value and "---KEY---" in f.value:
            continue
        secret_name, key = f.key.split("/", 1)
        groups.setdefault(secret_name, {})[key] = f.value
    return groups


def apply_secrets(groups: dict, namespace: str, release: str,
                  dry_run: bool, fields: list[SecretField] = None):
    for secret_name, kv in groups.items():
        literals = [f"--from-literal={k}={v!r}" for k, v in kv.items()]

        if secret_name == f"{release}-secrets":
            literals.append("--from-literal=KEYCLOAK_ADMIN=admin")
            oidc = kv.get("ENVOY_OIDC_CLIENT_SECRET", "")
            hmac = kv.get("ENVOY_HMAC_SECRET", "")
            token_yaml = (
                "resources:\n"
                "- \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n"
                "  name: token-secret\n  generic_secret:\n    secret:\n"
                f"      inline_string: {oidc}"
            )
            hmac_yaml = (
                "resources:\n"
                "- \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n"
                "  name: hmac-secret\n  generic_secret:\n    secret:\n"
                f"      inline_string: {hmac}"
            )
            literals += [
                f"--from-literal=token.yaml={token_yaml!r}",
                f"--from-literal=hmac.yaml={hmac_yaml!r}",
            ]

        cmd = (
            f"kubectl create secret generic {secret_name} "
            f"-n {namespace} {' '.join(literals)} "
            f"--dry-run=client -o yaml | kubectl apply -f -"
        )
        if dry_run:
            print(cmd)
        else:
            print(f"  Creating secret: {secret_name}")
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  ERROR: {r.stderr}", file=sys.stderr)
            else:
                print(f"  OK: {secret_name}")

    tls_field = next((f for f in (fields or []) if f.value and "---KEY---" in f.value), None)
    if tls_field:
        cert, key = tls_field.value.split("---KEY---\n", 1)
        tls_secret = tls_field.key.split("/")[0]
        if dry_run:
            print(f"# kubectl create secret generic {tls_secret} -n {namespace} --from-file=...")
        else:
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                crt_path = os.path.join(d, "server.crt")
                key_path = os.path.join(d, "server.key")
                open(crt_path, "w").write(cert)
                open(key_path, "w").write(key)
                cmd = (
                    f"kubectl create secret generic {tls_secret} -n {namespace} "
                    f"--from-file=server.crt={crt_path} --from-file=server.key={key_path} "
                    f"--from-file=tls.crt={crt_path} --from-file=tls.key={key_path} "
                    f"--dry-run=client -o yaml | kubectl apply -f -"
                )
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if r.returncode != 0:
                    print(f"  ERROR: {r.stderr}", file=sys.stderr)
                else:
                    print(f"  OK: {tls_secret}")


def export_csv(fields: list[SecretField], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Secret", "Key", "Value", "Notes"])
        for fld in fields:
            secret_name, key = fld.key.split("/", 1)
            writer.writerow([secret_name, key, fld.value, fld.description[:80]])
    print(f"Exported to {path}")


def load_existing_secrets(fields: list[SecretField], namespace: str, d=None):
    secret_names = list(dict.fromkeys(f.key.split("/", 1)[0] for f in fields))
    total = len(secret_names)
    existing: dict[str, dict] = {}
    for i, secret_name in enumerate(secret_names):
        if d:
            d.infobox(
                f"Checking existing secrets in namespace '{namespace}'...\n\n"
                f"  {secret_name}  ({i + 1}/{total})",
                width=60, height=8, title="Loading",
            )
        result = subprocess.run(
            ["kubectl", "get", "secret", secret_name, "-n", namespace,
             "-o", "jsonpath={.data}"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                existing[secret_name] = json.loads(result.stdout)
            except json.JSONDecodeError:
                existing[secret_name] = {}

    for f in fields:
        secret_name, key = f.key.split("/", 1)
        if secret_name not in existing:
            continue
        if key == "combined" or key in existing[secret_name]:
            f.value = "(already set in cluster)"
            f.sensitive = False
            f.confirmed = True


# ── TUI: dialog helpers ────────────────────────────────────────────────────────

def _make_dialog(namespace: str):
    import dialog
    d = dialog.Dialog()
    d.set_background_title(f"MetrANOVA Auth Wizard  |  namespace: {namespace}")
    return d


def _msgbox(d, msg: str, title: str = "", width: int = 60, height: int = 10):
    d.msgbox(msg, title=title, width=width, height=height)


def _error(d, msg: str):
    _msgbox(d, msg, title="Error")


def _confirm(d, msg: str, title: str = "", width: int = 60, height: int = 10) -> bool:
    code = d.yesno(msg, title=title, width=width, height=height,
                   yes_label="Yes", no_label="No")
    return code == d.OK


# ── TUI: step 0 — secrets ─────────────────────────────────────────────────────

def _edit_secret_field(d, f: SecretField):
    while True:
        if f.value:
            display = ("*** (hidden — use View/Edit to reveal)"
                       if f.sensitive else f.value[:300] + ("..." if len(f.value) > 300 else ""))
        else:
            display = "(not set)"

        status = "[CONFIRMED]" if f.confirmed else "[unconfirmed]"
        body = f"{f.description}\n\nValue: {display}\n\nStatus: {status}"

        code = d.yesno(
            body, title=f.label, width=70, height=18,
            yes_label="Confirm", no_label="Back",
            extra_button=True, extra_label="Generate",
            help_button=True, help_label="View/Edit",
        )
        if code in (d.CANCEL, d.ESC):
            return
        if code == d.OK:
            if not f.value:
                f.value = f.generate()
            f.confirmed = True
            return
        if code == "extra":
            f.value = f.generate()
            f.confirmed = False
        if code == "help":
            init = f.value if f.value not in ("", "(not set)") else ""
            c, val = d.inputbox(
                f"View or edit value for: {f.label}\n\n"
                "(Leave unchanged and press OK to keep current value.)",
                title=f.label, width=70, height=14, init=init,
            )
            if c == d.OK:
                new = val.strip()
                if new and new != f.value:
                    f.value = new
                    f.confirmed = False


def _run_secrets_menu(d, fields: list[SecretField]):
    while True:
        done  = sum(1 for f in fields if f.confirmed)
        total = len(fields)
        all_done = done == total

        choices = [(str(i), f"{'[x]' if f.confirmed else '[ ]'} {f.label}  ({f.group})")
                   for i, f in enumerate(fields)]

        msg = f"Progress: {done}/{total} confirmed.\n"
        msg += ("All confirmed. Press Write when ready."
                if all_done else "Open a secret to confirm it.")

        code, tag = d.menu(
            msg, choices=choices,
            width=76, height=24, menu_height=16, title="Secrets",
            ok_label="Open",
            extra_button=True, extra_label="Generate All",
            help_button=True, help_label="Write",
            cancel_label="Back",
        )

        if code in (d.CANCEL, d.ESC):
            return False

        if code == "extra":
            for f in fields:
                if not f.confirmed:
                    f.value = f.generate()
                    f.confirmed = True
            continue

        if code == "help":
            if not all_done:
                _msgbox(d, f"Not all secrets confirmed ({done}/{total}).\n"
                        "Confirm all before writing.", title="Cannot write yet")
                continue
            # confirm write
            c2, tag2 = d.menu(
                f"Write {len(group_fields(fields))} secrets to namespace?",
                title="Write secrets", width=60, height=12, menu_height=3,
                choices=[("W", "Write now"), ("X", "Export CSV then write"), ("Q", "Abort")],
                ok_label="Select", cancel_label="Abort",
            )
            if c2 in (d.CANCEL, d.ESC) or tag2 == "Q":
                continue
            return ("export_write" if tag2 == "X" else "write")

        _edit_secret_field(d, fields[int(tag)])


_PHASE_MSGS = [
    "Signalling ArgoCD...",
    "ArgoCD reconciling resources...",
    "Waiting for pods to be scheduled...",
    "Pods initialising...",
    "Waiting for health probes...",
    "Almost there...",
]


def argocd_sync_and_wait(d, namespace: str, app_name: str = "metranova-auth",
                          timeout: int = 300):
    """Trigger ArgoCD sync and wait for all pods to be ready.

    Runs polling in a background thread. The main thread drives
    d.gauge_start/update/stop so the terminal stays responsive to Ctrl+C.
    Press Ctrl+C or Escape at any time to abort.

    Returns True if all pods reached Ready within timeout, False otherwise.
    """
    import threading

    ctx_flag    = ["--context", _kubectl_context()]
    stop_event  = threading.Event()   # set to abort
    result_box  = [False]             # written by worker thread

    # Shared state updated by worker, read by gauge updater
    state = {
        "percent":  0,
        "text":     "Connecting to cluster...",
        "aborted":  False,
        "done":     False,
    }

    def _pod_line(parts: list[str]) -> str:
        name     = parts[0][:40]
        is_ready = len(parts) > 1 and parts[1].lower() == "true"
        status   = parts[2] if len(parts) > 2 else "?"
        restarts = parts[3] if len(parts) > 3 else "0"
        icon     = "✓" if is_ready else ("!" if status == "CrashLoopBackOff" else "…")
        restart_str = f" (r:{restarts})" if restarts not in ("0", "<none>") else ""
        return f"  {icon} {name:<40} {status}{restart_str}"

    def worker():
        log: list[str] = []

        def update(percent: int, msg: str):
            state["percent"] = percent
            state["text"]    = msg

        # Step 1: trigger sync
        update(2, "→ Annotating ArgoCD app for hard refresh...")
        subprocess.run(
            ["kubectl", "annotate", "application", app_name,
             "-n", "argocd",
             "argocd.argoproj.io/refresh=hard",
             "--overwrite"] + ctx_flag,
            capture_output=True,
        )
        if stop_event.is_set():
            return

        update(5, "→ Triggering ArgoCD sync...")
        r = subprocess.run(
            ["argocd", "app", "sync", app_name, "--async"],
            capture_output=True, text=True,
        )
        argocd_note = "✓ argocd sync triggered" if r.returncode == 0 \
                      else "(argocd CLI not found — annotation only)"
        log.append(argocd_note)

        # Step 2: poll pods
        start = time.time()
        prev_summary: list[str] = []

        while not stop_event.is_set():
            elapsed = time.time() - start
            if elapsed >= timeout:
                state["done"] = True
                return

            result = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "--no-headers",
                 "-o", "custom-columns="
                       "NAME:.metadata.name,"
                       "READY:.status.containerStatuses[0].ready,"
                       "STATUS:.status.phase,"
                       "RESTARTS:.status.containerStatuses[0].restartCount"] + ctx_flag,
                capture_output=True, text=True,
            )
            raw = [l for l in result.stdout.splitlines() if l.strip()]

            if not raw:
                phase = _PHASE_MSGS[1] if elapsed < 15 else _PHASE_MSGS[2]
                pct   = min(5 + int(elapsed / timeout * 20), 25)
                update(pct, f"{phase}\n\n{argocd_note}")
                time.sleep(2)
                continue

            ready = sum(1 for l in raw if len(l.split()) > 1 and l.split()[1].lower() == "true")
            total = len(raw)
            summary = [_pod_line(l.split()) for l in raw]

            # append new/changed lines to the running log
            for line in summary:
                if line not in prev_summary:
                    log.append(line.strip())
            prev_summary = summary

            frac  = ready / max(total, 1)
            pct   = min(10 + int(frac * 85), 99)
            if   frac == 0:   phase = _PHASE_MSGS[3]
            elif frac < 0.5:  phase = _PHASE_MSGS[4]
            elif frac < 1.0:  phase = _PHASE_MSGS[5]
            else:             phase = f"All {total} pods ready!"

            body = (
                f"{phase}  ({ready}/{total} ready)  [{int(elapsed)}s]\n\n"
                + "\n".join(summary)
                + "\n\n"
                + "\n".join(log[-3:])
            )
            update(pct, body)

            if ready == total and total > 0:
                result_box[0] = True
                state["done"] = True
                return

            time.sleep(2)

        # stopped by signal
        state["aborted"] = True
        state["done"]    = True

    # ── Main thread: drive the gauge ──────────────────────────────────────────
    t = threading.Thread(target=worker, daemon=True)
    t.start()

    # Install a SIGINT handler that sets stop_event instead of raising KeyboardInterrupt
    original_sigint = signal.getsignal(signal.SIGINT)
    def _abort(sig, frame):
        stop_event.set()
    signal.signal(signal.SIGINT, _abort)

    try:
        d.gauge_start(
            "Starting up — press Ctrl+C to abort\n\nConnecting...",
            width=70, height=20,
            title=f"Cluster sync — {app_name}",
            percent=0,
        )
        while not state["done"]:
            try:
                d.gauge_update(state["percent"], state["text"], update_text=True)
            except Exception:
                pass  # gauge may error if terminal resizes; keep going
            time.sleep(0.5)

        # Final update
        try:
            d.gauge_update(100 if result_box[0] else state["percent"],
                           state["text"], update_text=True)
            time.sleep(0.3)
        except Exception:
            pass
    finally:
        try:
            d.gauge_stop()
        except Exception:
            pass
        signal.signal(signal.SIGINT, original_sigint)
        stop_event.set()
        t.join(timeout=3)

    if state["aborted"]:
        _msgbox(d, "Sync aborted.\n\nThe secrets are written but the cluster\n"
                "may not be fully started. Check pod status\n"
                "with: kubectl get pods -n " + namespace,
                title="Aborted", width=62, height=14)
        return False

    return result_box[0]


def _kubectl_context() -> str:
    """Return the current kubectl context name."""
    result = subprocess.run(
        ["kubectl", "config", "current-context"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def section_secrets(d, namespace: str, release: str, dry_run: bool):
    fields = make_fields(release)
    load_existing_secrets(fields, namespace, d)

    result = _run_secrets_menu(d, fields)
    if not result:
        return

    groups = group_fields(fields)
    if result == "export_write":
        csv_path = f"metranova-secrets-{namespace}.csv"
        export_csv(fields, csv_path)
        _msgbox(d, f"Exported to {csv_path}\nStore in password manager, then delete.",
                title="Exported")

    apply_secrets(groups, namespace, release, dry_run, fields)

    if dry_run:
        _msgbox(d, "Dry run complete — no secrets written.", title="Done")
        return

    # Trigger ArgoCD sync and watch pods come up
    ok = argocd_sync_and_wait(d, namespace, app_name=release)
    if ok:
        _msgbox(d,
            "All pods are ready.\n\n"
            "Use step 1 (Connect) to open port-forwards,\n"
            "then proceed to Organizations and Grants.",
            title="Cluster ready", width=62, height=12)
    else:
        _msgbox(d,
            "Timed out waiting for pods.\n\n"
            "The cluster may still be starting. Check:\n"
            "  kubectl get pods -n " + namespace + "\n\n"
            "Once all pods are 1/1 Running, use step 1\n"
            "to connect.",
            title="Timeout", width=64, height=14)


# ── TUI: connectivity layer ────────────────────────────────────────────────────

class WizardConnections:
    """Holds live port-forwards and authenticated clients."""

    def __init__(self):
        self.ch_pf: Optional[PortForward] = None
        self.kc_pf: Optional[PortForward] = None
        self.ch: Optional[ClickHouseClient] = None
        self.kc: Optional[KeycloakClient] = None

    @property
    def connected(self) -> bool:
        return self.ch is not None and self.kc is not None

    def stop(self):
        if self.ch_pf:
            self.ch_pf.stop()
        if self.kc_pf:
            self.kc_pf.stop()
        self.ch = self.kc = self.ch_pf = self.kc_pf = None


def section_connect(d, conn: WizardConnections, namespace: str, release: str):
    """Open port-forwards and authenticate. Shows progress, reports errors."""

    conn.stop()  # clean up any previous attempt

    d.infobox("Connecting to cluster...\n\nOpening ClickHouse port-forward...",
              width=56, height=8, title="Connecting")

    # ClickHouse
    ch_svc = f"svc/{release}-clickhouse"
    ch_pf = PortForward(namespace, ch_svc, remote_port=9440, local_port=PF_CH_LOCAL_PORT)
    if not ch_pf.start(timeout=12):
        ch_pf.stop()
        _error(d, f"Could not reach ClickHouse.\n\nIs the cluster running?\n"
               f"Service: {ch_svc}\nNamespace: {namespace}")
        return

    d.infobox("Opening Keycloak port-forward...", width=56, height=8, title="Connecting")

    # Keycloak (management port via service)
    kc_svc = f"svc/{release}-keycloak"
    kc_pf = PortForward(namespace, kc_svc, remote_port=9000, local_port=PF_KC_LOCAL_PORT)
    if not kc_pf.start(timeout=15):
        kc_pf.stop()
        ch_pf.stop()
        _error(d, f"Could not reach Keycloak.\n\nIs the cluster running?\n"
               f"Service: {kc_svc}\nNamespace: {namespace}")
        return

    d.infobox("Authenticating...", width=56, height=8, title="Connecting")

    # Load credentials from cluster secrets
    ch_pass = load_ch_admin_password(namespace)
    kc_pass = load_keycloak_admin_password(release, namespace)

    if not ch_pass:
        ch_pf.stop(); kc_pf.stop()
        _error(d, "Could not read ClickHouse admin password from cluster.\n"
               "Run step 0 (Secrets) first.")
        return
    if not kc_pass:
        ch_pf.stop(); kc_pf.stop()
        _error(d, "Could not read Keycloak admin password from cluster.\n"
               "Run step 0 (Secrets) first.")
        return

    ch_client = ClickHouseClient(port=PF_CH_LOCAL_PORT, password=ch_pass)
    if not ch_client.ping():
        ch_pf.stop(); kc_pf.stop()
        _error(d, "ClickHouse port-forward is up but authentication failed.\n"
               "Check the admin password in the cluster secret.")
        return

    kc_client = KeycloakClient(
        base_url=f"http://127.0.0.1:{PF_KC_LOCAL_PORT}",
        admin_password=kc_pass,
    )
    if not kc_client.ping():
        ch_pf.stop(); kc_pf.stop()
        _error(d, "Keycloak port-forward is up but authentication failed.\n"
               "Check the admin password in the cluster secret.")
        return

    conn.ch_pf = ch_pf
    conn.kc_pf = kc_pf
    conn.ch    = ch_client
    conn.kc    = kc_client

    _msgbox(d, "Connected to ClickHouse and Keycloak.\n\nYou can now use Organizations, Rules, and Grants.",
            title="Connected", width=56, height=10)


# ── TUI: section 1 — organizations ────────────────────────────────────────────

def _list_orgs(ch: ClickHouseClient) -> list[dict]:
    out = ch.query(
        "SELECT id, name, slug, is_custodial FROM metranova_authz.organizations FINAL "
        "ORDER BY name FORMAT JSONEachRow"
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def section_orgs(d, conn: WizardConnections):
    while True:
        orgs = _list_orgs(conn.ch)
        choices = []
        for o in orgs:
            flag = " [custodial]" if o["is_custodial"] else ""
            choices.append((o["id"], f"{o['name']}  ({o['slug']}){flag}"))
        choices.append(("__new__", "+ Add organization"))

        code, tag = d.menu(
            "Organizations define the access control namespaces for data.\n"
            "Each installation has exactly one custodial organization.",
            choices=choices, title="Organizations",
            width=72, height=22, menu_height=14,
            ok_label="Edit", cancel_label="Back",
            extra_button=True, extra_label="Delete",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if tag == "__new__":
            _org_create(d, conn)
            continue

        if code == "extra":
            org = next(o for o in orgs if o["id"] == tag)
            if org["is_custodial"]:
                _msgbox(d, "Cannot delete the custodial organization.", title="Error")
                continue
            if _confirm(d, f"Delete organization '{org['name']}'?\n\nThis does NOT revoke grants — do that first.",
                        title="Confirm delete"):
                try:
                    conn.ch.multiquery(
                        f"ALTER TABLE metranova_authz.organizations DELETE WHERE id = '{tag}';"
                    )
                except RuntimeError as e:
                    _error(d, f"Delete failed:\n{e}")
            continue

        # Edit
        org = next(o for o in orgs if o["id"] == tag)
        _org_edit(d, conn, org)


def _org_create(d, conn: WizardConnections):
    c, name = d.inputbox("Organization name (human-readable):", title="New Organization",
                         width=60, height=10)
    if c != d.OK or not name.strip():
        return
    name = name.strip()

    c, slug = d.inputbox("Slug (lowercase, used in group names, e.g. esnet):",
                         title="New Organization", width=60, height=10,
                         init=name.lower().replace(" ", "-"))
    if c != d.OK or not slug.strip():
        return
    slug = slug.strip().lower()

    is_custodial = _confirm(d, f"Is '{name}' the custodial organization for this installation?\n\n"
                            "(Only one org can be custodial.)", title="Custodial?")

    try:
        conn.ch.multiquery(
            f"INSERT INTO metranova_authz.organizations (name, slug, is_custodial) "
            f"VALUES ('{name}', '{slug}', {'true' if is_custodial else 'false'});"
        )
        _msgbox(d, f"Created organization '{name}' (slug: {slug}).", title="Created")
    except RuntimeError as e:
        _error(d, f"Failed to create organization:\n{e}")


def _org_edit(d, conn: WizardConnections, org: dict):
    c, name = d.inputbox("Organization name:", title=f"Edit: {org['name']}",
                         width=60, height=10, init=org["name"])
    if c != d.OK or not name.strip():
        return
    try:
        conn.ch.multiquery(
            f"ALTER TABLE metranova_authz.organizations UPDATE name = '{name.strip()}', "
            f"updated_at = now64() WHERE id = '{org['id']}';"
        )
        _msgbox(d, f"Updated.", title="Saved")
    except RuntimeError as e:
        _error(d, f"Update failed:\n{e}")


# ── TUI: section 2 — rules ────────────────────────────────────────────────────

def _list_rules(ch: ClickHouseClient) -> list[dict]:
    out = ch.query(
        "SELECT r.id, r.policy_originator_pattern, r.policy_scope_pattern, "
        "r.assigned_tlp, r.priority, r.description, o.name AS org_name, o.slug "
        "FROM metranova_authz.rules r FINAL "
        "JOIN metranova_authz.organizations o ON r.organization_id = o.id "
        "ORDER BY r.priority DESC, r.id FORMAT JSONEachRow"
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def section_rules(d, conn: WizardConnections):
    while True:
        rules = _list_rules(conn.ch)
        choices = []
        for r in rules:
            tlp_str = f" → TLP:{r['assigned_tlp']}" if r["assigned_tlp"] else ""
            choices.append((r["id"],
                f"[{r['priority']:4d}] {r['policy_originator_pattern']} / "
                f"{r['policy_scope_pattern']} → {r['org_name']}{tlp_str}"))
        choices.append(("__new__", "+ Add rule"))

        code, tag = d.menu(
            "Classification rules tag data rows with organizations at ingest.\n"
            "All matching rules fire (org-tagging is additive).\n"
            "For TLP overrides, the highest-priority rule wins.",
            choices=choices, title="Classification Rules",
            width=78, height=22, menu_height=12,
            ok_label="Edit", cancel_label="Back",
            extra_button=True, extra_label="Delete",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if tag == "__new__":
            _rule_create(d, conn)
            continue

        if code == "extra":
            if _confirm(d, "Delete this rule?\n\nRows already ingested are not re-tagged.",
                        title="Confirm delete"):
                try:
                    conn.ch.multiquery(
                        f"ALTER TABLE metranova_authz.rules DELETE WHERE id = '{tag}';"
                    )
                except RuntimeError as e:
                    _error(d, f"Delete failed:\n{e}")
            continue

        rule = next(r for r in rules if r["id"] == tag)
        _rule_edit(d, conn, rule)


def _pick_org(d, conn: WizardConnections) -> Optional[dict]:
    orgs = _list_orgs(conn.ch)
    if not orgs:
        _error(d, "No organizations defined. Create one first.")
        return None
    choices = [(o["id"], f"{o['name']}  ({o['slug']})") for o in orgs]
    code, tag = d.menu("Select organization:", choices=choices,
                       title="Organization", width=60, height=18, menu_height=10,
                       ok_label="Select", cancel_label="Cancel")
    if code != d.OK:
        return None
    return next(o for o in orgs if o["id"] == tag)


def _rule_create(d, conn: WizardConnections):
    org = _pick_org(d, conn)
    if not org:
        return

    c, orig = d.inputbox(
        "policy_originator pattern (glob, e.g. esnet-* or exact value):",
        title="New Rule", width=68, height=10)
    if c != d.OK or not orig.strip():
        return

    c, scope = d.inputbox(
        "policy_scope pattern (glob, e.g. * for any scope):",
        title="New Rule", width=68, height=10, init="*")
    if c != d.OK:
        return

    c, prio = d.inputbox("Priority (higher wins for TLP override, default 0):",
                         title="New Rule", width=60, height=10, init="0")
    if c != d.OK:
        return
    try:
        prio_int = int(prio.strip())
    except ValueError:
        _error(d, "Priority must be an integer.")
        return

    # TLP override is optional
    tlp_choices = [("none", "No TLP override (org-tag only)")] + \
                  [(lvl, f"Override to {lvl}") for lvl in TLP_LEVELS]
    code, tlp_tag = d.menu("TLP override effect (optional):",
                            choices=tlp_choices, title="TLP Override",
                            width=60, height=16, menu_height=8,
                            ok_label="Select", cancel_label="Cancel")
    if code != d.OK:
        return
    assigned_tlp = "NULL" if tlp_tag == "none" else f"'{tlp_tag}'"

    c, desc = d.inputbox("Description (optional):", title="New Rule", width=68, height=10)
    if c != d.OK:
        return

    try:
        conn.ch.multiquery(
            f"INSERT INTO metranova_authz.rules "
            f"(organization_id, policy_originator_pattern, policy_scope_pattern, "
            f"assigned_tlp, priority, description) VALUES "
            f"('{org['id']}', '{orig.strip()}', '{scope.strip()}', "
            f"{assigned_tlp}, {prio_int}, '{desc.strip()}');"
        )
        _msgbox(d, f"Rule created.\n\nThe pipeline will pick it up at next ingest.",
                title="Created", width=60, height=10)
    except RuntimeError as e:
        _error(d, f"Failed to create rule:\n{e}")


def _rule_edit(d, conn: WizardConnections, rule: dict):
    c, desc = d.inputbox("Description:", title=f"Edit rule", width=68, height=10,
                         init=rule.get("description", ""))
    if c != d.OK:
        return
    c, prio = d.inputbox("Priority:", title="Edit rule", width=60, height=10,
                         init=str(rule.get("priority", 0)))
    if c != d.OK:
        return
    try:
        prio_int = int(prio.strip())
        conn.ch.multiquery(
            f"ALTER TABLE metranova_authz.rules UPDATE "
            f"description = '{desc.strip()}', priority = {prio_int} "
            f"WHERE id = '{rule['id']}';"
        )
        _msgbox(d, "Updated.", title="Saved")
    except (ValueError, RuntimeError) as e:
        _error(d, f"Update failed:\n{e}")


# ── TUI: section 3 — grants ───────────────────────────────────────────────────

def _group_name(org_slug: str, tlp_level: str, permission: str) -> str:
    return f"authz-tlp-{org_slug}-{tlp_level.split(':')[1]}-{permission}"


def _list_grants(ch: ClickHouseClient) -> list[dict]:
    out = ch.query(
        "SELECT g.id, g.group_name, g.max_tlp_level, g.permission, g.granted_by, "
        "o.name AS org_name, o.slug, g.revoked_at "
        "FROM metranova_authz.grants g FINAL "
        "JOIN metranova_authz.organizations o ON g.organization_id = o.id "
        "WHERE isNull(g.revoked_at) "
        "ORDER BY o.name, g.max_tlp_level, g.permission FORMAT JSONEachRow"
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def _ensure_ch_role(ch: ClickHouseClient, group_name: str):
    """CREATE ROLE IF NOT EXISTS for the group so LDAP mapping has a target."""
    ch.multiquery(f"CREATE ROLE IF NOT EXISTS `{group_name}`;")


def section_grants(d, conn: WizardConnections):
    while True:
        grants = _list_grants(conn.ch)
        choices = []
        for g in grants:
            perm_icon = "R" if g["permission"] == "read" else "W"
            choices.append((g["id"],
                f"[{perm_icon}] {g['org_name']}  {g['max_tlp_level']}  "
                f"→ {g['group_name']}"))
        choices.append(("__new__", "+ Add grant"))

        code, tag = d.menu(
            "Grants link Keycloak groups to org+TLP+permission.\n"
            "[R]=read  [W]=write  (independent — write does NOT imply read)\n\n"
            "Creating a grant also creates the Keycloak group and CH role.",
            choices=choices, title="Access Grants",
            width=78, height=22, menu_height=12,
            ok_label="View", cancel_label="Back",
            extra_button=True, extra_label="Revoke",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if tag == "__new__":
            _grant_create(d, conn)
            continue

        if code == "extra":
            grant = next(g for g in grants if g["id"] == tag)
            if _confirm(d,
                f"Revoke grant for group '{grant['group_name']}'?\n\n"
                f"The CH role and Keycloak group will be deleted.\n"
                f"Row policy takes effect within 30 seconds.",
                title="Confirm revoke"):
                _grant_revoke(d, conn, grant)
            continue

        grant = next(g for g in grants if g["id"] == tag)
        _msgbox(d,
            f"Group:       {grant['group_name']}\n"
            f"Org:         {grant['org_name']} ({grant['slug']})\n"
            f"Permission:  {grant['permission']}\n"
            f"Max TLP:     {grant['max_tlp_level']}\n"
            f"Granted by:  {grant['granted_by']}",
            title="Grant details", width=66, height=14)


def _grant_create(d, conn: WizardConnections):
    org = _pick_org(d, conn)
    if not org:
        return

    tlp_choices = [(lvl, lvl) for lvl in TLP_LEVELS]
    code, tlp = d.menu("Maximum TLP level for this grant:",
                       choices=tlp_choices, title="TLP Level",
                       width=56, height=14, menu_height=6,
                       ok_label="Select", cancel_label="Cancel")
    if code != d.OK:
        return

    perm_choices = [("read", "read  — SELECT only"), ("write", "write — INSERT/UPDATE only")]
    code, perm = d.menu("Permission type (read and write are independent grants):",
                        choices=perm_choices, title="Permission",
                        width=62, height=12, menu_height=4,
                        ok_label="Select", cancel_label="Cancel")
    if code != d.OK:
        return

    group = _group_name(org["slug"], tlp, perm)

    c, granted_by = d.inputbox("Granted by (your name/username for audit log):",
                               title="New Grant", width=60, height=10)
    if c != d.OK or not granted_by.strip():
        return

    # Preview and confirm
    if not _confirm(d,
        f"Create grant:\n\n"
        f"  Keycloak group:  {group}\n"
        f"  Organization:    {org['name']} ({org['slug']})\n"
        f"  Permission:      {perm}\n"
        f"  Max TLP:         {tlp}\n\n"
        f"This will:\n"
        f"  1. Create Keycloak group '{group}'\n"
        f"  2. CREATE ROLE in ClickHouse\n"
        f"  3. INSERT into metranova_authz.grants",
        title="Confirm grant", width=68, height=22):
        return

    errors = []

    # 1. Keycloak group
    try:
        conn.kc.create_group(group)
    except Exception as e:
        errors.append(f"Keycloak group: {e}")

    # 2. ClickHouse role (LDAP mapping target)
    try:
        _ensure_ch_role(conn.ch, group)
    except RuntimeError as e:
        errors.append(f"CH role: {e}")

    # 3. ClickHouse grant row
    try:
        conn.ch.multiquery(
            f"INSERT INTO metranova_authz.grants "
            f"(group_name, organization_id, max_tlp_level, permission, granted_by) "
            f"VALUES ('{group}', '{org['id']}', '{tlp}', '{perm}', '{granted_by.strip()}');"
        )
    except RuntimeError as e:
        errors.append(f"CH grant row: {e}")

    if errors:
        _error(d, "Partial failure creating grant:\n\n" + "\n".join(errors))
    else:
        _msgbox(d,
            f"Grant created.\n\n"
            f"Keycloak group '{group}' is ready for mapper configuration.\n"
            f"Row policy dict refreshes within 30 seconds.",
            title="Grant created", width=68, height=14)


def _grant_revoke(d, conn: WizardConnections, grant: dict):
    errors = []
    group = grant["group_name"]

    # 1. Set revoked_at in CH
    try:
        conn.ch.multiquery(
            f"ALTER TABLE metranova_authz.grants UPDATE revoked_at = now64() "
            f"WHERE id = '{grant['id']}';"
        )
    except RuntimeError as e:
        errors.append(f"CH revoke: {e}")

    # 2. Delete Keycloak group
    try:
        kc_groups = conn.kc.list_groups()
        match = next((g for g in kc_groups if g["name"] == group), None)
        if match:
            conn.kc.delete_group(match["id"])
    except Exception as e:
        errors.append(f"Keycloak group: {e}")

    # 3. Drop CH role
    try:
        conn.ch.multiquery(f"DROP ROLE IF EXISTS `{group}`;")
    except RuntimeError as e:
        errors.append(f"CH role: {e}")

    if errors:
        _error(d, "Partial failure revoking grant:\n\n" + "\n".join(errors))
    else:
        _msgbox(d, f"Grant revoked.\nDict refreshes within 30 seconds.",
                title="Revoked", width=56, height=10)


# ── TUI: section 4 — audit ────────────────────────────────────────────────────

def section_audit(d, conn: WizardConnections):
    while True:
        code, tag = d.menu(
            "View authorization audit log and compliance reports.",
            choices=[
                ("recent",  "Recent events (last 50)"),
                ("grants",  "Current grant report"),
                ("orgs",    "Organizations and rules summary"),
            ],
            title="Audit & Reports", width=60, height=16, menu_height=6,
            ok_label="View", cancel_label="Back",
        )
        if code in (d.CANCEL, d.ESC):
            return

        if tag == "recent":
            try:
                out = conn.ch.query(
                    "SELECT timestamp, event_type, actor, organization, details "
                    "FROM metranova_authz.audit_log "
                    "ORDER BY timestamp DESC LIMIT 50 FORMAT Vertical"
                )
                d.scrollbox(out or "(no audit events yet)", title="Recent Events",
                            width=78, height=24)
            except RuntimeError as e:
                _error(d, f"Query failed:\n{e}")

        elif tag == "grants":
            try:
                out = conn.ch.query(
                    "SELECT o.name AS org, g.permission, g.max_tlp_level, g.group_name "
                    "FROM metranova_authz.grants g FINAL "
                    "JOIN metranova_authz.organizations o ON g.organization_id = o.id "
                    "WHERE isNull(g.revoked_at) "
                    "ORDER BY o.name, g.permission, g.max_tlp_level FORMAT PrettyCompact"
                )
                d.scrollbox(out or "(no active grants)", title="Active Grants",
                            width=78, height=24)
            except RuntimeError as e:
                _error(d, f"Query failed:\n{e}")

        elif tag == "orgs":
            try:
                orgs_out = conn.ch.query(
                    "SELECT name, slug, is_custodial, "
                    "(SELECT count() FROM metranova_authz.rules r FINAL "
                    " WHERE r.organization_id = o.id) AS rule_count "
                    "FROM metranova_authz.organizations o FINAL "
                    "ORDER BY name FORMAT PrettyCompact"
                )
                d.scrollbox(orgs_out or "(no organizations)", title="Organizations",
                            width=78, height=24)
            except RuntimeError as e:
                _error(d, f"Query failed:\n{e}")


# ── Main TUI loop ──────────────────────────────────────────────────────────────

def run_wizard(namespace: str, release: str, dry_run: bool):
    d = _make_dialog(namespace)
    conn = WizardConnections()

    # Clean up port-forwards on exit
    def _cleanup(*_):
        conn.stop()
    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT,  _cleanup)

    try:
        while True:
            status = "connected" if conn.connected else "not connected"
            locked = not conn.connected

            choices = [
                ("0", "Secrets          — generate and write K8s secrets"),
                ("1", f"Connect          — open port-forwards  [{status}]"),
                ("2", f"Organizations    — manage orgs          {'[connect first]' if locked else ''}"),
                ("3", f"Rules            — classification rules  {'[connect first]' if locked else ''}"),
                ("4", f"Grants           — access grants         {'[connect first]' if locked else ''}"),
                ("5", f"Audit            — view audit log        {'[connect first]' if locked else ''}"),
            ]

            code, tag = d.menu(
                "MetrANOVA Authorization Wizard\n\n"
                "Start with step 0 (Secrets) then wait for the cluster to\n"
                "come up before using steps 2–5.",
                choices=choices,
                title="Main Menu",
                width=72, height=22, menu_height=10,
                ok_label="Open",
                cancel_label="Exit",
            )

            if code in (d.CANCEL, d.ESC):
                break

            if tag == "0":
                section_secrets(d, namespace, release, dry_run)
            elif tag == "1":
                section_connect(d, conn, namespace, release)
            elif tag == "2":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_orgs(d, conn)
            elif tag == "3":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_rules(d, conn)
            elif tag == "4":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_grants(d, conn)
            elif tag == "5":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_audit(d, conn)
    finally:
        conn.stop()


# ── Headless / non-interactive mode ───────────────────────────────────────────

def run_headless(namespace: str, release: str, dry_run: bool, export_csv_path: str = None):
    fields = make_fields(release)
    for f in fields:
        f.value = f.generate()
        f.confirmed = True
    groups = group_fields(fields)
    if export_csv_path:
        export_csv(fields, export_csv_path)
    apply_secrets(groups, namespace, release, dry_run, fields)
    print("\nDone.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MetrANOVA auth wizard")
    parser.add_argument("--namespace",  default=os.environ.get("NAMESPACE",    "metranova"))
    parser.add_argument("--release",    default=os.environ.get("AUTH_RELEASE", "metranova-auth"))
    parser.add_argument("--export-csv", metavar="PATH")
    parser.add_argument("--dry-run",    action="store_true")
    parser.add_argument("--no-tui",     action="store_true", help="Generate secrets non-interactively")
    args = parser.parse_args()

    if args.no_tui:
        run_headless(args.namespace, args.release, args.dry_run, args.export_csv)
    else:
        run_wizard(args.namespace, args.release, args.dry_run)


if __name__ == "__main__":
    main()
