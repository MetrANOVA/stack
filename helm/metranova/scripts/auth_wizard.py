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
    cluster_value: str = ""  # decoded value from cluster (set when sentinel is applied)


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
        # ── Keycloak ──────────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-secrets/KEYCLOAK_ADMIN_PASSWORD",
            label="Keycloak admin password",
            description="Password for the Keycloak admin account.",
            group="Keycloak",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/CROSS_INSTANCE_CLIENT_SECRET",
            label="Cross-instance OIDC client secret",
            description="Client secret for federated cross-instance queries.",
            group="Keycloak",
            generate=gen_token,
        ),
        # ── OpenLDAP ──────────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-secrets/LDAP_ADMIN_PASSWORD",
            label="LDAP admin password",
            description="Password for cn=admin in OpenLDAP. Used by all services that bind to LDAP.",
            group="LDAP",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/LDAP_CONFIG_PASSWORD",
            label="LDAP config password",
            description="Password for the OpenLDAP config DN (cn=config).",
            group="LDAP",
            generate=gen_password,
        ),
        # ── Token store ───────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-secrets/TOKEN_STORE_ENCRYPTION_KEY",
            label="Token store encryption key",
            description="Fernet encryption key for the token-store service.",
            group="Token Store",
            generate=gen_fernet,
        ),
        # ── Grafana ───────────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-secrets/GRAFANA_ADMIN_PASSWORD",
            label="Grafana admin password",
            description="Password for the Grafana admin UI account.",
            group="Grafana",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_CLICKHOUSE_PASSWORD",
            label="Grafana ClickHouse password",
            description="Password the Grafana ClickHouse datasource uses to connect.",
            group="Grafana",
            generate=gen_password,
        ),
        # ── Envoy ─────────────────────────────────────────────────────────────
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
        # ── ClickHouse (separate secret) ──────────────────────────────────────
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
            description="Password for the Grafana read-only ClickHouse user.",
            group="ClickHouse",
            generate=gen_password,
        ),
        # ── TLS ───────────────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-tls/combined",
            label="TLS certificate + key",
            description="Self-signed TLS certificate for Envoy. Replace with a real cert in production.",
            group="TLS",
            generate=gen_selfsigned_tls,
            sensitive=False,
        ),
    ]


# ── Preflight dependency checks ────────────────────────────────────────────────

REQUIRED_BINARIES = [
    ("kubectl", "install kubectl: https://kubernetes.io/docs/tasks/tools/"),
    ("openssl",  "install openssl (e.g. brew install openssl)"),
]

# ClickHouse ships either as a standalone 'clickhouse-client' binary (older) or
# as 'clickhouse client' subcommand (modern unified binary). Accept either.
def _clickhouse_client_available() -> bool:
    for cmd in (["which", "clickhouse-client"], ["clickhouse", "client", "--version"]):
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode == 0:
            return True
    return False

REQUIRED_PYTHON_PACKAGES = [
    ("dialog", "pip install pythondialog"),
    ("yaml",   "pip install pyyaml"),
]


def preflight_check(skip_tui: bool = False) -> list[str]:
    """Return a list of human-readable missing-dependency messages.

    Returns an empty list if all dependencies are satisfied.
    When skip_tui is True, the 'dialog' package is not required.
    """
    missing = []

    for binary, hint in REQUIRED_BINARIES:
        result = subprocess.run(["which", binary], capture_output=True)
        if result.returncode != 0:
            missing.append(f"Missing binary '{binary}': {hint}")

    if not _clickhouse_client_available():
        missing.append(
            "Missing ClickHouse client: install via https://clickhouse.com/docs/en/install"
            " ('clickhouse' or 'clickhouse-client' must be on PATH)"
        )

    packages = REQUIRED_PYTHON_PACKAGES if not skip_tui else [
        p for p in REQUIRED_PYTHON_PACKAGES if p[0] != "dialog"
    ]
    for module, hint in packages:
        try:
            __import__(module)
        except ImportError:
            missing.append(f"Missing Python package '{module}': {hint}")

    return missing


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
        # Support both 'clickhouse-client' (legacy) and 'clickhouse client' (modern)
        import shutil
        _binary = ["clickhouse-client"] if shutil.which("clickhouse-client") \
                  else ["clickhouse", "client"]
        self._base_cmd = _binary + [
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

_ALREADY_SET_SENTINEL = "(already set in cluster)"


def group_fields(fields: list[SecretField], include_cluster: bool = False) -> dict:
    """Group confirmed, writable fields by secret name.

    Excludes TLS combined fields (handled separately).
    Sentinel fields (already in cluster) are normally excluded; pass
    include_cluster=True to include them using their decoded cluster value
    (used when writing to files so the file reflects actual cluster state).
    """
    groups: dict[str, dict] = {}
    for f in fields:
        if f.value and "---KEY---" in f.value:
            continue
        if f.value == _ALREADY_SET_SENTINEL:
            if include_cluster and f.cluster_value:
                secret_name, key = f.key.split("/", 1)
                groups.setdefault(secret_name, {})[key] = f.cluster_value
            continue
        secret_name, key = f.key.split("/", 1)
        groups.setdefault(secret_name, {})[key] = f.value
    return groups


def _sds_yaml(secret_name: str, inline_string: str) -> str:
    return (
        'resources:\n'
        '- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n'
        f'  name: {secret_name}\n'
        '  generic_secret:\n'
        '    secret:\n'
        f'      inline_string: {inline_string}\n'
    )


def _secret_manifest_yaml(secret_name: str, namespace: str, data: dict[str, str]) -> str:
    import yaml as _yaml
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": secret_name, "namespace": namespace},
        "stringData": data,
    }
    return _yaml.dump(manifest, default_flow_style=False, allow_unicode=True)


def _write_secret_to_file(secret_name: str, namespace: str,
                           data: dict[str, str], secrets_dir: str):
    """Write a K8s Secret manifest to secrets/<name>.yaml."""
    os.makedirs(secrets_dir, exist_ok=True)
    path = os.path.join(secrets_dir, f"{secret_name}.yaml")
    with open(path, "w") as f:
        f.write(_secret_manifest_yaml(secret_name, namespace, data))
    print(f"  Written: {path}")


def _apply_secret_to_cluster(secret_name: str, namespace: str,
                              data: dict[str, str], dry_run: bool):
    """Apply a K8s Secret directly to the cluster via kubectl."""
    manifest_yaml = _secret_manifest_yaml(secret_name, namespace, data)

    if dry_run:
        print(f"# Secret: {secret_name}\n{manifest_yaml}")
        return

    print(f"  Applying secret: {secret_name}")
    r = subprocess.run(
        ["kubectl", "apply", "-f", "-",
         "--context", _kubectl_context()],
        input=manifest_yaml, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  ERROR: {r.stderr}", file=sys.stderr)
    else:
        print(f"  OK: {secret_name}")


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))


def apply_secrets(groups: dict, namespace: str, release: str,
                  dry_run: bool, fields: list[SecretField] = None,
                  dest: str = "files"):
    """Write secrets. dest='files' writes to secrets/ dir; dest='cluster' applies via kubectl."""
    import importlib
    try:
        importlib.import_module("yaml")
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])

    secrets_dir = os.path.join(_repo_root(), "secrets")

    for secret_name, kv in groups.items():
        data = dict(kv)

        if secret_name == f"{release}-secrets":
            data["KEYCLOAK_ADMIN"] = "admin"
            oidc = data.get("ENVOY_OIDC_CLIENT_SECRET", "")
            hmac = data.get("ENVOY_HMAC_SECRET", "")
            data["token.yaml"] = _sds_yaml("token-secret", oidc)
            data["hmac.yaml"]  = _sds_yaml("hmac-secret",  hmac)

        if dest == "cluster":
            _apply_secret_to_cluster(secret_name, namespace, data, dry_run)
        else:
            _write_secret_to_file(secret_name, namespace, data, secrets_dir)

    tls_field = next((f for f in (fields or []) if f.value and "---KEY---" in f.value), None)
    if tls_field:
        cert, key = tls_field.value.split("---KEY---\n", 1)
        tls_secret = tls_field.key.split("/")[0]
        tls_data = {
            "tls.crt":    cert,
            "tls.key":    key,
            "server.crt": cert,
            "server.key": key,
        }
        if dest == "cluster":
            _apply_secret_to_cluster(tls_secret, namespace, tls_data, dry_run)
        else:
            _write_secret_to_file(tls_secret, namespace, tls_data, secrets_dir)


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
            f.value = _ALREADY_SET_SENTINEL
            f.sensitive = False
            f.confirmed = True
            if key in existing[secret_name]:
                try:
                    f.cluster_value = base64.b64decode(existing[secret_name][key]).decode()
                except Exception:
                    pass


# ── TUI: dialog helpers ────────────────────────────────────────────────────────

def _make_dialog(namespace: str):
    import dialog
    d = dialog.Dialog()
    d.set_background_title(f"MetrANOVA Auth Wizard  |  namespace: {namespace}")
    return d


def _msgbox(d, msg: str, title: str = "", width: int = 60, height: int = 10):
    d.msgbox(msg, title=title, width=width, height=height)


def _error(d, msg: str):
    d.scrollbox(msg, title="Error", width=80, height=24)


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


def _run_secrets_menu(d, fields: list[SecretField],
                       namespace: str = "", release: str = "", dry_run: bool = False):
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
            return

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

            c2, selected = d.checklist(
                f"Select all destinations for {len(group_fields(fields))} secrets:",
                title="Write secrets", width=68, height=14, list_height=4,
                choices=[
                    ("F", "Write to files  (secrets/ dir, gitignored)", True),
                    ("C", "Apply to cluster  (kubectl apply direct)", False),
                    ("X", "Export CSV", False),
                ],
            )
            if c2 in (d.CANCEL, d.ESC) or not selected:
                continue

            if "X" in selected:
                csv_path = f"metranova-secrets-{namespace}.csv"
                export_csv(fields, csv_path)
                _msgbox(d, f"Exported to {csv_path}\nStore in a password manager, then delete.",
                        title="CSV exported")

            if "F" in selected:
                groups = group_fields(fields, include_cluster=True)
                apply_secrets(groups, namespace, release, dry_run, fields, dest="files")
                if not dry_run:
                    secrets_dir = os.path.join(_repo_root(), "secrets")
                    _msgbox(d,
                        f"Secrets written to:\n  {secrets_dir}/\n\n"
                        "Apply with:\n"
                        f"  kubectl apply -f secrets/ -n {namespace}\n\n"
                        "Or point ArgoCD / Flux at the secrets/ directory.\n"
                        "Use step A to have the wizard sync ArgoCD.",
                        title="Files written", width=70, height=16)

            if "C" in selected:
                groups = group_fields(fields)
                apply_secrets(groups, namespace, release, dry_run, fields, dest="cluster")
                if not dry_run:
                    _msgbox(d,
                        "Secrets applied directly to the cluster.\n\n"
                        "Use step A if you are using ArgoCD, or deploy\n"
                        "with your preferred tool. Then use step 1 (Connect).",
                        title="Applied to cluster", width=66, height=12)

            continue  # loop back — user can write again or edit more

        _edit_secret_field(d, fields[int(tag)])


_PHASE_MSGS = [
    "Signalling ArgoCD...",
    "ArgoCD reconciling resources...",
    "Waiting for pods to be scheduled...",
    "Pods initializing...",
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

        update(5, "→ Triggering ArgoCD sync via kubectl patch...")
        r = subprocess.run(
            ["kubectl", "patch", "application", app_name,
             "-n", "argocd",
             "--type=merge",
             "-p", '{"operation":{"sync":{"syncStrategy":{"apply":{"force":false}}},"initiatedBy":{"username":"auth-wizard"}}}']
            + ctx_flag,
            capture_output=True, text=True,
        )
        argocd_note = "✓ ArgoCD sync triggered" if r.returncode == 0 \
                      else f"⚠ sync patch failed: {r.stderr.strip()[:80]}"
        log.append(argocd_note)

        # Step 2: poll pods
        start = time.time()
        prev_summary: list[str] = []

        while not stop_event.is_set():
            elapsed = time.time() - start
            if elapsed >= timeout:
                state["done"] = True
                return

            # All pods in namespace — shown in gauge for full visibility
            all_result = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "--no-headers",
                 "-o", "custom-columns="
                       "NAME:.metadata.name,"
                       "READY:.status.containerStatuses[0].ready,"
                       "STATUS:.status.phase,"
                       "RESTARTS:.status.containerStatuses[0].restartCount"] + ctx_flag,
                capture_output=True, text=True,
            )
            all_raw = [l for l in all_result.stdout.splitlines() if l.strip()]

            # App-specific pods — used for ready-check so each sync waits for its own pods
            app_result = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "--no-headers",
                 "-l", f"app.kubernetes.io/instance={app_name}",
                 "-o", "custom-columns="
                       "NAME:.metadata.name,"
                       "READY:.status.containerStatuses[0].ready,"
                       "STATUS:.status.phase,"
                       "RESTARTS:.status.containerStatuses[0].restartCount"] + ctx_flag,
                capture_output=True, text=True,
            )
            app_raw = [l for l in app_result.stdout.splitlines() if l.strip()]

            if not app_raw:
                phase = _PHASE_MSGS[1] if elapsed < 15 else _PHASE_MSGS[2]
                pct   = min(5 + int(elapsed / timeout * 20), 25)
                ns_summary = [_pod_line(l.split()) for l in all_raw]
                ns_block = ("\n".join(ns_summary) + "\n\n") if ns_summary else ""
                update(pct, f"{phase}\n\n{ns_block}{argocd_note}")
                time.sleep(2)
                continue

            app_ready = sum(1 for l in app_raw if len(l.split()) > 1 and l.split()[1].lower() == "true")
            app_total = len(app_raw)
            all_summary = [_pod_line(l.split()) for l in all_raw]

            # append new/changed lines to the running log
            for line in all_summary:
                if line not in prev_summary:
                    log.append(line.strip())
            prev_summary = all_summary

            frac  = app_ready / max(app_total, 1)
            pct   = min(10 + int(frac * 85), 99)
            if   frac == 0:   phase = _PHASE_MSGS[3]
            elif frac < 0.5:  phase = _PHASE_MSGS[4]
            elif frac < 1.0:  phase = _PHASE_MSGS[5]
            else:             phase = f"All {app_name} pods ready!"

            body = (
                f"{phase}  ({app_ready}/{app_total} for {app_name})  [{int(elapsed)}s]\n\n"
                + "\n".join(all_summary)
                + "\n\n"
                + "\n".join(log[-3:])
            )
            update(pct, body)

            if app_ready == app_total and app_total > 0:
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
    _run_secrets_menu(d, fields, namespace=namespace, release=release, dry_run=dry_run)


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


def section_connect(d, conn: WizardConnections, namespace: str, release: str,
                    ch_service: str = ""):
    """Open port-forwards and authenticate. Shows progress, reports errors."""

    conn.stop()  # clean up any previous attempt

    d.infobox("Connecting to cluster...\n\nOpening ClickHouse port-forward...",
              width=56, height=8, title="Connecting")

    # ClickHouse — try the provided service, then common defaults
    ch_candidates = []
    if ch_service:
        ch_candidates.append(ch_service)
    ch_candidates += [
        f"svc/{release}-clickhouse",
        "svc/clickhouse-ch-cluster",
        "svc/clickhouse",
    ]

    ch_pf = None
    ch_svc_used = None
    for candidate in ch_candidates:
        # Determine namespace: allow "ns/svc-name" syntax
        if "/" in candidate and not candidate.startswith("svc/"):
            ch_ns, ch_svc_name = candidate.split("/", 1)
            pf = PortForward(ch_ns, f"svc/{ch_svc_name}", remote_port=9440,
                             local_port=PF_CH_LOCAL_PORT)
        else:
            pf = PortForward(namespace, candidate, remote_port=9440,
                             local_port=PF_CH_LOCAL_PORT)
        if pf.start(timeout=6):
            ch_pf = pf
            ch_svc_used = candidate
            break
        pf.stop()

    if ch_pf is None:
        tried = "\n  ".join(ch_candidates)
        _error(d,
            f"Could not reach ClickHouse.\n\n"
            f"Tried:\n  {tried}\n\n"
            f"If ClickHouse is in a different namespace or has a\n"
            f"non-standard service name, restart the wizard with:\n"
            f"  --clickhouse-service <svc-name>\n"
            f"or  --clickhouse-service <namespace>/<svc-name>")
        return

    d.infobox("Opening Keycloak port-forward...", width=56, height=8, title="Connecting")

    # Keycloak HTTP port
    kc_svc = f"svc/{release}-keycloak"
    kc_pf = PortForward(namespace, kc_svc, remote_port=8080, local_port=PF_KC_LOCAL_PORT)
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

    ch_client = ClickHouseClient(port=PF_CH_LOCAL_PORT, user="admin", password=ch_pass)
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


# ── TUI: section 2 — init authz schema ────────────────────────────────────────

_AUTHZ_SCHEMA_SQL = """\
CREATE DATABASE IF NOT EXISTS metranova_authz;

CREATE TABLE IF NOT EXISTS metranova_authz.organizations
(
    id            UUID          DEFAULT generateUUIDv4(),
    name          String,
    slug          String,
    is_custodial  Bool          DEFAULT false,
    created_at    DateTime64(3) DEFAULT now64(),
    updated_at    DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS metranova_authz.rules
(
    id                        UUID          DEFAULT generateUUIDv4(),
    organization_id           UUID,
    policy_originator_pattern String,
    policy_scope_pattern      String,
    assigned_tlp              Nullable(String),
    priority                  Int32         DEFAULT 0,
    description               String        DEFAULT '',
    created_at                DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (priority, id);

CREATE TABLE IF NOT EXISTS metranova_authz.grants
(
    id              UUID     DEFAULT generateUUIDv4(),
    group_name      String,
    organization_id UUID,
    max_tlp_level   String,
    permission      String,
    granted_by      String,
    granted_at      DateTime64(3)          DEFAULT now64(),
    revoked_at      Nullable(DateTime64(3))
)
ENGINE = ReplacingMergeTree(granted_at)
ORDER BY (group_name, organization_id, permission);

CREATE TABLE IF NOT EXISTS metranova_authz.audit_log
(
    timestamp    DateTime64(3) DEFAULT now64(),
    event_type   String,
    actor        String,
    target_user  String        DEFAULT '',
    organization String        DEFAULT '',
    details      String        DEFAULT '',
    checksum     String        DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (timestamp, event_type, actor)
SETTINGS allow_nullable_key = 0;

CREATE ROLE IF NOT EXISTS `authz-admin`;
GRANT SELECT, INSERT, ALTER, CREATE, DROP ON metranova_authz.* TO `authz-admin`;

CREATE ROLE IF NOT EXISTS `authz-reader`;
GRANT SELECT ON metranova_authz.* TO `authz-reader`;

-- Roles referenced by row policies. clickhouse-admin is mapped from the LDAP
-- group by the auth stack; pipeline and grafana are service account roles.
-- Creating them here ensures the row policies can reference them regardless of
-- whether the LDAP sync or user XML configuration has run yet.
CREATE ROLE IF NOT EXISTS `clickhouse-admin`;
CREATE ROLE IF NOT EXISTS pipeline;
CREATE ROLE IF NOT EXISTS grafana;
"""

# ── Authz policy SQL (dictionaries + row policies) ─────────────────────────────
#
# The dictionary SOURCE uses the ClickHouse cluster-internal service on plain TCP
# (9000) so the ClickHouse server queries itself without TLS cert negotiation.
#
# Dictionaries are COMPLEX_KEY_HASHED keyed on (group_name, tlp_numeric).
# The source query is cumulative: tlp_numeric=2 (amber) includes all orgs where
# max_tlp >= 2 (amber or red), so a single dictGetOrDefault at the row's TLP level
# returns everything the user can see at that level.
#
# Exempt identities are kept minimal. `clickhouse-admin` is a ClickHouse role
# (LDAP-mapped), not a hardcoded username. Any user holding it can drop row
# policies anyway — TLP enforcement on them provides false security.

_DICT_SOURCE_READ_SQL = (
    "SELECT g.group_name, CAST(n.tlp_numeric AS Int8) AS tlp_numeric,"
    " groupArray(o.slug) AS org_slugs"
    " FROM (SELECT 0 AS tlp_numeric UNION ALL SELECT 1"
    "       UNION ALL SELECT 2 UNION ALL SELECT 3) AS n"
    " CROSS JOIN metranova_authz.grants AS g"
    " JOIN metranova_authz.organizations AS o ON g.organization_id = o.id"
    " WHERE g.permission = ''read'' AND isNull(g.revoked_at)"
    "   AND tlp_to_numeric(g.max_tlp_level) >= n.tlp_numeric"
    " GROUP BY g.group_name, n.tlp_numeric"
)

_DICT_SOURCE_WRITE_SQL = (
    "SELECT g.group_name, CAST(n.tlp_numeric AS Int8) AS tlp_numeric,"
    " groupArray(o.slug) AS org_slugs"
    " FROM (SELECT 0 AS tlp_numeric UNION ALL SELECT 1"
    "       UNION ALL SELECT 2 UNION ALL SELECT 3) AS n"
    " CROSS JOIN metranova_authz.grants AS g"
    " JOIN metranova_authz.organizations AS o ON g.organization_id = o.id"
    " WHERE g.permission = ''write'' AND isNull(g.revoked_at)"
    "   AND tlp_to_numeric(g.max_tlp_level) >= n.tlp_numeric"
    " GROUP BY g.group_name, n.tlp_numeric"
)


def _build_authz_policy_sql(ch_password: str,
                             ch_internal_host: str = "clickhouse-ch-cluster",
                             ch_internal_port: int = 9000,
                             ch_user: str = "admin") -> str:
    """Return the full policy DDL with dict SOURCE credentials embedded."""
    pw = ch_password.replace("'", "''")
    return f"""\
CREATE FUNCTION IF NOT EXISTS tlp_to_numeric AS (level) ->
    toInt8(transform(
        level,
        ['tlp:clear', 'tlp:green', 'tlp:amber', 'tlp:red'],
        [0, 1, 2, 3],
        -1
    ));

DROP DICTIONARY IF EXISTS metranova_authz.authz_group_read_orgs;
CREATE DICTIONARY metranova_authz.authz_group_read_orgs
(
    group_name  String,
    tlp_numeric Int8,
    org_slugs   Array(String)
)
PRIMARY KEY group_name, tlp_numeric
SOURCE(CLICKHOUSE(
    HOST '{ch_internal_host}'
    PORT {ch_internal_port}
    USER '{ch_user}'
    PASSWORD '{pw}'
    QUERY '{_DICT_SOURCE_READ_SQL}'
))
LIFETIME(MIN 30 MAX 60)
LAYOUT(COMPLEX_KEY_HASHED());

DROP DICTIONARY IF EXISTS metranova_authz.authz_group_write_orgs;
CREATE DICTIONARY metranova_authz.authz_group_write_orgs
(
    group_name  String,
    tlp_numeric Int8,
    org_slugs   Array(String)
)
PRIMARY KEY group_name, tlp_numeric
SOURCE(CLICKHOUSE(
    HOST '{ch_internal_host}'
    PORT {ch_internal_port}
    USER '{ch_user}'
    PASSWORD '{pw}'
    QUERY '{_DICT_SOURCE_WRITE_SQL}'
))
LIFETIME(MIN 30 MAX 60)
LAYOUT(COMPLEX_KEY_HASHED());

DROP ROW POLICY IF EXISTS authz_read_policy ON metranova.data_flow;
DROP ROW POLICY IF EXISTS authz_grafana_read_policy ON metranova.data_flow;
DROP ROW POLICY IF EXISTS authz_write_policy ON metranova.data_flow;

CREATE ROW POLICY authz_read_policy ON metranova.data_flow
FOR SELECT
USING hasAny(
    policy_organizations,
    arrayFlatten(arrayMap(
        r -> dictGetOrDefault(
                'metranova_authz.authz_group_read_orgs',
                'org_slugs',
                (r, tlp_to_numeric(policy_level)),
                cast([], 'Array(String)')
             ),
        currentRoles()
    ))
)
TO ALL EXCEPT `clickhouse-admin`, admin, pipeline, default, grafana;

CREATE ROW POLICY authz_grafana_read_policy ON metranova.data_flow
FOR SELECT
USING (policy_level = 'tlp:clear')
TO grafana;

-- NOTE: ClickHouse FOR INSERT row policies are not yet supported in upstream
-- ClickHouse (as of 25.x). Write enforcement is handled via GRANT privileges:
-- only users/roles with explicit INSERT grants on metranova.data_flow can write.
-- The authz_group_write_orgs dictionary is created above for future use when
-- ClickHouse adds FOR INSERT policy support.
DROP ROW POLICY IF EXISTS authz_write_policy ON metranova.data_flow;
"""


def _authz_policies_exist(ch: ClickHouseClient) -> bool:
    try:
        out = ch.query(
            "SELECT count() FROM system.row_policies"
            " WHERE short_name IN ('authz_read_policy', 'authz_grafana_read_policy')"
        )
        return int(out.strip()) >= 2
    except Exception:
        return False


def section_init_authz_policies(d, conn: WizardConnections,
                                 ch_internal_host: str = "clickhouse-ch-cluster",
                                 ch_internal_port: int = 9000) -> bool:
    """Create/replace dictionaries and row policies. Returns True on success."""
    if _authz_policies_exist(conn.ch):
        code = d.yesno(
            "Row policies already exist.\n\n"
            "Replace dictionaries and row policies?\n"
            "(DROP + CREATE — existing grants are preserved in the tables.)",
            title="Policies exist", width=66, height=10,
            yes_label="Replace", no_label="Skip",
        )
        if code != d.OK:
            return True  # skipped, not a failure

    d.infobox("Creating dictionaries and row policies...", width=58, height=6,
              title="Init policies")
    sql = _build_authz_policy_sql(
        ch_password=conn.ch.password,
        ch_internal_host=ch_internal_host,
        ch_internal_port=ch_internal_port,
        ch_user=conn.ch.user,
    )
    try:
        conn.ch.multiquery(sql)
    except Exception as exc:
        _error(d, f"Policy initialization failed:\n\n{exc}")
        return False

    _msgbox(d,
            "Dictionaries and row policies created.\n\n"
            "  authz_group_read_orgs       — SELECT dict\n"
            "  authz_group_write_orgs      — INSERT dict\n"
            "  authz_read_policy           — all non-exempt users\n"
            "  authz_grafana_read_policy   — grafana: tlp:clear only\n"
            "  authz_write_policy          — INSERT enforcement\n\n"
            "Dictionaries refresh every 30–60 s.",
            title="Policies ready", width=66, height=16)
    return True


def _authz_schema_exists(ch: ClickHouseClient) -> bool:
    try:
        out = ch.query(
            "SELECT count() FROM system.databases WHERE name = 'metranova_authz'"
        )
        return out.strip() == "1"
    except Exception:
        return False


def section_init_authz(d, conn: WizardConnections):
    if _authz_schema_exists(conn.ch):
        code = d.yesno(
            "The metranova_authz schema already exists.\n\n"
            "Re-run initialization? (All CREATE statements use IF NOT EXISTS — "
            "no data will be dropped.)",
            title="Schema exists", width=66, height=10,
            yes_label="Re-run", no_label="Skip",
        )
        if code != d.OK:
            return

    d.infobox("Initializing metranova_authz schema...", width=56, height=6,
              title="Init authz schema")
    try:
        conn.ch.multiquery(_AUTHZ_SCHEMA_SQL)
    except Exception as exc:
        _error(d, f"Schema initialization failed:\n\n{exc}")
        return

    # Best-effort: add policy_organizations to data_flow if that table exists.
    # Fails silently if metranova.data_flow hasn't been created yet.
    try:
        conn.ch.query(
            "ALTER TABLE metranova.data_flow"
            " ADD COLUMN IF NOT EXISTS policy_organizations Array(String) DEFAULT []"
        )
    except Exception:
        pass

    _msgbox(d,
            "metranova_authz schema initialized.\n\n"
            "Database, tables, and roles created (IF NOT EXISTS).\n"
            "Proceeding to row policy setup...",
            title="Schema ready", width=64, height=12)

    section_init_authz_policies(d, conn)


# ── TUI: section 3 — organizations ────────────────────────────────────────────

def _list_orgs(ch: ClickHouseClient) -> list[dict]:
    out = ch.query(
        "SELECT id, name, slug, is_custodial, created_at FROM metranova_authz.organizations FINAL "
        "ORDER BY name FORMAT JSONEachRow"
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def section_orgs(d, conn: WizardConnections):
    while True:
        orgs = _list_orgs(conn.ch)
        org_index = {str(i): o for i, o in enumerate(orgs)}
        choices = []
        for i, o in enumerate(orgs):
            flag = " [custodial]" if o["is_custodial"] else ""
            choices.append((str(i), f"{o['name']}  ({o['slug']}){flag}"))
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

        org = org_index[tag]

        if code == "extra":
            if org["is_custodial"]:
                _msgbox(d, "Cannot delete the custodial organization.", title="Error")
                continue
            if _confirm(d, f"Delete organization '{org['name']}'?\n\nThis does NOT revoke grants — do that first.",
                        title="Confirm delete"):
                try:
                    conn.ch.multiquery(
                        f"ALTER TABLE metranova_authz.organizations DELETE WHERE id = '{org['id']}';"
                    )
                except RuntimeError as e:
                    _error(d, f"Delete failed:\n{e}")
            continue

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

    already_has_custodial = any(o.get("is_custodial") for o in _list_orgs(conn.ch))
    custodial_code = d.yesno(
        f"Is '{name}' the custodial organization?\n\n"
        "The custodial org is the one that operates this cluster — usually the organization the person doing this installation works for.\n\n"
        "Only one organization can be custodial. Rows not matched by any classification rule are owned by the custodial org at tlp:red.",
        title="Custodial organization?", width=66, height=14,
        yes_label="Yes", no_label="No",
        defaultno=already_has_custodial,
    )
    is_custodial = custodial_code == d.OK

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
            f"INSERT INTO metranova_authz.organizations "
            f"(id, name, slug, is_custodial, created_at, updated_at) VALUES "
            f"('{org['id']}', '{name.strip()}', '{org['slug']}', "
            f"{'true' if org['is_custodial'] else 'false'}, "
            f"'{org['created_at']}', now64());"
        )
        _msgbox(d, "Updated.", title="Saved")
    except RuntimeError as e:
        _error(d, f"Update failed:\n{e}")


# ── TUI: section 4 — rules ────────────────────────────────────────────────────

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
        rule_index = {str(i): r for i, r in enumerate(rules)}
        choices = []
        for i, r in enumerate(rules):
            tlp_str = f" → {r['assigned_tlp']}" if r["assigned_tlp"] else ""
            desc = f"  {r['description']}" if r.get("description") else ""
            choices.append((str(i),
                f"[p{r['priority']}] {r['org_name']:<18} "
                f"{r['policy_originator_pattern']} / {r['policy_scope_pattern']}"
                f"{tlp_str}{desc}"))
        choices.append(("__new__", "+ Add rule"))

        code, tag = d.menu(
            "Classification rules tag data rows with organizations at ingest.\n"
            "All matching rules fire (org-tagging is additive).\n"
            "For TLP overrides, the highest-priority rule wins.",
            choices=choices, title="Classification Rules",
            width=90, height=22, menu_height=12,
            ok_label="Edit", cancel_label="Back",
            extra_button=True, extra_label="Delete",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if tag == "__new__":
            _rule_create(d, conn)
            continue

        rule = rule_index[tag]

        if code == "extra":
            if _confirm(d, "Delete this rule?\n\nRows already ingested are not re-tagged.",
                        title="Confirm delete"):
                try:
                    conn.ch.multiquery(
                        f"ALTER TABLE metranova_authz.rules DELETE WHERE id = '{rule['id']}';"
                    )
                except RuntimeError as e:
                    _error(d, f"Delete failed:\n{e}")
            continue

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


def _rule_so_far(org=None, orig=None, scope=None, prio=None, tlp=None) -> str:
    """One-line-per-field summary prepended to each rule creation dialog."""
    parts = []
    if org:           parts.append(f"  Org:      {org['name']} ({org['slug']})")
    if orig:          parts.append(f"  Source:   {orig}")
    if scope:         parts.append(f"  Scope:    {scope}")
    if prio is not None: parts.append(f"  Priority: {prio}")
    if tlp:           parts.append(f"  TLP:      {tlp}")
    if not parts:
        return ""
    return "Rule so far:\n" + "\n".join(parts) + "\n\n"


def _rule_match_count(ch: ClickHouseClient, orig: str, scope: str) -> Optional[int]:
    """COUNT rows in metranova.data_flow matching the given patterns. Returns None on error."""
    conditions = []
    if orig.strip() not in ("*", ""):
        conditions.append(f"policy_originator LIKE '{orig.strip().replace('*', '%')}'")
    if scope.strip() not in ("*", ""):
        s = scope.strip()
        if "*" in s:
            conditions.append(f"arrayExists(x -> x LIKE '{s.replace('*', '%')}', policy_scope)")
        else:
            conditions.append(f"has(policy_scope, '{s}')")
    where = " AND ".join(conditions) if conditions else "1=1"
    try:
        out = ch.query(f"SELECT formatReadableQuantity(count()) FROM metranova.data_flow WHERE {where}")
        return out.strip()
    except Exception:
        return None


def _rule_create(d, conn: WizardConnections):
    org = _pick_org(d, conn)
    if not org:
        return

    # Step 1: source/router pattern
    c, orig = d.inputbox(
        _rule_so_far(org=org) +
        "Router / collector pattern — which device does this data come from?\n"
        "For flow data use * (any source). For SNMP use a router name or glob (e.g. 'esnet-cr*').",
        title="New Rule (1/5)", width=72, height=14, init="*")
    if c != d.OK or not orig.strip():
        return
    orig = orig.strip()

    # Step 2: scope/AS pattern
    c, scope = d.inputbox(
        _rule_so_far(org=org, orig=orig) +
        "Scope pattern — the pipeline stamps each flow with AS numbers (e.g. 'as:293') and community names (e.g. 'comm:lhcone').\n\n"
        "Examples:\n"
        "  as:293       — flows involving ESnet (AS 293)\n"
        "  as:*         — flows involving any AS number\n"
        "  comm:lhcone  — flows tagged with the LHCONE BGP community\n"
        "  *            — match all flows regardless of scope",
        title="New Rule (2/5)", width=72, height=18, init="*")
    if c != d.OK:
        return
    scope = scope.strip()

    # Show match count preview
    d.infobox("Estimating row count...", width=48, height=5, title="Preview")
    count = _rule_match_count(conn.ch, orig, scope)
    if count is not None:
        _msgbox(d,
            _rule_so_far(org=org, orig=orig, scope=scope) +
            f"This rule would match approximately {count} rows in the current dataset.\n\n"
            "Press OK to continue setting priority, TLP override, and description.",
            title="Match preview", width=72, height=16)

    # Step 3: priority
    c, prio = d.inputbox(
        _rule_so_far(org=org, orig=orig, scope=scope) +
        "Priority — when multiple rules match a row, the highest priority wins.\n"
        "Use 0 for general rules, higher numbers for more specific overrides.",
        title="New Rule (3/5)", width=72, height=16, init="0")
    if c != d.OK:
        return
    try:
        prio_int = int(prio.strip())
    except ValueError:
        _error(d, "Priority must be an integer.")
        return

    # Step 4: TLP override
    tlp_choices = [("none", "No override — use the TLP level stamped on each row")] + \
                  [(lvl, f"Force all matched rows to {lvl}") for lvl in TLP_LEVELS]
    code, tlp_tag = d.menu(
        _rule_so_far(org=org, orig=orig, scope=scope, prio=prio_int) +
        "TLP level override (optional) — normally each row carries its own TLP level.",
        choices=tlp_choices, title="New Rule (4/5)",
        width=72, height=22, menu_height=7,
        ok_label="Select", cancel_label="Cancel")
    if code != d.OK:
        return
    assigned_tlp = "NULL" if tlp_tag == "none" else f"'{tlp_tag}'"
    tlp_display = "none (use row's TLP)" if tlp_tag == "none" else tlp_tag

    # Step 5: description
    c, desc = d.inputbox(
        _rule_so_far(org=org, orig=orig, scope=scope, prio=prio_int, tlp=tlp_display) +
        "Description (optional — shown in rule list):",
        title="New Rule (5/5)", width=72, height=17)
    if c != d.OK:
        return

    try:
        conn.ch.multiquery(
            f"INSERT INTO metranova_authz.rules "
            f"(organization_id, policy_originator_pattern, policy_scope_pattern, "
            f"assigned_tlp, priority, description) VALUES "
            f"('{org['id']}', '{orig}', '{scope}', "
            f"{assigned_tlp}, {prio_int}, '{desc.strip()}');"
        )
        _msgbox(d, "Rule created.\n\nThe pipeline will pick it up at next ingest.",
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


# ── TUI: section 5 — grants ───────────────────────────────────────────────────

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
    """CREATE ROLE IF NOT EXISTS, grant SELECT on data_flow, and dictGet on authz dicts.

    The dictGet privilege is required because row policy USING expressions run in
    the user's security context — without it the dictGetOrDefault calls fail and the
    policy silently denies all rows.
    """
    ch.multiquery(
        f"CREATE ROLE IF NOT EXISTS `{group_name}`;\n"
        f"GRANT SELECT ON metranova.data_flow TO `{group_name}`;\n"
        f"GRANT dictGet ON metranova_authz.authz_group_read_orgs TO `{group_name}`;\n"
        f"GRANT dictGet ON metranova_authz.authz_group_write_orgs TO `{group_name}`;"
    )


def section_grants(d, conn: WizardConnections):
    while True:
        grants = _list_grants(conn.ch)
        grant_index = {str(i): g for i, g in enumerate(grants)}
        choices = []
        for i, g in enumerate(grants):
            perm_icon = "R" if g["permission"] == "read" else "W"
            tlp_short = g["max_tlp_level"].replace("tlp:", "")
            choices.append((str(i),
                f"[{perm_icon}] {g['org_name']:<18} {tlp_short:<8} {g['group_name']}"))
        choices.append(("__new__", "+ Add grant"))

        code, tag = d.menu(
            "Grants link Keycloak groups to org+TLP+permission.\n"
            "[R]=read  [W]=write  (independent — write does NOT imply read)\n\n"
            "Creating a grant also creates the Keycloak group and CH role.",
            choices=choices, title="Access Grants",
            width=84, height=22, menu_height=12,
            ok_label="View", cancel_label="Back",
            extra_button=True, extra_label="Revoke",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if tag == "__new__":
            _grant_create(d, conn)
            continue

        if code == "extra":
            grant = grant_index[tag]
            if _confirm(d,
                f"Revoke grant for group '{grant['group_name']}'?\n\n"
                f"The CH role and Keycloak group will be deleted.\n"
                f"Row policy takes effect within 30 seconds.",
                title="Confirm revoke"):
                _grant_revoke(d, conn, grant)
            continue

        grant = grant_index[tag]
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


# ── TUI: section T — enforcement report ───────────────────────────────────────

_REPORT_TEMP_USER = "_authz_test_probe"


def _row_count_as(ch: ClickHouseClient, username: str) -> int:
    """Return data_flow row count as seen by the given CH username (no password)."""
    import shutil
    binary = ["clickhouse-client"] if shutil.which("clickhouse-client") else ["clickhouse", "client"]
    result = subprocess.run(
        binary + [
            "--host", ch.host, "--secure", "--port", str(ch.port),
            "--user", username,
            "--accept-invalid-certificate",
            "--query", "SELECT count() FROM metranova.data_flow",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return int(result.stdout.strip())


def _enforcement_report(ch: ClickHouseClient) -> dict:
    """Build enforcement report data without any TUI interaction.

    Returns:
        {
          "total": int,               # admin-visible count
          "no_grants": int,           # count with no roles at all
          "grants": [                 # one entry per active grant
            {"group_name": str, "max_tlp_level": str, "permission": str,
             "org_slug": str, "visible": int}
          ],
          "errors": [str]             # any per-grant errors
        }
    """
    errors = []

    # Total visible to admin
    total = int(ch.query("SELECT count() FROM metranova.data_flow").strip())

    # No-grant baseline: create a temp user with no roles
    try:
        ch.multiquery(
            f"DROP USER IF EXISTS `{_REPORT_TEMP_USER}`;\n"
            f"CREATE USER `{_REPORT_TEMP_USER}` IDENTIFIED WITH no_password;\n"
            f"GRANT SELECT ON metranova.data_flow TO `{_REPORT_TEMP_USER}`;\n"
            f"GRANT dictGet ON metranova_authz.authz_group_read_orgs TO `{_REPORT_TEMP_USER}`;\n"
            f"GRANT dictGet ON metranova_authz.authz_group_write_orgs TO `{_REPORT_TEMP_USER}`;"
        )
        no_grants = _row_count_as(ch, _REPORT_TEMP_USER)
    except Exception as exc:
        no_grants = None
        errors.append(f"no-grants baseline: {exc}")
    finally:
        try:
            ch.query(f"DROP USER IF EXISTS `{_REPORT_TEMP_USER}`")
        except Exception:
            pass

    # Per-grant counts
    raw = ch.query(
        "SELECT g.group_name, g.max_tlp_level, g.permission, o.slug "
        "FROM metranova_authz.grants AS g FINAL "
        "JOIN metranova_authz.organizations AS o ON g.organization_id = o.id "
        "WHERE isNull(g.revoked_at) "
        "ORDER BY o.slug, g.max_tlp_level, g.permission "
        "FORMAT JSONEachRow"
    )
    grants_meta = [json.loads(line) for line in raw.splitlines() if line.strip()]

    grant_rows = []
    for g in grants_meta:
        group = g["group_name"]
        try:
            ch.multiquery(
                f"DROP USER IF EXISTS `{_REPORT_TEMP_USER}`;\n"
                f"CREATE USER `{_REPORT_TEMP_USER}` IDENTIFIED WITH no_password;\n"
                f"GRANT `{group}` TO `{_REPORT_TEMP_USER}`;\n"
                f"GRANT SELECT ON metranova.data_flow TO `{_REPORT_TEMP_USER}`;\n"
                f"GRANT dictGet ON metranova_authz.authz_group_read_orgs TO `{_REPORT_TEMP_USER}`;\n"
                f"GRANT dictGet ON metranova_authz.authz_group_write_orgs TO `{_REPORT_TEMP_USER}`;"
            )
            visible = _row_count_as(ch, _REPORT_TEMP_USER)
        except Exception as exc:
            visible = None
            errors.append(f"{group}: {exc}")
        finally:
            try:
                ch.query(f"DROP USER IF EXISTS `{_REPORT_TEMP_USER}`")
            except Exception:
                pass
        grant_rows.append({**g, "visible": visible})

    return {"total": total, "no_grants": no_grants, "grants": grant_rows, "errors": errors}


def _format_enforcement_report(data: dict) -> str:
    total = data["total"]
    pct = lambda n: f"{100*n//total}%" if total > 0 and n is not None else ("0%" if total == 0 else "?")
    vis = lambda n: str(n) if n is not None else "err"

    w_role = max(36, *(len(g["group_name"]) + 2 for g in data["grants"]) if data["grants"] else [36])
    sep = "─" * (w_role + 22)

    lines = [
        f"Total rows in data_flow: {total:,}",
        "",
        f"{'Role / context':<{w_role}}  {'Visible':>8}  {'% of total':>10}",
        sep,
        f"{'admin  (exempt)':<{w_role}}  {total:>8,}  {'100%':>10}",
        sep,
    ]

    if data["grants"]:
        for g in data["grants"]:
            label = g["group_name"]
            n = g["visible"]
            lines.append(f"{label:<{w_role}}  {vis(n):>8}  {pct(n):>10}")
    else:
        lines.append(f"{'(no active grants)':}")

    lines += [
        sep,
        f"{'[no grants]':<{w_role}}  {vis(data['no_grants']):>8}  {pct(data['no_grants'] or 0):>10}",
    ]

    if data["errors"]:
        lines += ["", "Errors:"] + [f"  {e}" for e in data["errors"]]

    return "\n".join(lines)


def section_enforcement_report(d, conn: WizardConnections):
    # Pre-check: data_flow must exist before we can run counts
    try:
        exists = conn.ch.query(
            "SELECT count() FROM system.tables"
            " WHERE database='metranova' AND name='data_flow'"
        ).strip()
    except Exception as exc:
        _error(d, f"Could not reach ClickHouse:\n\n{exc}")
        return
    if exists == "0":
        _msgbox(d,
                "metranova.data_flow does not exist yet.\n\n"
                "ArgoCD may still be syncing the ClickHouse schema.\n"
                "Wait for the flow pipeline pod to start, then retry.",
                title="Table not ready", width=64, height=12)
        return

    d.infobox("Running enforcement report...\n\nQuerying as each grant role — may take a few seconds.",
              width=62, height=7, title="Enforcement Report")
    try:
        data = _enforcement_report(conn.ch)
    except Exception as exc:
        _error(d, f"Report failed:\n\n{exc}")
        return

    report = _format_enforcement_report(data)
    _msgbox(d, report, title="Enforcement Report", width=72, height=min(30, len(report.splitlines()) + 6))


# ── TUI: section 6 — audit ────────────────────────────────────────────────────

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


# ── Prerequisites: cluster operators ──────────────────────────────────────────

_PREREQUISITES = [
    {
        "key":        "argocd",
        "label":      "ArgoCD",
        "desc":       "GitOps controller (optional — needed for step A)",
        "crd":        "applications.argoproj.io",
        "namespace":  "argocd",
        "helm_repo":  ("argo", "https://argoproj.github.io/argo-helm"),
        "helm_chart": "argo/argo-cd",
        "helm_release": "argocd",
        "helm_ns":    "argocd",
        "helm_flags": ["--create-namespace"],
    },
    {
        "key":        "clickhouse-operator",
        "label":      "Altinity ClickHouse Operator",
        "desc":       "Required to run ClickHouse clusters",
        "crd":        "clickhouseinstallations.clickhouse.altinity.com",
        "namespace":  "kube-system",
        "helm_repo":  ("altinity-clickhouse-operator",
                       "https://docs.altinity.com/clickhouse-operator"),
        "helm_chart": "altinity-clickhouse-operator/altinity-clickhouse-operator",
        "helm_release": "clickhouse-operator",
        "helm_ns":    "kube-system",
        "helm_flags": [],
    },
    {
        "key":        "strimzi",
        "label":      "Strimzi Kafka Operator",
        "desc":       "Required to run Kafka clusters",
        "crd":        "kafkas.kafka.strimzi.io",
        "namespace":  "kube-system",
        "helm_repo":  ("strimzi", "https://strimzi.io/charts/"),
        "helm_chart": "strimzi/strimzi-kafka-operator",
        "helm_release": "strimzi-kafka-operator",
        "helm_ns":    "kube-system",
        # watchNamespaces must include the app namespace so the operator
        # reconciles Kafka/KafkaNodePool/KafkaUser CRs deployed there.
        "helm_flags": ["--set", "watchNamespaces={metranova}"],
    },
    {
        "key":        "traefik",
        "label":      "Traefik Ingress Controller",
        "desc":       "Required for ingress routes",
        "crd":        "ingressroutes.traefik.io",
        "namespace":  "kube-system",
        "helm_repo":  ("traefik", "https://helm.traefik.io/traefik"),
        "helm_chart": "traefik/traefik",
        "helm_release": "traefik",
        "helm_ns":    "kube-system",
        "helm_flags": [],
    },
]


def _crd_exists(crd_name: str) -> bool:
    r = subprocess.run(
        ["kubectl", "get", "crd", crd_name, "--context", _kubectl_context()],
        capture_output=True,
    )
    return r.returncode == 0


def _helm_repo_add(name: str, url: str) -> tuple[bool, str]:
    r = subprocess.run(
        ["helm", "repo", "add", name, url, "--force-update"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, r.stderr.strip()
    subprocess.run(["helm", "repo", "update", name], capture_output=True)
    return True, ""


def _helm_install(chart: str, release: str, namespace: str,
                   extra_flags: list[str]) -> tuple[bool, str]:
    r = subprocess.run(
        ["helm", "upgrade", "--install", release, chart,
         "--namespace", namespace,
         "--kube-context", _kubectl_context()]
        + extra_flags,
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, r.stderr.strip()
    return True, r.stdout.strip()


def _wait_for_crd(crd_name: str, timeout: int = 120) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if _crd_exists(crd_name):
            return True
        time.sleep(3)
    return False


def section_prerequisites(d, namespace: str):
    """Check and install cluster operators required by the MetrANOVA stack."""
    ctx = ["--context", _kubectl_context()]

    # Check which are installed
    d.infobox("Checking cluster prerequisites...", width=52, height=6, title="Prerequisites")
    status = {p["key"]: _crd_exists(p["crd"]) for p in _PREREQUISITES}

    # Build checklist — pre-select missing ones
    choices = []
    for p in _PREREQUISITES:
        installed = status[p["key"]]
        tag = "✓ " if installed else "  "
        label = f"{tag}{p['label']} — {p['desc']}"
        choices.append((p["key"], label, not installed))

    code, selected = d.checklist(
        "Cluster prerequisites for the MetrANOVA stack.\n\n"
        "Checked items will be installed. Already-installed\n"
        "items are pre-unchecked but can be re-installed.",
        title="Prerequisites",
        width=78, height=20, list_height=6,
        choices=choices,
    )

    if code in (d.CANCEL, d.ESC) or not selected:
        return

    # Ensure the app namespace exists before installing operators that create
    # RoleBindings in it (e.g. Strimzi with watchNamespaces).
    subprocess.run(
        ["kubectl", "create", "namespace", namespace,
         "--context", _kubectl_context()],
        capture_output=True,  # ignore "already exists" error
    )

    errors = []
    for p in _PREREQUISITES:
        if p["key"] not in selected:
            continue

        name, url = p["helm_repo"]
        d.infobox(
            f"Adding Helm repo: {name}\n  {url}",
            width=64, height=6, title=f"Installing {p['label']}",
        )
        ok, msg = _helm_repo_add(name, url)
        if not ok:
            errors.append(f"{p['label']}: repo add failed — {msg}")
            continue

        d.infobox(
            f"Installing {p['helm_chart']}\n"
            f"  release: {p['helm_release']}  namespace: {p['helm_ns']}",
            width=64, height=6, title=f"Installing {p['label']}",
        )
        ok, msg = _helm_install(
            p["helm_chart"], p["helm_release"], p["helm_ns"], p["helm_flags"]
        )
        if not ok:
            errors.append(f"{p['label']}: helm install failed — {msg}")
            continue

        d.infobox(
            f"Waiting for CRD: {p['crd']}\n(up to 120s)",
            width=64, height=6, title=f"Installing {p['label']}",
        )
        if not _wait_for_crd(p["crd"]):
            errors.append(f"{p['label']}: CRD {p['crd']} not found after 120s — operator may still be starting")

    if errors:
        import textwrap
        wrapped = []
        for e in errors:
            lines = textwrap.wrap(e, width=78, subsequent_indent="  ")
            wrapped.append("• " + "\n".join(lines))
        d.scrollbox(
            "Some prerequisites had issues:\n\n" +
            "\n\n".join(wrapped) +
            "\n\nYou can continue and retry later, or install\n"
            "manually and re-run this step.",
            title="Prerequisites: issues", width=84, height=24)
    else:
        _msgbox(d,
            "All selected prerequisites installed successfully.\n\n"
            "You can now proceed to step 0 (Secrets) and\n"
            "step A (ArgoCD sync).",
            title="Prerequisites ready", width=64, height=12)


# ── Preflight: stack deployment check ─────────────────────────────────────────

ARGOCD_APP_MANIFEST = (
    # Path relative to repo root — applied as-is
    "argocd/metranova-app.yaml"
)

def _argocd_app_exists(app_name: str) -> bool:
    r = subprocess.run(
        ["kubectl", "get", "application", app_name, "-n", "argocd",
         "--context", _kubectl_context()],
        capture_output=True,
    )
    return r.returncode == 0


def _apply_argocd_manifest(manifest_rel_path: str) -> tuple[bool, str]:
    """Apply an ArgoCD Application manifest from the repo root. Returns (ok, msg)."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    full_path = os.path.join(repo_root, manifest_rel_path)
    if not os.path.exists(full_path):
        return False, f"Manifest not found: {full_path}"
    r = subprocess.run(
        ["kubectl", "apply", "-f", full_path,
         "--context", _kubectl_context()],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, r.stderr.strip()
    return True, r.stdout.strip()


def _rules_to_authz_json(ch: ClickHouseClient) -> str:
    """Serialize current authz rules to JSON for CLICKHOUSE_FLOW_POLICY_AUTHZ_RULES."""
    out = ch.query(
        "SELECT policy_originator_pattern, policy_scope_pattern, slug "
        "FROM metranova_authz.rules AS r FINAL "
        "JOIN metranova_authz.organizations AS o ON r.organization_id = o.id "
        "ORDER BY priority DESC, r.id FORMAT JSONEachRow"
    )
    rules = []
    for line in out.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rules.append({
            "originator": row["policy_originator_pattern"],
            "scope":      row["policy_scope_pattern"],
            "org":        row["slug"],
        })
    return json.dumps(rules)


def section_sync_pipeline(d, conn: WizardConnections, namespace: str):
    """Sync authz rules to the flow pipeline deployment as env vars.

    Serializes metranova_authz.rules to JSON and patches the
    metranova-flowpipeline-data-flow deployment env vars. The deployment
    rolls automatically — no manual restart needed.
    """
    try:
        rules_json = _rules_to_authz_json(conn.ch)
    except Exception as exc:
        _error(d, f"Could not read rules from ClickHouse:\n\n{exc}")
        return

    rules = json.loads(rules_json)
    if not rules:
        code = d.yesno(
            "No classification rules are defined.\n\n"
            "Syncing now will set CLICKHOUSE_FLOW_POLICY_AUTHZ_ENABLED=false, "
            "meaning all flow rows will default to policy_organizations=[] (invisible to non-exempt users).\n\n"
            "Proceed?",
            title="No rules defined", width=70, height=12,
            yes_label="Proceed", no_label="Cancel",
        )
        if code != d.OK:
            return

    summary = "\n".join(
        f"  {r['originator']} / {r['scope']}  →  {r['org']}" for r in rules[:10]
    )
    if len(rules) > 10:
        summary += f"\n  ... and {len(rules) - 10} more"

    enabled = "true" if rules else "false"
    code = d.yesno(
        f"Sync {len(rules)} rule(s) to pipeline deployment:\n\n"
        f"{summary}\n\n"
        f"CLICKHOUSE_FLOW_POLICY_AUTHZ_ENABLED={enabled}\n\n"
        "The pipeline deployment will roll automatically.",
        title="Sync pipeline config", width=76, height=20,
        yes_label="Sync", no_label="Cancel",
    )
    if code != d.OK:
        return

    # Ensure policy_organizations column exists before the pipeline tries to write it.
    # This is a no-op if the column was already added by step 2.
    try:
        conn.ch.query(
            "ALTER TABLE metranova.data_flow"
            " ADD COLUMN IF NOT EXISTS policy_organizations Array(LowCardinality(String)) DEFAULT []"
        )
    except Exception as exc:
        _error(d, f"Could not add policy_organizations column to metranova.data_flow:\n\n{exc}\n\n"
                  "Make sure the data_flow table exists (ArgoCD sync may still be in progress).")
        return

    deployment = "metranova-flowpipeline-data-flow"
    patch = {
        "spec": {"template": {"spec": {"containers": [{
            "name": "data-flow",
            "env": [
                {"name": "CLICKHOUSE_FLOW_POLICY_AUTHZ_ENABLED", "value": enabled},
                {"name": "CLICKHOUSE_FLOW_POLICY_AUTHZ_RULES",   "value": rules_json},
            ],
        }]}}}
    }

    d.infobox(f"Patching {deployment}...", width=56, height=6, title="Syncing")
    result = subprocess.run(
        ["kubectl", "patch", "deployment", deployment,
         "-n", namespace, "--context", _kubectl_context(),
         "--type", "strategic",
         "-p", json.dumps(patch)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        _error(d, f"Patch failed:\n\n{result.stderr.strip()}")
        return

    _msgbox(d,
        f"Pipeline deployment patched.\n\n"
        f"{len(rules)} rule(s) synced.\n"
        "CLICKHOUSE_FLOW_POLICY_AUTHZ_ENABLED=" + enabled + "\n\n"
        "The pod is rolling — new flows will be stamped with\n"
        "policy_organizations once the new pod is ready.",
        title="Synced", width=68, height=14)


def section_argocd_sync(d, namespace: str, release: str, ch_service: str):
    """Optional step: register ArgoCD apps if needed and sync both auth + umbrella."""
    d.infobox("Checking ArgoCD applications...", width=48, height=6, title="ArgoCD")

    auth_exists = _argocd_app_exists(release)
    umbrella_exists = _argocd_app_exists("metranova")

    lines = []
    if not auth_exists:
        lines.append(f"  • '{release}' app not found — will create from argocd/{release}-app.yaml")
    else:
        lines.append(f"  • '{release}' app exists")
    if not umbrella_exists:
        lines.append("  • 'metranova' app not found — will create from argocd/metranova-app.yaml")
    else:
        lines.append("  • 'metranova' app exists")

    status_text = "\n".join(lines)
    code = d.yesno(
        f"ArgoCD application status:\n\n{status_text}\n\n"
        "Proceed with sync? This will apply any missing\n"
        "Application manifests and wait for pods to be ready.",
        title="ArgoCD Sync",
        width=70, height=18,
        yes_label="Sync",
        no_label="Cancel",
    )
    if code != d.OK:
        return

    if not auth_exists:
        ok, msg = _apply_argocd_manifest(f"argocd/{release}-app.yaml")
        if not ok:
            _error(d, f"Failed to create '{release}' ArgoCD app:\n\n{msg}")
            return

    if not umbrella_exists:
        ok, msg = _apply_argocd_manifest(ARGOCD_APP_MANIFEST)
        if not ok:
            _error(d, f"Failed to create 'metranova' ArgoCD app:\n\n{msg}")
            return

    ok_auth = argocd_sync_and_wait(d, namespace, app_name=release)
    ok_umbrella = True
    if _argocd_app_exists("metranova"):
        ok_umbrella = argocd_sync_and_wait(d, namespace, app_name="metranova", timeout=600)

    if ok_auth and ok_umbrella:
        _msgbox(d,
            "All pods are ready.\n\n"
            "Use step 1 (Connect) to open port-forwards,\n"
            "then proceed to Organizations and Grants.",
            title="Cluster ready", width=62, height=12)
    else:
        which = []
        if not ok_auth:
            which.append(release)
        if not ok_umbrella:
            which.append("metranova")
        _msgbox(d,
            f"Timed out waiting for: {', '.join(which)}\n\n"
            "The cluster may still be starting. Check:\n"
            f"  kubectl get pods -n {namespace}\n\n"
            "Once all pods are 1/1 Running, use step 1\n"
            "to connect.",
            title="Timeout", width=64, height=14)


# ── Main TUI loop ──────────────────────────────────────────────────────────────

def run_wizard(namespace: str, release: str, dry_run: bool, ch_service: str = ""):
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
                ("P", "Prerequisites    — install cluster operators (CH, Kafka, Traefik, ArgoCD)"),
                ("0", "Secrets          — generate and write K8s secrets"),
                ("1", f"Connect          — open port-forwards  [{status}]"),
                ("2", f"Init authz DB    — create metranova_authz schema  {'[connect first]' if locked else ''}"),
                ("3", f"Init policies    — deploy dicts + row policies  {'[connect first]' if locked else ''}"),
                ("4", f"Organizations    — manage orgs          {'[connect first]' if locked else ''}"),
                ("5", f"Rules            — classification rules  {'[connect first]' if locked else ''}"),
                ("6", f"Grants           — access grants         {'[connect first]' if locked else ''}"),
                ("7", f"Audit            — view audit log        {'[connect first]' if locked else ''}"),
                ("T", f"Test enforcement — row count per grant role     {'[connect first]' if locked else ''}"),
                ("S", f"Sync pipeline    — push rules to flow pipeline  {'[connect first]' if locked else ''}"),
                ("A", "ArgoCD sync      — register apps and sync (optional)"),
            ]

            code, tag = d.menu(
                "MetrANOVA Authorization Wizard\n\n"
                "Fresh cluster? Start with P (Prerequisites), then\n"
                "0 (Secrets), deploy, 1 (Connect), 2 (Init authz DB), 3 (Init policies).",
                choices=choices,
                title="Main Menu",
                width=76, height=30, menu_height=17,
                ok_label="Open",
                cancel_label="Exit",
            )

            if code in (d.CANCEL, d.ESC):
                break

            if tag == "0":
                section_secrets(d, namespace, release, dry_run)
            elif tag == "1":
                section_connect(d, conn, namespace, release, ch_service=ch_service)
            elif tag == "2":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_init_authz(d, conn)
            elif tag == "3":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_init_authz_policies(d, conn)
            elif tag == "4":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_orgs(d, conn)
            elif tag == "5":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_rules(d, conn)
            elif tag == "6":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_grants(d, conn)
            elif tag == "7":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_audit(d, conn)
            elif tag == "T":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_enforcement_report(d, conn)
            elif tag == "S":
                if locked:
                    _msgbox(d, "Connect first (step 1).", title="Not connected")
                else:
                    section_sync_pipeline(d, conn, namespace)
            elif tag == "P":
                section_prerequisites(d, namespace)
            elif tag == "A":
                section_argocd_sync(d, namespace, release, ch_service)
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


def run_init_policies(namespace: str, ch_service: str = "",
                      ch_internal_host: str = "clickhouse-ch-cluster",
                      ch_internal_port: int = 9000):
    """Non-interactively deploy dictionaries and row policies.

    Opens a port-forward, runs the policy DDL, then tears down the forward.
    Exits non-zero on failure.
    """
    candidates = []
    if ch_service:
        candidates.append(ch_service)
    candidates += ["svc/clickhouse-ch-cluster", "svc/clickhouse"]

    ch_pf = None
    for candidate in candidates:
        if "/" in candidate and not candidate.startswith("svc/"):
            ch_ns, ch_svc_name = candidate.split("/", 1)
            pf = PortForward(ch_ns, f"svc/{ch_svc_name}", remote_port=9440,
                             local_port=PF_CH_LOCAL_PORT)
        else:
            pf = PortForward(namespace, candidate, remote_port=9440,
                             local_port=PF_CH_LOCAL_PORT)
        if pf.start(timeout=10):
            ch_pf = pf
            break
        pf.stop()

    if ch_pf is None:
        print(f"ERROR: could not reach ClickHouse (tried {candidates})", file=sys.stderr)
        sys.exit(1)

    try:
        ch_pass = load_ch_admin_password(namespace)
        if not ch_pass:
            print("ERROR: could not read ClickHouse admin password from cluster secret",
                  file=sys.stderr)
            sys.exit(1)

        ch = ClickHouseClient(port=PF_CH_LOCAL_PORT, user="admin", password=ch_pass)
        if not ch.ping():
            print("ERROR: ClickHouse port-forward up but authentication failed", file=sys.stderr)
            sys.exit(1)

        sql = _build_authz_policy_sql(
            ch_password=ch_pass,
            ch_internal_host=ch_internal_host,
            ch_internal_port=ch_internal_port,
            ch_user="admin",
        )
        print("Deploying dictionaries and row policies...")
        ch.multiquery(sql)
        print("Done.")
    finally:
        ch_pf.stop()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MetrANOVA auth wizard")
    parser.add_argument("--namespace",  default=os.environ.get("NAMESPACE",    "metranova"))
    parser.add_argument("--release",    default=os.environ.get("AUTH_RELEASE", "metranova-auth"))
    parser.add_argument("--export-csv", metavar="PATH")
    parser.add_argument("--dry-run",    action="store_true")
    parser.add_argument("--no-tui",     action="store_true", help="Generate secrets non-interactively")
    parser.add_argument("--init-policies", action="store_true",
                        help="Non-interactively deploy authz dictionaries and row policies, then exit")
    parser.add_argument("--clickhouse-service", default="", metavar="SVC",
                        help="ClickHouse K8s service name or namespace/name (default: auto-detect)")
    parser.add_argument("--ch-internal-host", default="clickhouse-ch-cluster", metavar="HOST",
                        help="ClickHouse cluster-internal hostname for dictionary SOURCE (default: clickhouse-ch-cluster)")
    parser.add_argument("--ch-internal-port", type=int, default=9000, metavar="PORT",
                        help="ClickHouse plain TCP port for dictionary SOURCE (default: 9000)")
    args = parser.parse_args()

    problems = preflight_check(skip_tui=args.no_tui or args.init_policies)
    if problems:
        print("Cannot start — missing dependencies:\n", file=sys.stderr)
        for p in problems:
            print(f"  • {p}", file=sys.stderr)
        sys.exit(1)

    if args.init_policies:
        run_init_policies(args.namespace, ch_service=args.clickhouse_service,
                          ch_internal_host=args.ch_internal_host,
                          ch_internal_port=args.ch_internal_port)
    elif args.no_tui:
        run_headless(args.namespace, args.release, args.dry_run, args.export_csv)
    else:
        run_wizard(args.namespace, args.release, args.dry_run,
                   ch_service=args.clickhouse_service)


if __name__ == "__main__":
    main()
