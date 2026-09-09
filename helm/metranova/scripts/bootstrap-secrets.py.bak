#!/usr/bin/env python3
"""
MetrANOVA Secret Bootstrap TUI

Usage:
    python3 bootstrap-secrets.py [--namespace metranova] [--release metranova-auth]
    python3 bootstrap-secrets.py --export-csv secrets.csv
    python3 bootstrap-secrets.py --dry-run
    python3 bootstrap-secrets.py --no-tui --dry-run   # CI/headless
"""

import argparse
import base64
import csv
import os
import secrets
import string
import subprocess
import sys
from dataclasses import dataclass


# ── Secret definitions ─────────────────────────────────────────────────────────

@dataclass
class SecretField:
    key: str          # "secret-name/key"
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
    """Generate a self-signed TLS cert and return 'cert\\nKEY_SEPARATOR\\nkey'."""
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
        cert_data = open(crt).read()
        key_data = open(key).read()
        return cert_data + "---KEY---\n" + key_data


def make_fields(release: str) -> list:
    return [
        SecretField(
            key="clickhouse-users/admin-password",
            label="ClickHouse admin password",
            description="Full-access admin password for ClickHouse.",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/readonly-password",
            label="ClickHouse readonly password",
            description="Password for the readonly ClickHouse user (used by Grafana).",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/backup-password",
            label="ClickHouse backup password",
            description="Password for the ClickHouse backup user.",
            group="ClickHouse",
            generate=gen_password,
        ),
        SecretField(
            key="grafana-admin/admin-user",
            label="Grafana admin username",
            description="Grafana admin login username.",
            group="Grafana",
            generate=lambda: "admin",
            sensitive=False,
        ),
        SecretField(
            key="grafana-admin/admin-password",
            label="Grafana admin password",
            description="Grafana admin login password.",
            group="Grafana",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/KEYCLOAK_ADMIN_PASSWORD",
            label="Keycloak admin password",
            description="Password for the Keycloak 'admin' user.",
            group="Auth",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/LDAP_ADMIN_PASSWORD",
            label="OpenLDAP admin password",
            description="Password for the OpenLDAP admin bind DN.",
            group="Auth",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/LDAP_CONFIG_PASSWORD",
            label="OpenLDAP config password",
            description="Password for the OpenLDAP config database.",
            group="Auth",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_OIDC_CLIENT_SECRET",
            label="Envoy OIDC client secret",
            description=(
                "Shared secret for the 'envoy-proxy' Keycloak client. "
                "Must match what is configured in Keycloak after first deploy."
            ),
            group="Auth",
            generate=gen_token,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_HMAC_SECRET",
            label="Envoy HMAC secret",
            description="Signs Envoy OAuth2 session cookies. 256 bits of entropy.",
            group="Auth",
            generate=gen_hex,
        ),
        SecretField(
            key=f"{release}-secrets/TOKEN_STORE_ENCRYPTION_KEY",
            label="Token store encryption key",
            description=(
                "Fernet symmetric key. Must be exactly 32 url-safe base64 bytes. "
                "Use Generate — do not type this by hand."
            ),
            group="Auth",
            generate=gen_fernet,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_ADMIN_PASSWORD",
            label="Grafana admin password (auth chart)",
            description="Grafana admin password configured via the auth chart.",
            group="Auth",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_CLICKHOUSE_PASSWORD",
            label="Grafana ClickHouse password",
            description="Password for the Grafana ClickHouse datasource user.",
            group="Auth",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_OIDC_CLIENT_SECRET",
            label="Grafana OIDC client secret",
            description=(
                "Shared secret for the 'grafana' Keycloak client. "
                "Must match what is configured in Keycloak after first deploy."
            ),
            group="Auth",
            generate=gen_token,
        ),
        SecretField(
            key=f"{release}-tls/combined",
            label="Auth TLS certificate + key",
            description=(
                "TLS cert and key for Envoy HTTPS termination. "
                "Choose Generate for a self-signed cert (dev/test) "
                "or Enter to paste a PEM cert+key. Requires openssl."
            ),
            group="Auth TLS",
            generate=gen_selfsigned_tls,
            sensitive=False,
        ),
    ]


# ── kubectl / export ───────────────────────────────────────────────────────────

def group_fields(fields):
    groups = {}
    for f in fields:
        if f.value and "---KEY---" in f.value:
            continue  # TLS handled separately
        secret_name, key = f.key.split("/", 1)
        groups.setdefault(secret_name, {})[key] = f.value
    return groups


def apply_secrets(groups, namespace, release, dry_run, fields=None):
    for secret_name, kv in groups.items():
        literals = []
        for k, v in kv.items():
            literals.append(f"--from-literal={k}={v!r}")

        if secret_name == f"{release}-secrets":
            literals.append("--from-literal=KEYCLOAK_ADMIN=admin")
            oidc = kv.get("ENVOY_OIDC_CLIENT_SECRET", "")
            hmac = kv.get("ENVOY_HMAC_SECRET", "")
            token_yaml = (
                "resources:\n"
                "- \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n"
                "  name: token-secret\n"
                "  generic_secret:\n"
                "    secret:\n"
                f"      inline_string: {oidc}"
            )
            hmac_yaml = (
                "resources:\n"
                "- \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n"
                "  name: hmac-secret\n"
                "  generic_secret:\n"
                "    secret:\n"
                f"      inline_string: {hmac}"
            )
            literals.append(f"--from-literal=token.yaml={token_yaml!r}")
            literals.append(f"--from-literal=hmac.yaml={hmac_yaml!r}")

        cmd = (
            f"kubectl create secret generic {secret_name} "
            f"-n {namespace} {' '.join(literals)} "
            f"--dry-run=client -o yaml | kubectl apply -f -"
        )
        if dry_run:
            print(cmd)
        else:
            print(f"  Creating secret: {secret_name}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"  ERROR: {result.stderr}", file=sys.stderr)
            else:
                print(f"  OK: {secret_name}")

    tls_field = next((f for f in (fields or []) if f.value and "---KEY---" in f.value), None)
    if tls_field:
        cert, key = tls_field.value.split("---KEY---\n", 1)
        tls_secret = tls_field.key.split("/")[0]
        if dry_run:
            print(f"# kubectl create secret generic {tls_secret} -n {namespace} --from-file=...")
        else:
            print(f"  Creating secret: {tls_secret}")
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                crt_path = os.path.join(d, "server.crt")
                key_path = os.path.join(d, "server.key")
                open(crt_path, "w").write(cert)
                open(key_path, "w").write(key)
                cmd = (
                    f"kubectl create secret generic {tls_secret} "
                    f"-n {namespace} "
                    f"--from-file=server.crt={crt_path} "
                    f"--from-file=server.key={key_path} "
                    f"--from-file=tls.crt={crt_path} "
                    f"--from-file=tls.key={key_path} "
                    f"--dry-run=client -o yaml | kubectl apply -f -"
                )
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"  ERROR: {result.stderr}", file=sys.stderr)
                else:
                    print(f"  OK: {tls_secret}")


def export_csv(fields, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Secret", "Key", "Value", "Notes"])
        for field in fields:
            secret_name, key = field.key.split("/", 1)
            writer.writerow([secret_name, key, field.value, field.description[:80]])
    print(f"Exported to {path} — import into your password manager, then delete this file.")


def load_existing(fields, namespace, d=None):
    """Mark fields confirmed if their key already exists in the cluster.

    Batches kubectl calls — one per distinct secret name rather than one per field.
    Pass a dialog.Dialog instance to show a progress infobox.
    """
    # Collect distinct secret names
    secret_names = list(dict.fromkeys(f.key.split("/", 1)[0] for f in fields))
    total = len(secret_names)

    # Fetch all secrets in one batch: {secret_name: {key: base64_value}}
    existing = {}
    for i, secret_name in enumerate(secret_names):
        if d:
            d.infobox(
                f"Checking existing secrets in namespace '{namespace}'...\n\n"
                f"  {secret_name}  ({i + 1}/{total})",
                width=60, height=8,
                title="Loading",
            )
        result = subprocess.run(
            ["kubectl", "get", "secret", secret_name, "-n", namespace,
             "-o", "jsonpath={.data}"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                existing[secret_name] = json.loads(result.stdout)
            except json.JSONDecodeError:
                existing[secret_name] = {}

    for f in fields:
        secret_name, key = f.key.split("/", 1)
        if secret_name not in existing:
            continue
        if key == "combined":
            # TLS secret — presence is enough
            f.value = "(already set in cluster)"
            f.sensitive = False
            f.confirmed = True
        elif key in existing[secret_name] and existing[secret_name][key]:
            f.value = "(already set in cluster)"
            f.sensitive = False
            f.confirmed = True


# ── dialog TUI ────────────────────────────────────────────────────────────────

def _make_dialog(namespace):
    import dialog
    d = dialog.Dialog()
    d.set_background_title(f"MetrANOVA Secret Bootstrap  |  namespace: {namespace}")
    return d


def run_tui(fields, namespace):
    d = _make_dialog(namespace)

    while True:
        done = sum(1 for f in fields if f.confirmed)
        total = len(fields)
        all_done = done == total

        choices = []
        for i, f in enumerate(fields):
            mark = "[x]" if f.confirmed else "[ ]"
            choices.append((str(i), f"{mark} {f.label}  ({f.group})"))

        msg = f"Progress: {done}/{total} confirmed.\n"
        if all_done:
            msg += "All secrets confirmed. Press Write to Cluster when ready."
        else:
            msg += "Arrow keys to navigate, Enter to open a secret."

        code, tag = d.menu(
            msg,
            choices=choices,
            width=76, height=24, menu_height=16,
            title="Secrets",
            ok_label="Open",
            extra_button=True, extra_label="Generate All",
            help_button=True,  help_label="Write",
            cancel_label="Quit",
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
            if not all(f.confirmed for f in fields):
                d.msgbox(
                    f"Not all secrets are confirmed yet ({done}/{total} done).\n"
                    "Please confirm all secrets before writing.",
                    width=60, height=10, title="Cannot write yet",
                )
                continue
            return True

        # OK — open the item under the cursor
        _edit_field(d, fields[int(tag)])


def _edit_field(d, f: SecretField):
    """Button-based edit screen — Tab between buttons, Enter activates.

    Buttons: Confirm | Generate | View/Edit | Back
    View/Edit opens an inputbox showing the current value (always echoes),
    serving as both show/hide and manual entry.
    """
    while True:
        if f.value:
            display = "*** (hidden — use View/Edit to reveal)" if f.sensitive else (
                f.value[:300] + ("..." if len(f.value) > 300 else ""))
        else:
            display = "(not set)"

        status = "[CONFIRMED]" if f.confirmed else "[unconfirmed]"
        body = (
            f"{f.description}\n\n"
            f"Value: {display}\n\n"
            f"Status: {status}"
        )

        code = d.yesno(
            body,
            title=f.label,
            width=70, height=18,
            yes_label="Confirm",
            no_label="Back",
            extra_button=True, extra_label="Generate",
            help_button=True,  help_label="View/Edit",
        )

        if code in (d.CANCEL, d.ESC):
            return

        if code == d.OK:                # Confirm
            if not f.value:
                f.value = f.generate()
            f.confirmed = True
            return

        if code == "extra":             # Generate
            f.value = f.generate()
            f.confirmed = False

        if code == "help":              # View/Edit — always echoes, shows current value
            init = f.value if f.value and f.value != "(not set)" else ""
            c, val = d.inputbox(
                f"View or edit value for: {f.label}\n\n"
                f"(Leave unchanged and press OK to keep current value.)",
                title=f.label, width=70, height=14,
                init=init,
            )
            if c == d.OK:
                new = val.strip()
                if new and new != f.value:
                    f.value = new
                    f.confirmed = False
                # if unchanged, just loop back (acts as show-only)


def confirm_screen(fields, namespace):
    d = _make_dialog(namespace)
    groups = group_fields(fields)
    n = len(groups) + (1 if any("---KEY---" in f.value for f in fields if f.value) else 0)

    code, tag = d.menu(
        f"Ready to write {n} secrets to namespace '{namespace}'.\n\n"
        "IMPORTANT: Store all values in a password manager before\n"
        "proceeding — they cannot be recovered from the cluster.",
        title="Write secrets to cluster",
        width=68, height=18, menu_height=3,
        choices=[
            ("W", "Write secrets to cluster now"),
            ("X", "Export CSV, then write"),
            ("Q", "Abort — do not write"),
        ],
        ok_label="Select",
        cancel_label="Abort",
    )

    if code in (d.CANCEL, d.ESC) or tag == "Q":
        return "abort"
    if tag == "X":
        return "export_write"
    return "write"


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MetrANOVA secret bootstrap TUI")
    parser.add_argument("--namespace",  default=os.environ.get("NAMESPACE",    "metranova"))
    parser.add_argument("--release",    default=os.environ.get("AUTH_RELEASE", "metranova-auth"))
    parser.add_argument("--export-csv", metavar="PATH")
    parser.add_argument("--dry-run",    action="store_true")
    parser.add_argument("--no-tui",     action="store_true", help="Generate all non-interactively")
    args = parser.parse_args()

    fields = make_fields(args.release)

    if args.no_tui:
        for f in fields:
            f.value = f.generate()
            f.confirmed = True
        groups = group_fields(fields)
        if args.export_csv:
            export_csv(fields, args.export_csv)
        apply_secrets(groups, args.namespace, args.release, args.dry_run, fields)
        print("\nDone.")
        return

    d = _make_dialog(args.namespace)
    load_existing(fields, args.namespace, d)
    completed = run_tui(fields, args.namespace)

    if not completed:
        print("Aborted — no secrets written.")
        sys.exit(0)

    action = confirm_screen(fields, args.namespace)

    if action == "abort":
        print("Aborted — no secrets written.")
        sys.exit(0)

    groups = group_fields(fields)

    if action == "export_write" or args.export_csv:
        csv_path = args.export_csv or f"metranova-secrets-{args.namespace}.csv"
        export_csv(fields, csv_path)

    apply_secrets(groups, args.namespace, args.release, args.dry_run, fields)
    print("\nDone. Run 'manage-secrets.sh check' to verify.")


if __name__ == "__main__":
    main()
