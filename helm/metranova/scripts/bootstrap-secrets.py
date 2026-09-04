#!/usr/bin/env python3
"""
MetrANOVA Secret Bootstrap TUI

Interactive curses-based secret generator for the metranova helm stack.
Auto-generates cryptographically secure values; lets operators review and
override each one before writing to kubectl.

Usage:
    python3 bootstrap-secrets.py [--namespace metranova] [--release metranova-auth]
    python3 bootstrap-secrets.py --export-csv secrets.csv   # backup for password manager
    python3 bootstrap-secrets.py --dry-run                  # print kubectl commands only
"""

import argparse
import base64
import csv
import curses
import os
import secrets
import string
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional


# ── Secret definitions ─────────────────────────────────────────────────────────

@dataclass
class SecretField:
    key: str
    label: str
    description: str
    group: str
    generate: callable
    value: str = ""
    confirmed: bool = False
    sensitive: bool = True


def gen_password(length=24):
    alphabet = string.ascii_letters + string.digits + "!@#%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_token(length=43):
    return secrets.token_urlsafe(32)[:length]


def gen_fernet():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def gen_hex(nbytes=32):
    return secrets.token_hex(nbytes)


def make_fields(release: str) -> list[SecretField]:
    return [
        # ── ClickHouse ──────────────────────────────────────────────────────
        SecretField(
            key="clickhouse-users/admin-password",
            label="ClickHouse admin password",
            description="Password for the ClickHouse admin user. Full access.",
            group="ClickHouse  (secret: clickhouse-users)",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/readonly-password",
            label="ClickHouse readonly password",
            description="Password for the ClickHouse readonly user (Grafana datasource).",
            group="ClickHouse  (secret: clickhouse-users)",
            generate=gen_password,
        ),
        SecretField(
            key="clickhouse-users/backup-password",
            label="ClickHouse backup password",
            description="Password for the ClickHouse backup user.",
            group="ClickHouse  (secret: clickhouse-users)",
            generate=gen_password,
        ),
        # ── Grafana admin ───────────────────────────────────────────────────
        SecretField(
            key="grafana-admin/admin-user",
            label="Grafana admin username",
            description="Grafana admin login username.",
            group="Grafana admin  (secret: grafana-admin)",
            generate=lambda: "admin",
            sensitive=False,
        ),
        SecretField(
            key="grafana-admin/admin-password",
            label="Grafana admin password",
            description="Grafana admin login password.",
            group="Grafana admin  (secret: grafana-admin)",
            generate=gen_password,
        ),
        # ── Auth ────────────────────────────────────────────────────────────
        SecretField(
            key=f"{release}-secrets/KEYCLOAK_ADMIN_PASSWORD",
            label="Keycloak admin password",
            description="Password for the Keycloak 'admin' user. Used to manage realms and clients.",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/LDAP_ADMIN_PASSWORD",
            label="OpenLDAP admin password",
            description="Password for the OpenLDAP admin bind DN (cn=admin,dc=...).",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/LDAP_CONFIG_PASSWORD",
            label="OpenLDAP config password",
            description="Password for the OpenLDAP config database (cn=config).",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_OIDC_CLIENT_SECRET",
            label="Envoy OIDC client secret",
            description=(
                "Shared secret between Envoy and Keycloak for the 'envoy-proxy' client.\n"
                "Must match the client secret configured in Keycloak after first deploy."
            ),
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_token,
        ),
        SecretField(
            key=f"{release}-secrets/ENVOY_HMAC_SECRET",
            label="Envoy HMAC secret",
            description="Secret used to sign Envoy OAuth2 session cookies. 256 bits.",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_hex,
        ),
        SecretField(
            key=f"{release}-secrets/TOKEN_STORE_ENCRYPTION_KEY",
            label="Token store encryption key",
            description=(
                "Fernet symmetric key for encrypting tokens at rest.\n"
                "MUST be exactly 32 URL-safe base64-encoded bytes (44 chars ending in '=').\n"
                "Do not edit manually — use the auto-generated value."
            ),
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_fernet,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_ADMIN_PASSWORD",
            label="Grafana admin password (auth chart)",
            description="Grafana admin password configured via the auth chart.",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_CLICKHOUSE_PASSWORD",
            label="Grafana ClickHouse password",
            description="Password for the Grafana ClickHouse datasource user.",
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_password,
        ),
        SecretField(
            key=f"{release}-secrets/GRAFANA_OIDC_CLIENT_SECRET",
            label="Grafana OIDC client secret",
            description=(
                "Shared secret between Grafana and Keycloak for the 'grafana' client.\n"
                "Must match the client secret configured in Keycloak after first deploy."
            ),
            group=f"Auth  (secret: {release}-secrets)",
            generate=gen_token,
        ),
    ]


# ── TUI ────────────────────────────────────────────────────────────────────────

HELP = "ENTER Accept   e Edit   r Regenerate   UP/DOWN Navigate   q Quit"

COLOR_TITLE   = 1
COLOR_GROUP   = 2
COLOR_LABEL   = 3
COLOR_VALUE   = 4
COLOR_DONE    = 5
COLOR_HELP    = 6
COLOR_WARN    = 7
COLOR_CURSOR  = 8


def safestr(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    s = s[:max(0, w - x - 1)]  # leave last cell to avoid wrap ERR
    if not s:
        return
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_TITLE,  curses.COLOR_CYAN,    -1)
    curses.init_pair(COLOR_GROUP,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(COLOR_LABEL,  curses.COLOR_WHITE,   -1)
    curses.init_pair(COLOR_VALUE,  curses.COLOR_GREEN,   -1)
    curses.init_pair(COLOR_DONE,   curses.COLOR_GREEN,   -1)
    curses.init_pair(COLOR_HELP,   curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(COLOR_WARN,   curses.COLOR_RED,     -1)
    curses.init_pair(COLOR_CURSOR, curses.COLOR_BLACK,   curses.COLOR_CYAN)


def draw_header(win, namespace: str):
    h, w = win.getmaxyx()
    title = " MetrANOVA Secret Bootstrap "
    sub   = f" namespace: {namespace} "
    safestr(win, 0, max(0, (w - len(title)) // 2), title, curses.color_pair(COLOR_TITLE) | curses.A_BOLD)
    safestr(win, 1, max(0, (w - len(sub)) // 2), sub, curses.color_pair(COLOR_GROUP))
    try:
        win.hline(2, 0, curses.ACS_HLINE, w - 1)
    except curses.error:
        pass


def draw_help(win):
    h, w = win.getmaxyx()
    safestr(win, h - 1, 0, HELP[:w - 1].ljust(w - 1), curses.color_pair(COLOR_HELP))


def draw_field_list(win, fields, current, scroll):
    h, w = win.getmaxyx()
    body_top = 3
    body_bot = h - 4
    visible = body_bot - body_top

    last_group = None
    row = body_top
    visible_indices = []

    for i, f in enumerate(fields):
        if f.group != last_group:
            visible_indices.append(("group", f.group))
            last_group = f.group
        visible_indices.append(("field", i))

    # Scroll so current field is visible
    # Find position of current field in visible_indices
    cur_pos = next(j for j, x in enumerate(visible_indices) if x == ("field", current))
    if cur_pos - scroll >= visible:
        scroll = cur_pos - visible + 1
    if cur_pos - scroll < 0:
        scroll = cur_pos

    for j, item in enumerate(visible_indices[scroll:scroll + visible]):
        if row >= body_bot:
            break
        kind, val = item
        if kind == "group":
            safestr(win, row, 2, f"-- {val} "[:w - 4], curses.color_pair(COLOR_GROUP) | curses.A_BOLD)
        else:
            f = fields[val]
            is_current = (val == current)
            status = "*" if f.confirmed else " "
            label = f"{status} {f.label}"
            display_val = ("*" * min(len(f.value), 20)) if f.sensitive else f.value[:w - 40]
            line = f"{label:<35} {display_val}"[:w - 4]

            if is_current:
                safestr(win, row, 2, line, curses.color_pair(COLOR_CURSOR) | curses.A_BOLD)
            elif f.confirmed:
                safestr(win, row, 2, line, curses.color_pair(COLOR_DONE))
            else:
                safestr(win, row, 2, line, curses.color_pair(COLOR_LABEL))
        row += 1

    # Progress bar
    done = sum(1 for f in fields if f.confirmed)
    total = len(fields)
    bar_w = max(0, w - 22)
    pct = done * bar_w // total if total else 0
    bar = "#" * pct + "-" * (bar_w - pct)
    safestr(win, h - 3, 2, f"Progress: {done}/{total} [{bar}]", curses.color_pair(COLOR_HELP))

    return scroll


def draw_detail(win, f: SecretField):
    h, w = win.getmaxyx()
    box_top = h - 10
    try:
        win.hline(box_top, 0, curses.ACS_HLINE, w - 1)
    except curses.error:
        pass
    desc_lines = []
    for line in f.description.split("\n"):
        desc_lines.extend(textwrap.wrap(line, w - 6) or [""])
    for i, line in enumerate(desc_lines[:4]):
        safestr(win, box_top + 1 + i, 4, line, curses.color_pair(COLOR_LABEL))

    val_row = box_top + 6
    if f.sensitive:
        display = f.value[:60] if f.value else "(not set)"
        safestr(win, val_row, 4, f"Value: {display}", curses.color_pair(COLOR_VALUE) | curses.A_BOLD)
    else:
        safestr(win, val_row, 4, f"Value: {f.value}", curses.color_pair(COLOR_VALUE))

    safestr(win, val_row + 1, 4, "[ENTER] Accept    [r] Regenerate    [e] Edit", curses.color_pair(COLOR_WARN))


def edit_value(win, f: SecretField) -> str:
    h, w = win.getmaxyx()
    prompt = f"Edit '{f.label}' (ENTER to confirm, ESC to cancel):"
    edit_row = h - 2
    safestr(win, edit_row - 1, 2, prompt)
    curses.echo()
    curses.curs_set(1)
    win.move(edit_row, 2)
    win.clrtoeol()
    try:
        val = win.getstr(edit_row, 2, w - 4).decode("utf-8")
    except Exception:
        val = f.value
    curses.noecho()
    curses.curs_set(0)
    return val if val else f.value


def run_tui(stdscr, fields: list[SecretField], namespace: str) -> bool:
    curses.curs_set(0)
    curses.noecho()
    init_colors()

    # Pre-generate all values
    for f in fields:
        f.value = f.generate()

    current = 0
    scroll = 0

    while True:
        stdscr.erase()
        draw_header(stdscr, namespace)
        scroll = draw_field_list(stdscr, fields, current, scroll)
        draw_detail(stdscr, fields[current])
        draw_help(stdscr)
        stdscr.refresh()

        key = stdscr.getch()

        if key in (curses.KEY_DOWN, ord("j")):
            current = min(len(fields) - 1, current + 1)
        elif key in (curses.KEY_UP, ord("k")):
            current = max(0, current - 1)
        elif key in (curses.KEY_RIGHT, ord("\n"), ord("\r"), 10):
            fields[current].confirmed = True
            if current < len(fields) - 1:
                current += 1
            elif all(f.confirmed for f in fields):
                return True  # all done
        elif key in (curses.KEY_LEFT,):
            if current > 0:
                fields[current].confirmed = False
                current -= 1
        elif key in (ord("r"), ord("R")):
            fields[current].value = fields[current].generate()
            fields[current].confirmed = False
        elif key in (ord("e"), ord("i")):
            new_val = edit_value(stdscr, fields[current])
            fields[current].value = new_val
            fields[current].confirmed = False
        elif key in (ord("q"), ord("Q"), 27):
            return False
        elif key in (ord(" "),):
            # Space = accept and move on
            fields[current].confirmed = True
            current = min(len(fields) - 1, current + 1)

        # Auto-advance when all confirmed
        if all(f.confirmed for f in fields):
            return True


# ── kubectl output ─────────────────────────────────────────────────────────────

def group_fields(fields: list[SecretField]) -> dict[str, dict[str, str]]:
    """Group fields by secret name -> {key: value}."""
    groups: dict[str, dict[str, str]] = {}
    for f in fields:
        secret_name, key = f.key.split("/", 1)
        groups.setdefault(secret_name, {})[key] = f.value
    return groups


def build_kubectl_commands(groups: dict, namespace: str, release: str) -> list[str]:
    cmds = []
    for secret_name, kv in groups.items():
        literals = " ".join(f"--from-literal={k}={v!r}" for k, v in kv.items())

        # Also inject Envoy SDS yaml files into the auth secrets secret
        if secret_name == f"{release}-secrets":
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
            literals += f" --from-literal='token.yaml={token_yaml}'"
            literals += f" --from-literal='hmac.yaml={hmac_yaml}'"

        cmd = (
            f"kubectl create secret generic {secret_name} "
            f"-n {namespace} {literals} "
            f"--dry-run=client -o yaml | kubectl apply -f -"
        )
        cmds.append(cmd)

    # TLS — generate self-signed
    tls_cmd = (
        f"# Auth TLS: run manage-secrets.sh to generate or provide AUTH_TLS_CERT/KEY\n"
        f"# NAMESPACE={namespace} bash manage-secrets.sh bootstrap  (TLS step only)"
    )
    cmds.append(tls_cmd)
    return cmds


def apply_secrets(groups: dict, namespace: str, release: str, dry_run: bool):
    cmds = build_kubectl_commands(groups, namespace, release)
    for cmd in cmds:
        if cmd.startswith("#"):
            print(cmd)
            continue
        if dry_run:
            print(cmd)
        else:
            print(f"Applying: kubectl create secret ... {cmd.split('--from-literal')[0].split()[-1]}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"ERROR: {result.stderr}", file=sys.stderr)
            else:
                print(f"  OK")


def export_csv(fields: list[SecretField], path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Secret", "Key", "Value", "Notes"])
        for field in fields:
            secret_name, key = field.key.split("/", 1)
            writer.writerow([secret_name, key, field.value, field.description.split("\n")[0]])
    print(f"Exported to {path} — import into your password manager and delete afterwards.")


# ── Confirmation screen ────────────────────────────────────────────────────────

def confirm_screen(stdscr, namespace: str, n_secrets: int) -> bool:
    h, w = stdscr.getmaxyx()
    stdscr.erase()
    init_colors()
    lines = [
        "",
        "  All secrets confirmed.",
        "",
        f"  Ready to write {n_secrets} secrets to namespace '{namespace}'.",
        "",
        "  These values will be stored in Kubernetes secrets.",
        "  Make sure you have exported a CSV backup before proceeding.",
        "",
        "  [w] Write to cluster   [x] Export CSV then write   [q] Abort",
        "",
    ]
    for i, line in enumerate(lines):
        safestr(stdscr, h // 2 - len(lines) // 2 + i, 0, line)
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key in (ord("w"), ord("W")):
            return "write"
        if key in (ord("x"), ord("X")):
            return "export_write"
        if key in (ord("q"), ord("Q"), 27):
            return "abort"


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MetrANOVA secret bootstrap TUI")
    parser.add_argument("--namespace", default=os.environ.get("NAMESPACE", "metranova"))
    parser.add_argument("--release", default=os.environ.get("AUTH_RELEASE", "metranova-auth"))
    parser.add_argument("--export-csv", metavar="PATH", help="Export secrets to CSV for password manager backup")
    parser.add_argument("--dry-run", action="store_true", help="Print kubectl commands without applying")
    parser.add_argument("--no-tui", action="store_true", help="Generate all secrets non-interactively and print/apply")
    args = parser.parse_args()

    fields = make_fields(args.release)

    if args.no_tui:
        for f in fields:
            f.value = f.generate()
            f.confirmed = True
        groups = group_fields(fields)
        if args.export_csv:
            export_csv(fields, args.export_csv)
        apply_secrets(groups, args.namespace, args.release, args.dry_run)
        return

    # Run TUI
    completed = curses.wrapper(run_tui, fields, args.namespace)

    if not completed:
        print("Aborted — no secrets written.")
        sys.exit(0)

    groups = group_fields(fields)

    # Confirmation
    action = curses.wrapper(confirm_screen, args.namespace, len(groups))

    if action == "abort":
        print("Aborted — no secrets written.")
        sys.exit(0)

    if action in ("export_write", "write"):
        if action == "export_write" or args.export_csv:
            csv_path = args.export_csv or f"metranova-secrets-{args.namespace}.csv"
            export_csv(fields, csv_path)

        apply_secrets(groups, args.namespace, args.release, args.dry_run)

    print("\nDone. Run 'manage-secrets.sh check' to verify.")
    print("Next: sync ArgoCD or run 'helm upgrade --install'.")


if __name__ == "__main__":
    main()
