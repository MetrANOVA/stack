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
import curses
import os
import secrets
import string
import subprocess
import sys
import textwrap
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
                "Shared secret for the 'envoy-proxy' Keycloak client.\n"
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
                "Fernet symmetric key. Must be exactly 32 url-safe base64 bytes.\n"
                "Use 'g' to generate — do not type this by hand."
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
                "Shared secret for the 'grafana' Keycloak client.\n"
                "Must match what is configured in Keycloak after first deploy."
            ),
            group="Auth",
            generate=gen_token,
        ),
    ]


# ── Color constants ────────────────────────────────────────────────────────────

C_TITLE   = 1   # primary: orange/yellow bold
C_HEADING = 2   # secondary: blue
C_NORMAL  = 3
C_DONE    = 4   # green
C_CURSOR  = 5   # highlighted row
C_WARN    = 6   # red/orange for hints
C_VALUE   = 7   # bright value display


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    # Primary: bold white on default (bright)
    curses.init_pair(C_TITLE,   curses.COLOR_YELLOW, -1)
    # Secondary/headings: blue
    curses.init_pair(C_HEADING, curses.COLOR_BLUE,   -1)
    curses.init_pair(C_NORMAL,  -1,                  -1)
    curses.init_pair(C_DONE,    curses.COLOR_GREEN,  -1)
    # Cursor: white on blue
    curses.init_pair(C_CURSOR,  curses.COLOR_WHITE,  curses.COLOR_BLUE)
    curses.init_pair(C_WARN,    curses.COLOR_RED,    -1)
    curses.init_pair(C_VALUE,   curses.COLOR_CYAN,   -1)


def W(win, y, x, s, attr=0):
    """Safe addstr — clips to window, never raises."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    s = str(s)[:max(0, w - x - 1)]
    if s:
        try:
            win.addstr(y, x, s, attr)
        except curses.error:
            pass


def box(win):
    try:
        win.border()
    except curses.error:
        pass


# ── List screen ────────────────────────────────────────────────────────────────

def draw_list(stdscr, fields, current, scroll, namespace):
    sh, sw = stdscr.getmaxyx()
    # Fill background
    try:
        stdscr.bkgd(" ", curses.color_pair(C_NORMAL))
    except curses.error:
        pass

    # Centered window dimensions
    win_h = min(sh - 2, 30)
    win_w = min(sw - 4, 80)
    win_y = max(0, (sh - win_h) // 2)
    win_x = max(0, (sw - win_w) // 2)

    win = curses.newwin(win_h, win_w, win_y, win_x)
    box(win)

    # Title
    title = " MetrANOVA Secret Bootstrap "
    W(win, 0, max(1, (win_w - len(title)) // 2), title, curses.color_pair(C_TITLE) | curses.A_BOLD)

    # Subtitle
    sub = f" namespace: {namespace} "
    W(win, 1, max(1, (win_w - len(sub)) // 2), sub, curses.color_pair(C_HEADING))

    try:
        win.hline(2, 1, curses.ACS_HLINE, win_w - 2)
    except curses.error:
        pass

    # Build flat list of rows (group headers + fields)
    rows = []
    last_group = None
    for i, f in enumerate(fields):
        if f.group != last_group:
            rows.append(("group", f.group))
            last_group = f.group
        rows.append(("field", i))

    # Find scroll offset so current field is visible
    body_top = 3
    body_bot = win_h - 4
    visible = body_bot - body_top

    cur_pos = next(j for j, r in enumerate(rows) if r == ("field", current))
    if cur_pos - scroll >= visible:
        scroll = cur_pos - visible + 1
    if cur_pos - scroll < 0:
        scroll = cur_pos

    row = body_top
    for item in rows[scroll:scroll + visible]:
        if row >= body_bot:
            break
        kind, val = item
        if kind == "group":
            W(win, row, 2, f"  {val}", curses.color_pair(C_HEADING) | curses.A_BOLD)
        else:
            f = fields[val]
            is_cur = (val == current)
            mark = "[x]" if f.confirmed else "[ ]"
            label = f"{mark} {f.label}"
            if f.value:
                disp = ("*" * 16) if f.sensitive else f.value[:win_w - 40]
            else:
                disp = "(not set)"

            line = f"{label:<40} {disp}"[:win_w - 4]
            if is_cur:
                attr = curses.color_pair(C_CURSOR) | curses.A_BOLD
            elif f.confirmed:
                attr = curses.color_pair(C_DONE)
            else:
                attr = curses.color_pair(C_NORMAL)
            W(win, row, 2, line, attr)
        row += 1

    # Progress
    done = sum(1 for f in fields if f.confirmed)
    total = len(fields)
    bar_w = win_w - 22
    filled = done * bar_w // total if total else 0
    bar = "#" * filled + "-" * (bar_w - filled)
    try:
        win.hline(win_h - 4, 1, curses.ACS_HLINE, win_w - 2)
    except curses.error:
        pass
    W(win, win_h - 3, 2, f"{done}/{total} [{bar}]", curses.color_pair(C_HEADING))

    # Help line
    help_str = "ENTER:open  G:gen-all  j/k:move  q:quit"
    W(win, win_h - 2, 2, help_str[:win_w - 4], curses.color_pair(C_NORMAL))

    win.refresh()
    return scroll


# ── Modal for a single secret ──────────────────────────────────────────────────

def open_modal(stdscr, f: SecretField) -> bool:
    """
    Show a centered modal for one secret.
    Returns True if confirmed, False if cancelled (ESC).
    """
    sh, sw = stdscr.getmaxyx()

    modal_h = 14
    modal_w = min(sw - 8, 72)
    modal_y = max(0, (sh - modal_h) // 2)
    modal_x = max(0, (sw - modal_w) // 2)

    while True:
        stdscr.clear()
        stdscr.refresh()
        win = curses.newwin(modal_h, modal_w, modal_y, modal_x)
        box(win)

        # Title
        title = f" {f.label} "[:modal_w - 2]
        W(win, 0, max(1, (modal_w - len(title)) // 2), title, curses.color_pair(C_TITLE) | curses.A_BOLD)

        # Group
        W(win, 1, 2, f"Group: {f.group}", curses.color_pair(C_HEADING))

        try:
            win.hline(2, 1, curses.ACS_HLINE, modal_w - 2)
        except curses.error:
            pass

        # Description
        desc_lines = []
        for line in f.description.split("\n"):
            desc_lines.extend(textwrap.wrap(line, modal_w - 6) or [""])
        for i, dl in enumerate(desc_lines[:3]):
            W(win, 3 + i, 3, dl, curses.color_pair(C_NORMAL))

        try:
            win.hline(6, 1, curses.ACS_HLINE, modal_w - 2)
        except curses.error:
            pass

        # Current value
        if f.value:
            display = ("*" * min(len(f.value), modal_w - 14)) if f.sensitive else f.value[:modal_w - 14]
            W(win, 7, 3, "Value: ", curses.color_pair(C_NORMAL))
            W(win, 7, 10, display, curses.color_pair(C_VALUE) | curses.A_BOLD)
        else:
            W(win, 7, 3, "Value: (not set)", curses.color_pair(C_WARN))

        W(win, 8, 3, "Status: " + ("[confirmed]" if f.confirmed else "[unconfirmed]"),
          curses.color_pair(C_DONE) if f.confirmed else curses.color_pair(C_WARN))

        try:
            win.hline(9, 1, curses.ACS_HLINE, modal_w - 2)
        except curses.error:
            pass

        W(win, 10, 3, "g: generate    e: enter manually    ENTER: confirm    ESC: back",
          curses.color_pair(C_HEADING))
        W(win, 11, 3, "s: show/hide value",
          curses.color_pair(C_NORMAL))

        win.refresh()
        key = win.getch()

        if key in (ord("g"), ord("G")):
            f.value = f.generate()
            f.confirmed = False

        elif key in (ord("e"), ord("i")):
            f.value = prompt_input(stdscr, modal_y + modal_h + 1, modal_x, modal_w, f)
            f.confirmed = False

        elif key in (ord("s"), ord("S")):
            f.sensitive = not f.sensitive

        elif key in (ord("\n"), ord("\r"), 10):
            if not f.value:
                f.value = f.generate()
            f.confirmed = True
            return True

        elif key in (27, curses.KEY_LEFT):  # ESC or left
            return False


def prompt_input(stdscr, y, x, w, f: SecretField) -> str:
    """Single-line input prompt drawn below the modal."""
    sh, sw = stdscr.getmaxyx()
    prompt = f"Enter value (ENTER confirm, ESC cancel): "
    input_y = min(y, sh - 2)
    input_x = max(0, x)
    input_w = min(w - 2, sw - input_x - 2)

    curses.echo()
    curses.curs_set(1)
    stdscr.addstr(input_y, input_x, " " * min(input_w + len(prompt), sw - input_x - 1))
    try:
        stdscr.addstr(input_y, input_x, prompt[:input_w])
    except curses.error:
        pass
    stdscr.refresh()

    try:
        val = stdscr.getstr(input_y, input_x + len(prompt), max(1, input_w - len(prompt))).decode("utf-8")
    except Exception:
        val = f.value

    curses.noecho()
    curses.curs_set(0)
    return val if val.strip() else f.value


# ── Main TUI loop ──────────────────────────────────────────────────────────────

def run_tui(stdscr, fields, namespace):
    curses.curs_set(0)
    curses.noecho()
    init_colors()
    stdscr.clear()
    stdscr.refresh()

    current = 0
    scroll = 0

    while True:
        stdscr.clear()
        scroll = draw_list(stdscr, fields, current, scroll, namespace)
        key = stdscr.getch()

        if key in (curses.KEY_DOWN, ord("j"), ord("J")):
            current = min(len(fields) - 1, current + 1)

        elif key in (curses.KEY_UP, ord("k"), ord("K")):
            current = max(0, current - 1)

        elif key in (ord("\n"), ord("\r"), 10, curses.KEY_RIGHT):
            open_modal(stdscr, fields[current])
            if fields[current].confirmed and current < len(fields) - 1:
                current += 1

        elif key in (ord("G"),):
            for f in fields:
                if not f.confirmed:
                    f.value = f.generate()

        elif key in (ord("q"), ord("Q"), 27):
            return False

        if all(f.confirmed for f in fields):
            return True


# ── Confirmation screen ────────────────────────────────────────────────────────

def confirm_screen(stdscr, namespace, n_secrets):
    sh, sw = stdscr.getmaxyx()
    init_colors()

    win_h, win_w = 14, min(sw - 8, 64)
    win_y = max(0, (sh - win_h) // 2)
    win_x = max(0, (sw - win_w) // 2)

    win = curses.newwin(win_h, win_w, win_y, win_x)
    box(win)

    title = " All secrets confirmed "
    W(win, 0, max(1, (win_w - len(title)) // 2), title, curses.color_pair(C_TITLE) | curses.A_BOLD)

    lines = [
        "",
        f"  Ready to write {n_secrets} secrets to:",
        f"  namespace: {namespace}",
        "",
        "  IMPORTANT: Store all values in a password",
        "  manager before proceeding. They cannot be",
        "  recovered from the cluster afterwards.",
        "",
        "  w  Write to cluster",
        "  x  Export CSV, then write",
        "  q  Abort",
    ]
    for i, line in enumerate(lines):
        W(win, 1 + i, 0, line[:win_w - 1], curses.color_pair(C_NORMAL))

    win.refresh()

    while True:
        key = win.getch()
        if key in (ord("w"), ord("W")):
            return "write"
        if key in (ord("x"), ord("X")):
            return "export_write"
        if key in (ord("q"), ord("Q"), 27):
            return "abort"


# ── kubectl / export ───────────────────────────────────────────────────────────

def group_fields(fields):
    groups = {}
    for f in fields:
        secret_name, key = f.key.split("/", 1)
        groups.setdefault(secret_name, {})[key] = f.value
    return groups


def apply_secrets(groups, namespace, release, dry_run):
    for secret_name, kv in groups.items():
        literals = []
        for k, v in kv.items():
            literals.append(f"--from-literal={k}={v!r}")

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

    # TLS handled by manage-secrets.sh
    tls_cmd = (
        f"NAMESPACE={namespace} bash helm/metranova/scripts/manage-secrets.sh bootstrap"
    )
    if dry_run:
        print(f"# TLS secret — run: {tls_cmd}")
    else:
        print(f"\n  TLS secret: run manage-secrets.sh to generate")
        print(f"  $ {tls_cmd}")


def export_csv(fields, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Secret", "Key", "Value", "Notes"])
        for field in fields:
            secret_name, key = field.key.split("/", 1)
            writer.writerow([secret_name, key, field.value, field.description.split("\n")[0]])
    print(f"Exported to {path} — import into your password manager, then delete this file.")


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
        apply_secrets(groups, args.namespace, args.release, args.dry_run)
        print("\nDone.")
        return

    completed = curses.wrapper(run_tui, fields, args.namespace)

    if not completed:
        print("Aborted — no secrets written.")
        sys.exit(0)

    groups = group_fields(fields)
    action = curses.wrapper(confirm_screen, args.namespace, len(groups))

    if action == "abort":
        print("Aborted — no secrets written.")
        sys.exit(0)

    if action == "export_write" or args.export_csv:
        csv_path = args.export_csv or f"metranova-secrets-{args.namespace}.csv"
        export_csv(fields, csv_path)

    apply_secrets(groups, args.namespace, args.release, args.dry_run)
    print("\nDone. Run 'manage-secrets.sh check' to verify.")


if __name__ == "__main__":
    main()
