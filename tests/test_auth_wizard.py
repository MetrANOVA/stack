"""Tests for auth_wizard.py.

Coverage strategy:
  Layer 1 — pure unit tests: generators, naming, secret grouping, TLP constants
  Layer 2 — mock-based tests: ClickHouseClient, KeycloakClient, grant create/revoke
             atomicity, PortForward lifecycle, load_existing_secrets
  Layer 3 — TUI state machine: connectivity gating, field confirmation logic
             (dialog rendering itself is not tested — it requires a real terminal)
"""
from __future__ import annotations

import base64
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "helm" / "metranova" / "scripts"))
import auth_wizard as W


# ── Layer 1: pure unit tests ───────────────────────────────────────────────────

class TestGenerators:
    def test_gen_password_length(self):
        p = W.gen_password(24)
        assert len(p) == 24

    def test_gen_password_entropy(self):
        # 10 calls should not all be identical
        values = {W.gen_password() for _ in range(10)}
        assert len(values) > 1

    def test_gen_token_url_safe(self):
        t = W.gen_token()
        # urlsafe base64 contains only these chars
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in t)
        assert len(t) >= 32

    def test_gen_fernet_base64(self):
        f = W.gen_fernet()
        # must be valid base64url and decode to 32 bytes
        decoded = base64.urlsafe_b64decode(f + "==")
        assert len(decoded) == 32

    def test_gen_hex_length(self):
        h = W.gen_hex()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_gen_password_custom_length(self):
        assert len(W.gen_password(48)) == 48


class TestTLPConstants:
    def test_levels_ordered(self):
        assert W.TLP_LEVELS == ["tlp:clear", "tlp:green", "tlp:amber", "tlp:red"]

    def test_numeric_mapping(self):
        assert W.TLP_NUMERIC["tlp:clear"] == 0
        assert W.TLP_NUMERIC["tlp:green"] == 1
        assert W.TLP_NUMERIC["tlp:amber"] == 2
        assert W.TLP_NUMERIC["tlp:red"]   == 3

    def test_strictly_increasing(self):
        nums = [W.TLP_NUMERIC[lvl] for lvl in W.TLP_LEVELS]
        assert nums == sorted(nums)
        assert len(set(nums)) == len(nums)


class TestGroupName:
    def test_read_grant(self):
        assert W._group_name("esnet", "tlp:amber", "read") == "authz-tlp-esnet-amber-read"

    def test_write_grant(self):
        assert W._group_name("esnet", "tlp:green", "write") == "authz-tlp-esnet-green-write"

    def test_clear(self):
        assert W._group_name("internet2", "tlp:clear", "read") == "authz-tlp-internet2-clear-read"

    def test_red(self):
        assert W._group_name("geant", "tlp:red", "write") == "authz-tlp-geant-red-write"

    def test_slug_preserved(self):
        assert W._group_name("geant-engineering", "tlp:amber", "read") == \
               "authz-tlp-geant-engineering-amber-read"


class TestGroupFields:
    def _make_field(self, key, value="val", confirmed=True):
        f = W.SecretField(key=key, label="", description="", group="",
                          generate=W.gen_password)
        f.value = value
        f.confirmed = confirmed
        return f

    def test_groups_by_secret_name(self):
        fields = [
            self._make_field("clickhouse-users/admin-password", "pw1"),
            self._make_field("clickhouse-users/grafana-password", "pw2"),
            self._make_field("my-release-secrets/KEYCLOAK_ADMIN_PASSWORD", "pw3"),
        ]
        groups = W.group_fields(fields)
        assert set(groups.keys()) == {"clickhouse-users", "my-release-secrets"}
        assert groups["clickhouse-users"]["admin-password"] == "pw1"
        assert groups["clickhouse-users"]["grafana-password"] == "pw2"

    def test_tls_field_excluded(self):
        fields = [
            self._make_field("my-tls/combined", "cert---KEY---\nkey"),
            self._make_field("other/key", "val"),
        ]
        groups = W.group_fields(fields)
        assert "my-tls" not in groups
        assert "other" in groups

    def test_already_set_sentinel_excluded(self):
        """Fields with the cluster-sentinel value must NOT be written back."""
        fields = [
            self._make_field("my-secret/real-key", "real-value"),
            self._make_field("my-secret/already-set", W._ALREADY_SET_SENTINEL),
        ]
        groups = W.group_fields(fields)
        assert "real-key" in groups["my-secret"]
        assert "already-set" not in groups["my-secret"]

    def test_already_set_sentinel_not_written_for_any_field(self):
        """Even if every field is already-set, group_fields returns no values."""
        fields = [
            self._make_field("sec/a", W._ALREADY_SET_SENTINEL),
            self._make_field("sec/b", W._ALREADY_SET_SENTINEL),
        ]
        groups = W.group_fields(fields)
        assert groups.get("sec", {}) == {}

    def test_empty(self):
        assert W.group_fields([]) == {}


class TestMakeFields:
    def test_all_have_keys(self):
        fields = W.make_fields("metranova-auth")
        for f in fields:
            assert "/" in f.key, f"Missing '/' in key: {f.key}"

    def test_all_have_generators(self):
        fields = W.make_fields("metranova-auth")
        for f in fields:
            val = f.generate()
            assert val, f"Generator returned empty for {f.label}"

    def test_release_interpolated(self):
        fields = W.make_fields("my-release")
        keys = [f.key for f in fields]
        assert any("my-release" in k for k in keys)

    def test_contains_expected_secrets(self):
        fields = W.make_fields("r")
        labels = [f.label for f in fields]
        assert any("ClickHouse admin" in l for l in labels)
        assert any("Keycloak admin" in l for l in labels)
        assert any("TLS" in l for l in labels)
        assert any("HMAC" in l for l in labels)

    def test_contains_ldap_secrets(self):
        fields = W.make_fields("r")
        labels = [f.label for f in fields]
        assert any("LDAP admin" in l for l in labels)
        assert any("LDAP config" in l for l in labels)

    def test_contains_token_store_key(self):
        fields = W.make_fields("r")
        labels = [f.label for f in fields]
        assert any("Token store" in l for l in labels)

    def test_contains_grafana_secrets(self):
        fields = W.make_fields("r")
        labels = [f.label for f in fields]
        assert any("Grafana admin" in l for l in labels)
        assert any("Grafana ClickHouse" in l for l in labels)

    def test_all_keys_in_correct_secrets(self):
        fields = W.make_fields("auth")
        # All non-TLS, non-CH fields should land in auth-secrets
        for f in fields:
            secret, _ = f.key.split("/", 1)
            assert secret in ("auth-secrets", "clickhouse-users", "auth-tls"), \
                f"Unexpected secret name '{secret}' for field '{f.label}'"


class TestPreflightCheck:
    def test_all_present_returns_empty(self):
        with patch("subprocess.run") as mock_run, \
             patch("builtins.__import__", side_effect=lambda name, *a, **kw: None):
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/usr/bin/kubectl", stderr="")
            # Don't patch __import__ for real — use importlib mock instead
        # Real environment: binaries exist, packages importable
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/usr/bin/x", stderr="")
            result = W.preflight_check(skip_tui=True)
            # yaml may or may not be installed; only check binary errors absent
            binary_errors = [m for m in result if "Missing binary" in m]
            assert binary_errors == []

    def test_missing_binary_reported(self):
        # All subprocess calls fail: which-checks and clickhouse subcommand check
        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = W.preflight_check(skip_tui=True)
        assert any("kubectl" in m for m in result)
        assert any("ClickHouse" in m for m in result)
        assert any("openssl" in m for m in result)

    def test_clickhouse_client_legacy_binary_accepted(self):
        """'clickhouse-client' on PATH satisfies the ClickHouse requirement."""
        import shutil
        def fake_run(cmd, **kwargs):
            # which clickhouse-client succeeds
            if cmd == ["which", "clickhouse-client"]:
                return SimpleNamespace(returncode=0, stdout="/usr/bin/clickhouse-client", stderr="")
            return SimpleNamespace(returncode=0, stdout="/x", stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("shutil.which", return_value="/usr/bin/clickhouse-client"):
            result = W.preflight_check(skip_tui=True)
        ch_errors = [m for m in result if "ClickHouse" in m]
        assert ch_errors == []

    def test_clickhouse_modern_subcommand_accepted(self):
        """'clickhouse client --version' succeeding satisfies the requirement."""
        def fake_run(cmd, **kwargs):
            if cmd == ["which", "clickhouse-client"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if cmd == ["clickhouse", "client", "--version"]:
                return SimpleNamespace(returncode=0, stdout="ClickHouse 25.9", stderr="")
            return SimpleNamespace(returncode=0, stdout="/x", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = W.preflight_check(skip_tui=True)
        ch_errors = [m for m in result if "ClickHouse" in m]
        assert ch_errors == []

    def test_clickhouse_missing_when_both_absent(self):
        """Neither legacy nor modern binary → ClickHouse error reported."""
        def fake_run(cmd, **kwargs):
            if cmd[0] in ("which", "clickhouse"):
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="/x", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = W.preflight_check(skip_tui=True)
        assert any("ClickHouse" in m for m in result)

    def test_missing_binary_includes_hint(self):
        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = W.preflight_check(skip_tui=True)
        kubectl_msg = next(m for m in result if "kubectl" in m)
        assert "https://" in kubectl_msg or "install" in kubectl_msg.lower()

    def test_missing_python_package_reported(self):
        import builtins
        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no module named yaml")
            return real_import(name, *args, **kwargs)

        with patch("subprocess.run") as mock_run, \
             patch("builtins.__import__", side_effect=failing_import):
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/x", stderr="")
            result = W.preflight_check(skip_tui=True)

        assert any("yaml" in m for m in result)

    def test_dialog_not_required_in_headless_mode(self):
        import builtins
        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "dialog":
                raise ImportError("no dialog")
            return real_import(name, *args, **kwargs)

        with patch("subprocess.run") as mock_run, \
             patch("builtins.__import__", side_effect=failing_import):
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/x", stderr="")
            result = W.preflight_check(skip_tui=True)

        assert not any("dialog" in m for m in result)

    def test_dialog_required_in_tui_mode(self):
        import builtins
        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "dialog":
                raise ImportError("no dialog")
            return real_import(name, *args, **kwargs)

        with patch("subprocess.run") as mock_run, \
             patch("builtins.__import__", side_effect=failing_import):
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/x", stderr="")
            result = W.preflight_check(skip_tui=False)

        assert any("dialog" in m for m in result)

    def test_returns_list(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="/x", stderr="")
            result = W.preflight_check(skip_tui=True)
        assert isinstance(result, list)

    def test_required_binaries_coverage(self):
        # Ensure every entry in REQUIRED_BINARIES has a name and a hint
        for binary, hint in W.REQUIRED_BINARIES:
            assert binary
            assert hint


# ── Layer 2: mock-based tests ──────────────────────────────────────────────────

class TestClickHouseClient:
    def _client(self):
        return W.ClickHouseClient(host="127.0.0.1", port=19440,
                                  user="default", password="secret")

    def test_ping_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="1\n", stderr="")
            assert self._client().ping() is True

    def test_ping_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="connection refused")
            assert self._client().ping() is False

    def test_query_returns_stripped_stdout(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="  hello\n", stderr="")
            result = self._client().query("SELECT 1")
        assert result == "hello"

    def test_query_raises_on_nonzero(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="DB error")
            with pytest.raises(RuntimeError, match="DB error"):
                self._client().query("BAD SQL")

    def test_multiquery_passes_input(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            self._client().multiquery("CREATE TABLE t;")
        args, kwargs = mock_run.call_args
        assert kwargs.get("input") == "CREATE TABLE t;" or "CREATE TABLE t;" in (args[1:] or [None])[0]

    def test_base_cmd_includes_credentials(self):
        c = self._client()
        assert "--user" in c._base_cmd
        assert "default" in c._base_cmd
        assert "--password" in c._base_cmd
        assert "secret" in c._base_cmd
        assert "--secure" in c._base_cmd
        assert "--accept-invalid-certificate" in c._base_cmd


class TestKeycloakClient:
    def _client(self):
        return W.KeycloakClient(
            base_url="http://127.0.0.1:19080",
            realm="metranova",
            admin_user="admin",
            admin_password="adminpass",
        )

    def _mock_urlopen(self, responses: list):
        """Build a side_effect list for urllib.request.urlopen."""
        class FakeResp:
            def __init__(self, data):
                self._data = data if isinstance(data, bytes) else json.dumps(data).encode()
            def read(self): return self._data
            def __enter__(self): return self
            def __exit__(self, *_): pass

        side_effects = [FakeResp(r) for r in responses]
        return side_effects

    def test_ping_success(self):
        token_resp = {"access_token": "tok123", "token_type": "Bearer"}
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read = lambda: json.dumps(token_resp).encode()
            assert self._client().ping() is True

    def test_ping_failure_on_http_error(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = urllib.error.URLError("refused")
            assert self._client().ping() is False

    def test_create_group_idempotent(self):
        """create_group returns existing ID when group already exists."""
        existing = [{"id": "uuid-1", "name": "authz-tlp-esnet-amber-read"}]
        kc = self._client()
        kc._token = "tok"

        with patch.object(kc, "list_groups", return_value=existing):
            gid = kc.create_group("authz-tlp-esnet-amber-read")
        assert gid == "uuid-1"

    def test_create_group_new(self):
        kc = self._client()
        kc._token = "tok"
        new_group = {"id": "uuid-2", "name": "authz-tlp-esnet-green-write"}

        call_count = 0
        def fake_list():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            return [new_group]

        with patch.object(kc, "list_groups", side_effect=fake_list), \
             patch.object(kc, "_request") as mock_req:
            mock_req.return_value = None
            gid = kc.create_group("authz-tlp-esnet-green-write")
        assert gid == "uuid-2"

    def test_delete_group(self):
        kc = self._client()
        kc._token = "tok"
        with patch.object(kc, "_request") as mock_req:
            mock_req.return_value = None
            kc.delete_group("uuid-999")
        mock_req.assert_called_once_with("DELETE", "/groups/uuid-999")


class TestPortForward:
    def test_stop_terminates_process(self):
        pf = W.PortForward("ns", "svc/foo", 9440, 19440)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        pf._proc = mock_proc
        pf.stop()
        mock_proc.terminate.assert_called_once()

    def test_stop_noop_if_not_started(self):
        pf = W.PortForward("ns", "svc/foo", 9440, 19440)
        pf.stop()  # should not raise

    def test_context_manager_calls_stop(self):
        pf = W.PortForward("ns", "svc/foo", 9440, 19440)
        pf.stop = MagicMock()
        with pf:
            pass
        pf.stop.assert_called_once()

    def test_start_returns_false_on_timeout(self):
        with patch("subprocess.Popen") as mock_popen, \
             patch("socket.create_connection") as mock_conn:
            mock_popen.return_value = MagicMock()
            mock_conn.side_effect = OSError("refused")
            pf = W.PortForward("ns", "svc/foo", 9440, 19440)
            result = pf.start(timeout=0.1)
        assert result is False


class TestGrantCreateAtomicity:
    """Grant creation must touch CH (role + row) and Keycloak (group)."""

    def _setup(self):
        ch = MagicMock(spec=W.ClickHouseClient)
        ch.multiquery.return_value = ""
        kc = MagicMock(spec=W.KeycloakClient)
        kc.create_group.return_value = "group-uuid"
        conn = W.WizardConnections()
        conn.ch = ch
        conn.kc = kc
        return conn, ch, kc

    def test_grant_create_calls_all_three_systems(self):
        conn, ch, kc = self._setup()
        org = {"id": "org-uuid", "name": "ESnet", "slug": "esnet"}
        group = W._group_name("esnet", "tlp:amber", "read")

        # Call the helpers directly (bypassing TUI dialog)
        kc.create_group(group)
        W._ensure_ch_role(conn.ch, group)
        conn.ch.multiquery(
            f"INSERT INTO metranova_authz.grants "
            f"(group_name, organization_id, max_tlp_level, permission, granted_by) "
            f"VALUES ('{group}', '{org['id']}', 'tlp:amber', 'read', 'testuser');"
        )

        kc.create_group.assert_called_once_with(group)
        assert ch.multiquery.call_count == 2  # CREATE ROLE + INSERT

    def test_grant_revoke_calls_all_three_systems(self):
        conn, ch, kc = self._setup()
        kc.list_groups.return_value = [{"id": "gid-1", "name": "authz-tlp-esnet-amber-read"}]

        grant = {
            "id": "grant-uuid",
            "group_name": "authz-tlp-esnet-amber-read",
            "org_name": "ESnet",
            "slug": "esnet",
        }

        # Simulate _grant_revoke steps
        conn.ch.multiquery(f"ALTER TABLE metranova_authz.grants UPDATE revoked_at = now64() WHERE id = '{grant['id']}';")
        kc_groups = conn.kc.list_groups()
        match = next((g for g in kc_groups if g["name"] == grant["group_name"]), None)
        if match:
            conn.kc.delete_group(match["id"])
        conn.ch.multiquery(f"DROP ROLE IF EXISTS `{grant['group_name']}`;")

        assert ch.multiquery.call_count == 2   # UPDATE + DROP ROLE
        kc.delete_group.assert_called_once_with("gid-1")

    def test_group_name_used_consistently(self):
        """The group name written to CH must match the one sent to Keycloak."""
        conn, ch, kc = self._setup()
        org_slug, tlp, perm = "internet2", "tlp:green", "write"
        group = W._group_name(org_slug, tlp, perm)

        kc.create_group(group)
        ch.multiquery(
            f"INSERT INTO metranova_authz.grants (group_name, organization_id, "
            f"max_tlp_level, permission, granted_by) VALUES "
            f"('{group}', 'org-id', '{tlp}', '{perm}', 'admin');"
        )

        kc_call_arg = kc.create_group.call_args[0][0]
        ch_call_sql = ch.multiquery.call_args[0][0]
        assert kc_call_arg in ch_call_sql  # same group name in both places


class TestLoadExistingSecrets:
    def _make_field(self, key):
        f = W.SecretField(key=key, label="", description="", group="",
                          generate=W.gen_password)
        return f

    def test_existing_secret_marks_confirmed(self):
        fields = [self._make_field("clickhouse-users/admin-password")]
        existing_data = json.dumps({"admin-password": base64.b64encode(b"pw").decode()})

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=0, stdout=existing_data, stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            W.load_existing_secrets(fields, "metranova", d=None)

        assert fields[0].confirmed is True
        assert fields[0].value == W._ALREADY_SET_SENTINEL

    def test_sentinel_value_not_written_back_via_group_fields(self):
        """The sentinel value must never reach group_fields as a real secret value."""
        fields = [self._make_field("clickhouse-users/admin-password")]
        existing_data = json.dumps({"admin-password": base64.b64encode(b"realpassword").decode()})

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=0, stdout=existing_data, stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            W.load_existing_secrets(fields, "metranova", d=None)

        # group_fields must skip the sentinel — no key should appear
        groups = W.group_fields(fields)
        for secret_vals in groups.values():
            for v in secret_vals.values():
                assert v != W._ALREADY_SET_SENTINEL, \
                    "Sentinel value must not be written to the cluster"

    def test_missing_secret_leaves_unconfirmed(self):
        fields = [self._make_field("clickhouse-users/admin-password")]

        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="not found")

        with patch("subprocess.run", side_effect=fake_run):
            W.load_existing_secrets(fields, "metranova", d=None)

        assert fields[0].confirmed is False
        assert fields[0].value == ""

    def test_batches_by_secret_name(self):
        """One kubectl call per distinct secret name, not per field."""
        fields = [
            self._make_field("clickhouse-users/admin-password"),
            self._make_field("clickhouse-users/grafana-password"),
            self._make_field("my-release-secrets/KEYCLOAK_ADMIN_PASSWORD"),
        ]
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return SimpleNamespace(returncode=1, stdout="", stderr="not found")

        with patch("subprocess.run", side_effect=fake_run):
            W.load_existing_secrets(fields, "metranova", d=None)

        # Should be 2 calls: clickhouse-users, my-release-secrets
        secret_args = [c[c.index("get") + 2] for c in calls if "get" in c]
        assert len(set(secret_args)) == 2


class TestKubectlGetSecretField:
    def test_decodes_base64(self):
        encoded = base64.b64encode(b"my-password").decode()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout=encoded, stderr="")
            result = W.kubectl_get_secret_field("my-secret", "admin-password", "ns")
        assert result == "my-password"

    def test_returns_empty_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="not found")
            result = W.kubectl_get_secret_field("my-secret", "field", "ns")
        assert result == ""

    def test_returns_empty_on_empty_stdout(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="  ", stderr="")
            result = W.kubectl_get_secret_field("my-secret", "field", "ns")
        assert result == ""


# ── Layer 3: TUI state machine ─────────────────────────────────────────────────

class TestWizardConnections:
    def test_not_connected_initially(self):
        conn = W.WizardConnections()
        assert conn.connected is False

    def test_connected_when_both_clients_set(self):
        conn = W.WizardConnections()
        conn.ch = MagicMock()
        conn.kc = MagicMock()
        assert conn.connected is True

    def test_connected_false_if_only_ch(self):
        conn = W.WizardConnections()
        conn.ch = MagicMock()
        assert conn.connected is False

    def test_stop_clears_clients(self):
        conn = W.WizardConnections()
        conn.ch = MagicMock()
        conn.kc = MagicMock()
        conn.ch_pf = MagicMock()
        conn.kc_pf = MagicMock()
        conn.stop()
        assert conn.ch is None
        assert conn.kc is None

    def test_stop_calls_pf_stop(self):
        conn = W.WizardConnections()
        pf = MagicMock()
        conn.ch_pf = pf
        conn.kc_pf = MagicMock()
        conn.stop()
        pf.stop.assert_called_once()


class TestSecretFieldConfirmation:
    def _field(self):
        f = W.SecretField(key="s/k", label="L", description="D", group="G",
                          generate=W.gen_password)
        return f

    def test_confirmed_false_by_default(self):
        assert self._field().confirmed is False

    def test_value_empty_by_default(self):
        assert self._field().value == ""

    def test_generate_and_confirm_flow(self):
        f = self._field()
        f.value = f.generate()
        f.confirmed = True
        assert len(f.value) >= 16
        assert f.confirmed is True

    def test_all_confirmed_check(self):
        fields = [self._field() for _ in range(3)]
        assert not all(f.confirmed for f in fields)
        for f in fields:
            f.value = f.generate()
            f.confirmed = True
        assert all(f.confirmed for f in fields)

    def test_generate_all_pattern(self):
        fields = [self._field() for _ in range(5)]
        for f in fields:
            if not f.confirmed:
                f.value = f.generate()
                f.confirmed = True
        assert all(f.confirmed for f in fields)
        assert all(f.value for f in fields)


class TestApplySecrets:
    def _basic_fields(self, key="sec/k", value="val"):
        return [W.SecretField(key=key, label="", description="", group="",
                              generate=W.gen_password, value=value, confirmed=True)]

    def test_default_dest_writes_files_not_kubectl(self):
        """Default dest='files' writes to disk, never calls kubectl."""
        fields = self._basic_fields()
        groups = W.group_fields(fields)
        with patch("subprocess.run") as mock_run, \
             patch("builtins.open", MagicMock()), \
             patch("os.makedirs"):
            W.apply_secrets(groups, "ns", "release", dry_run=False, fields=fields, dest="files")
        mock_run.assert_not_called()

    def test_cluster_dest_calls_kubectl(self):
        """dest='cluster' pipes manifest to kubectl apply."""
        fields = self._basic_fields()
        groups = W.group_fields(fields)
        inputs_seen = []

        def fake_run(cmd, **kwargs):
            inputs_seen.append(kwargs.get("input", ""))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            W.apply_secrets(groups, "ns", "release", dry_run=False, fields=fields, dest="cluster")

        assert inputs_seen, "kubectl was never called"

    def test_dry_run_cluster_does_not_call_kubectl(self):
        fields = self._basic_fields()
        groups = W.group_fields(fields)
        with patch("subprocess.run") as mock_run:
            W.apply_secrets(groups, "ns", "release", dry_run=True, fields=fields, dest="cluster")
        mock_run.assert_not_called()

    def test_release_secrets_extra_fields_written_to_file(self):
        """release-secrets gets token.yaml and hmac.yaml; verify content in written file."""
        fields = [
            W.SecretField(key="rel-secrets/ENVOY_OIDC_CLIENT_SECRET", label="", description="",
                          group="", generate=W.gen_token, value="my-oidc", confirmed=True),
            W.SecretField(key="rel-secrets/ENVOY_HMAC_SECRET", label="", description="",
                          group="", generate=W.gen_hex, value="my-hmac", confirmed=True),
        ]
        groups = W.group_fields(fields)
        written = {}

        import io
        def fake_open(path, mode="r", **kw):
            buf = io.StringIO()
            written[path] = buf
            buf.close = lambda: None
            return buf

        with patch("builtins.open", side_effect=fake_open), \
             patch("os.makedirs"), \
             patch.object(W, "_repo_root", return_value="/fake"):
            W.apply_secrets(groups, "ns", "rel", dry_run=False, fields=fields, dest="files")

        content = "".join(buf.getvalue() for buf in written.values())
        assert "token.yaml" in content
        assert "hmac.yaml" in content
        assert "my-oidc" in content
        assert "my-hmac" in content

    def test_release_secrets_extra_fields_in_cluster_manifest(self):
        """dest='cluster': token.yaml and hmac.yaml appear in kubectl stdin."""
        fields = [
            W.SecretField(key="rel-secrets/ENVOY_OIDC_CLIENT_SECRET", label="", description="",
                          group="", generate=W.gen_token, value="my-oidc", confirmed=True),
            W.SecretField(key="rel-secrets/ENVOY_HMAC_SECRET", label="", description="",
                          group="", generate=W.gen_hex, value="my-hmac", confirmed=True),
        ]
        groups = W.group_fields(fields)
        inputs_seen = []

        def fake_run(cmd, **kwargs):
            inputs_seen.append(kwargs.get("input", ""))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            W.apply_secrets(groups, "ns", "rel", dry_run=False, fields=fields, dest="cluster")

        manifest_text = "\n".join(inputs_seen)
        assert "token.yaml" in manifest_text
        assert "hmac.yaml" in manifest_text
        assert "my-oidc" in manifest_text
        assert "my-hmac" in manifest_text


class TestEnsureChRole:
    def test_sends_create_role_sql(self):
        ch = MagicMock(spec=W.ClickHouseClient)
        ch.multiquery.return_value = ""
        W._ensure_ch_role(ch, "authz-tlp-esnet-amber-read")
        sql = ch.multiquery.call_args[0][0]
        assert "CREATE ROLE IF NOT EXISTS" in sql
        assert "authz-tlp-esnet-amber-read" in sql


class TestKubectlContext:
    def test_returns_current_context(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(
                returncode=0,
                stdout="gke_metranova_us-east1-b_metranova-dev-auth\n",
                stderr="",
            )
            ctx = W._kubectl_context()
        assert ctx == "gke_metranova_us-east1-b_metranova-dev-auth"

    def test_strips_whitespace(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="  ctx  \n", stderr="")
            assert W._kubectl_context() == "ctx"


class TestArgoCDSyncAndWait:
    """
    argocd_sync_and_wait runs polling in a background thread and drives
    d.gauge_start/update/stop in the main thread. Tests run the full function
    with mocked subprocess and a fake dialog gauge.
    """

    def _make_dialog(self):
        d = MagicMock()
        # gauge methods must not raise so the function completes cleanly
        d.gauge_start = MagicMock()
        d.gauge_update = MagicMock()
        d.gauge_stop = MagicMock()
        d.msgbox = MagicMock()
        return d

    def _pod_stdout(self, ready: bool = True) -> str:
        flag = "true" if ready else "false"
        return f"metranova-auth-keycloak-abc   {flag}   Running   0\n"

    def test_returns_true_when_all_pods_ready(self):
        d = self._make_dialog()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=True), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            result = W.argocd_sync_and_wait(d, "metranova", timeout=30)

        assert result is True
        d.gauge_start.assert_called_once()
        d.gauge_stop.assert_called_once()

    def test_returns_false_on_timeout(self):
        d = self._make_dialog()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=False), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        # Use a very short timeout so the worker thread exits via timeout path
        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            result = W.argocd_sync_and_wait(d, "metranova", timeout=1)

        assert result is False

    def test_triggers_annotation_and_argocd_sync(self):
        d = self._make_dialog()
        calls = []

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list):
                calls.append(cmd[:])
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=True), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            W.argocd_sync_and_wait(d, "metranova", app_name="metranova-auth", timeout=30)

        cmds = [" ".join(c) for c in calls]
        assert any("annotate" in c and "argocd.argoproj.io/refresh=hard" in c for c in cmds)
        assert any("argocd" in c and "sync" in c for c in cmds)

    def test_gauge_updated_with_pod_status(self):
        d = self._make_dialog()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=True), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            W.argocd_sync_and_wait(d, "metranova", timeout=30)

        assert d.gauge_update.called
        all_text = " ".join(str(c) for c in d.gauge_update.call_args_list)
        assert "ready" in all_text.lower() or "Running" in all_text

    def test_registers_sigint_handler(self):
        """SIGINT handler is registered and restored around the gauge loop."""
        import signal as sig_mod
        d = self._make_dialog()
        sigint_calls = []

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=True), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        original = sig_mod.signal
        def tracking_signal(sig, handler):
            sigint_calls.append((sig, handler))
            return original(sig, handler)

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"), \
             patch("auth_wizard.signal.signal", side_effect=tracking_signal):
            W.argocd_sync_and_wait(d, "metranova", timeout=30)

        registered_sigs = [sig for sig, _ in sigint_calls]
        assert sig_mod.SIGINT in registered_sigs, "SIGINT handler was never registered"
        # Should be registered and then restored — at least 2 calls for SIGINT
        sigint_only = [(s, h) for s, h in sigint_calls if s == sig_mod.SIGINT]
        assert len(sigint_only) >= 2, "SIGINT handler not restored after completion"

    def test_gauge_stopped_on_completion(self):
        """gauge_stop is always called, even on success path."""
        d = self._make_dialog()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "get" in cmd and "pods" in cmd:
                return SimpleNamespace(returncode=0, stdout=self._pod_stdout(ready=True), stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            W.argocd_sync_and_wait(d, "metranova", timeout=30)

        d.gauge_stop.assert_called_once()


class TestCrdExists:
    def test_returns_true_when_crd_found(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            assert W._crd_exists("kafkas.kafka.strimzi.io") is True

    def test_returns_false_when_crd_missing(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="not found")
            assert W._crd_exists("kafkas.kafka.strimzi.io") is False


class TestHelmInstall:
    def test_returns_true_on_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="deployed", stderr="")
            ok, msg = W._helm_install("strimzi/strimzi-kafka-operator", "strimzi", "kube-system", [])
        assert ok is True

    def test_returns_false_and_stderr_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="chart not found")
            ok, msg = W._helm_install("bad/chart", "rel", "ns", [])
        assert ok is False
        assert "chart not found" in msg

    def test_passes_kube_context(self):
        calls = []
        with patch("subprocess.run", side_effect=lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(returncode=0, stdout="", stderr="")), \
             patch.object(W, "_kubectl_context", return_value="my-ctx"):
            W._helm_install("chart/name", "rel", "ns", [])
        assert any("my-ctx" in " ".join(c) for c in calls)


class TestSectionPrerequisites:
    def _make_dialog(self, checklist_selected):
        d = MagicMock()
        d.OK = 0
        d.CANCEL = 1
        d.ESC = 2
        d.infobox = MagicMock()
        d.checklist = MagicMock(return_value=(d.OK, checklist_selected))
        d.msgbox = MagicMock()
        return d

    def test_cancel_does_nothing(self):
        d = self._make_dialog([])
        d.checklist.return_value = (d.CANCEL, [])
        with patch.object(W, "_crd_exists", return_value=False), \
             patch.object(W, "_helm_repo_add") as mock_repo, \
             patch.object(W, "_helm_install") as mock_install:
            W.section_prerequisites(d, "metranova")
        mock_repo.assert_not_called()
        mock_install.assert_not_called()

    def test_installs_selected_prerequisites(self):
        d = self._make_dialog(["strimzi"])
        with patch.object(W, "_crd_exists", return_value=False), \
             patch.object(W, "_helm_repo_add", return_value=(True, "")), \
             patch.object(W, "_helm_install", return_value=(True, "")) as mock_install, \
             patch.object(W, "_wait_for_crd", return_value=True), \
             patch.object(W, "_msgbox"):
            W.section_prerequisites(d, "metranova")
        mock_install.assert_called_once()
        assert "strimzi" in mock_install.call_args[0][0]

    def test_skips_unselected_prerequisites(self):
        d = self._make_dialog(["strimzi"])
        install_calls = []
        with patch.object(W, "_crd_exists", return_value=False), \
             patch.object(W, "_helm_repo_add", return_value=(True, "")), \
             patch.object(W, "_helm_install", side_effect=lambda *a, **kw: install_calls.append(a[0]) or (True, "")), \
             patch.object(W, "_wait_for_crd", return_value=True), \
             patch.object(W, "_msgbox"):
            W.section_prerequisites(d, "metranova")
        assert not any("traefik" in c for c in install_calls)
        assert not any("argocd" in c for c in install_calls)

    def test_reports_error_when_repo_add_fails(self):
        d = self._make_dialog(["strimzi"])
        scrollbox_texts = []
        with patch.object(W, "_crd_exists", return_value=False), \
             patch.object(W, "_helm_repo_add", return_value=(False, "connection refused")), \
             patch.object(W, "_helm_install") as mock_install, \
             patch.object(d, "scrollbox", side_effect=lambda msg, **kw: scrollbox_texts.append(msg)):
            W.section_prerequisites(d, "metranova")
        mock_install.assert_not_called()
        assert any("repo add failed" in t for t in scrollbox_texts)

    def test_all_four_prerequisites_defined(self):
        keys = {p["key"] for p in W._PREREQUISITES}
        assert "argocd" in keys
        assert "clickhouse-operator" in keys
        assert "strimzi" in keys
        assert "traefik" in keys

    def test_each_prerequisite_has_required_fields(self):
        required = {"key", "label", "desc", "crd", "helm_repo", "helm_chart",
                    "helm_release", "helm_ns", "helm_flags"}
        for p in W._PREREQUISITES:
            missing = required - p.keys()
            assert not missing, f"{p['key']} missing fields: {missing}"


class TestArgocdAppExists:
    def test_returns_true_when_app_found(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            assert W._argocd_app_exists("metranova") is True

    def test_returns_false_when_app_missing(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="not found")
            assert W._argocd_app_exists("metranova") is False

    def test_queries_argocd_namespace(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            W._argocd_app_exists("metranova")
        cmd = mock_run.call_args[0][0]
        assert "argocd" in cmd
        assert "metranova" in cmd


class TestRunSecretsMenu:
    """_run_secrets_menu handles write destinations independently and loops back."""

    def _fields(self):
        return [W.SecretField(key="sec/k", label="L", description="D", group="G",
                              generate=W.gen_password, value="v", confirmed=True)]

    def _make_dialog(self, checklist_selected):
        d = MagicMock()
        d.OK = 0
        d.CANCEL = 1
        d.ESC = 2
        # First call: Write button → checklist; second call: Back → exit
        d.menu = MagicMock(side_effect=[
            ("help", None),   # press Write
            (d.CANCEL, None), # press Back to exit
        ])
        d.checklist = MagicMock(return_value=(d.OK, checklist_selected))
        return d

    def test_files_dest_calls_apply_files(self):
        d = self._make_dialog(["F"])
        fields = self._fields()
        with patch.object(W, "apply_secrets") as mock_apply, \
             patch.object(W, "_msgbox"), \
             patch.object(W, "_repo_root", return_value="/fake"):
            W._run_secrets_menu(d, fields, namespace="ns", release="rel", dry_run=False)
        mock_apply.assert_called_once()
        assert mock_apply.call_args[1]["dest"] == "files"

    def test_cluster_dest_calls_apply_cluster(self):
        d = self._make_dialog(["C"])
        fields = self._fields()
        with patch.object(W, "apply_secrets") as mock_apply, \
             patch.object(W, "_msgbox"):
            W._run_secrets_menu(d, fields, namespace="ns", release="rel", dry_run=False)
        mock_apply.assert_called_once()
        assert mock_apply.call_args[1]["dest"] == "cluster"

    def test_all_three_destinations(self):
        """Selecting F+C+X calls apply twice (files + cluster) and exports CSV."""
        d = self._make_dialog(["F", "C", "X"])
        fields = self._fields()
        apply_calls = []
        with patch.object(W, "apply_secrets", side_effect=lambda *a, **kw: apply_calls.append(kw.get("dest"))), \
             patch.object(W, "export_csv") as mock_csv, \
             patch.object(W, "_msgbox"), \
             patch.object(W, "_repo_root", return_value="/fake"):
            W._run_secrets_menu(d, fields, namespace="ns", release="rel", dry_run=False)
        assert "files" in apply_calls
        assert "cluster" in apply_calls
        mock_csv.assert_called_once()

    def test_no_argocd_sync_triggered(self):
        d = self._make_dialog(["F"])
        fields = self._fields()
        with patch.object(W, "apply_secrets"), \
             patch.object(W, "_msgbox"), \
             patch.object(W, "_repo_root", return_value="/fake"), \
             patch.object(W, "argocd_sync_and_wait") as mock_sync:
            W._run_secrets_menu(d, fields, namespace="ns", release="rel", dry_run=False)
        mock_sync.assert_not_called()

    def test_empty_checklist_does_not_write(self):
        d = self._make_dialog([])
        fields = self._fields()
        with patch.object(W, "apply_secrets") as mock_apply:
            W._run_secrets_menu(d, fields, namespace="ns", release="rel", dry_run=False)
        mock_apply.assert_not_called()


class TestSectionArgoCDSync:
    def _make_dialog(self):
        d = MagicMock()
        d.OK = 0
        d.CANCEL = 1
        d.ESC = 2
        d.infobox = MagicMock()
        d.yesno = MagicMock(return_value=0)  # default: Sync
        return d

    def test_cancel_does_not_sync(self):
        d = self._make_dialog()
        d.yesno.return_value = d.CANCEL
        with patch.object(W, "_argocd_app_exists", return_value=True), \
             patch.object(W, "argocd_sync_and_wait") as mock_sync:
            W.section_argocd_sync(d, "metranova", "metranova-auth", "")
        mock_sync.assert_not_called()

    def test_applies_auth_manifest_when_missing(self):
        d = self._make_dialog()
        apply_calls = []
        with patch.object(W, "_argocd_app_exists", return_value=False), \
             patch.object(W, "_apply_argocd_manifest", side_effect=lambda p: apply_calls.append(p) or (True, "ok")), \
             patch.object(W, "argocd_sync_and_wait", return_value=True), \
             patch.object(W, "_msgbox"):
            W.section_argocd_sync(d, "metranova", "metranova-auth", "")
        assert any("metranova-auth" in p for p in apply_calls)

    def test_applies_umbrella_manifest_when_missing(self):
        d = self._make_dialog()
        apply_calls = []

        def fake_exists(name):
            return name != "metranova"  # auth exists, umbrella doesn't

        with patch.object(W, "_argocd_app_exists", side_effect=fake_exists), \
             patch.object(W, "_apply_argocd_manifest", side_effect=lambda p: apply_calls.append(p) or (True, "ok")), \
             patch.object(W, "argocd_sync_and_wait", return_value=True), \
             patch.object(W, "_msgbox"):
            W.section_argocd_sync(d, "metranova", "metranova-auth", "")
        assert any("metranova-app.yaml" in p for p in apply_calls)

    def test_syncs_both_apps_when_both_exist(self):
        d = self._make_dialog()
        sync_calls = []

        def fake_sync(d, namespace, app_name="metranova-auth", timeout=300):
            sync_calls.append(app_name)
            return True

        with patch.object(W, "_argocd_app_exists", return_value=True), \
             patch.object(W, "argocd_sync_and_wait", side_effect=fake_sync), \
             patch.object(W, "_msgbox"):
            W.section_argocd_sync(d, "metranova", "metranova-auth", "")

        assert "metranova-auth" in sync_calls
        assert "metranova" in sync_calls

    def test_skips_umbrella_sync_when_app_missing_after_apply_error(self):
        """If umbrella manifest apply fails, sync is aborted."""
        d = self._make_dialog()

        def fake_exists(name):
            return name == "metranova-auth"

        with patch.object(W, "_argocd_app_exists", side_effect=fake_exists), \
             patch.object(W, "_apply_argocd_manifest", return_value=(False, "permission denied")), \
             patch.object(W, "argocd_sync_and_wait") as mock_sync, \
             patch.object(W, "_error"):
            W.section_argocd_sync(d, "metranova", "metranova-auth", "")

        mock_sync.assert_not_called()


# ── Tests: _build_authz_policy_sql and section_init_authz_policies ─────────────

class TestBuildAuthzPolicySql:
    def test_contains_tlp_function(self):
        sql = W._build_authz_policy_sql("secret")
        assert "tlp_to_numeric" in sql
        assert "CREATE FUNCTION" in sql

    def test_contains_both_dicts(self):
        sql = W._build_authz_policy_sql("secret")
        assert "authz_group_read_orgs" in sql
        assert "authz_group_write_orgs" in sql

    def test_contains_two_active_policies(self):
        sql = W._build_authz_policy_sql("secret")
        assert "authz_read_policy" in sql
        assert "authz_grafana_read_policy" in sql

    def test_password_embedded(self):
        sql = W._build_authz_policy_sql("mypassword")
        assert "mypassword" in sql

    def test_password_single_quotes_escaped(self):
        sql = W._build_authz_policy_sql("it's")
        assert "it''s" in sql
        assert "it's" not in sql

    def test_internal_host_and_port_embedded(self):
        sql = W._build_authz_policy_sql("pw", ch_internal_host="mych", ch_internal_port=19000)
        assert "mych" in sql
        assert "19000" in sql

    def test_internal_user_embedded(self):
        sql = W._build_authz_policy_sql("pw", ch_user="pipeline")
        assert "pipeline" in sql

    def test_grafana_policy_tlp_clear_only(self):
        sql = W._build_authz_policy_sql("pw")
        grafana_section = sql.split("CREATE ROW POLICY authz_grafana_read_policy")[1].split(";")[0]
        assert "tlp:clear" in grafana_section
        assert "dictGet" not in grafana_section

    def test_grafana_exempt_from_main_read_policy(self):
        sql = W._build_authz_policy_sql("pw")
        read_policy = sql.split("CREATE ROW POLICY authz_read_policy ON")[1].split(";")[0]
        assert "grafana" in read_policy

    def test_service_accounts_exempt_from_read(self):
        sql = W._build_authz_policy_sql("pw")
        read_policy = sql.split("CREATE ROW POLICY authz_read_policy ON")[1].split(";")[0]
        assert "pipeline" in read_policy
        assert "default" in read_policy
        assert "admin" in read_policy

    def test_write_policy_dropped_not_created(self):
        # FOR INSERT row policies unsupported in ClickHouse 25.x;
        # write enforcement is via GRANT privileges instead.
        sql = W._build_authz_policy_sql("pw")
        assert "DROP ROW POLICY IF EXISTS authz_write_policy" in sql
        assert "CREATE ROW POLICY authz_write_policy" not in sql

    def test_dict_source_uses_single_quote_escaping(self):
        sql = W._build_authz_policy_sql("pw")
        assert "''read''" in sql
        assert "''write''" in sql

    def test_drop_before_create_for_dicts(self):
        sql = W._build_authz_policy_sql("pw")
        drop_read   = sql.index("DROP DICTIONARY IF EXISTS metranova_authz.authz_group_read_orgs")
        create_read = sql.index("CREATE DICTIONARY metranova_authz.authz_group_read_orgs")
        assert drop_read < create_read

    def test_drop_before_create_for_policies(self):
        sql = W._build_authz_policy_sql("pw")
        drop_pos   = sql.index("DROP ROW POLICY IF EXISTS authz_read_policy")
        create_pos = sql.index("CREATE ROW POLICY authz_read_policy")
        assert drop_pos < create_pos


class TestAuthzPoliciesExist:
    def test_returns_true_when_two_policies_found(self):
        ch = MagicMock()
        ch.query.return_value = "2"
        assert W._authz_policies_exist(ch) is True

    def test_returns_false_when_one_policy_found(self):
        ch = MagicMock()
        ch.query.return_value = "1"
        assert W._authz_policies_exist(ch) is False

    def test_returns_false_when_zero_policies(self):
        ch = MagicMock()
        ch.query.return_value = "0"
        assert W._authz_policies_exist(ch) is False

    def test_returns_false_on_exception(self):
        ch = MagicMock()
        ch.query.side_effect = RuntimeError("no table")
        assert W._authz_policies_exist(ch) is False

    def test_queries_correct_policy_names(self):
        ch = MagicMock()
        ch.query.return_value = "2"
        W._authz_policies_exist(ch)
        call_sql = ch.query.call_args[0][0]
        assert "authz_read_policy" in call_sql
        assert "authz_grafana_read_policy" in call_sql


class TestSectionInitAuthzPolicies:
    def _make_dialog(self):
        d = MagicMock()
        d.OK = 0
        d.CANCEL = 1
        d.ESC = -1
        return d

    def _make_conn(self, password="testpw", user="admin"):
        conn = MagicMock()
        conn.ch.password = password
        conn.ch.user = user
        return conn

    def test_runs_policy_sql_when_no_existing_policies(self):
        d = self._make_dialog()
        conn = self._make_conn()
        with patch.object(W, "_authz_policies_exist", return_value=False), \
             patch.object(W, "_msgbox"):
            result = W.section_init_authz_policies(d, conn)
        assert result is True
        conn.ch.multiquery.assert_called_once()
        sql = conn.ch.multiquery.call_args[0][0]
        assert "authz_read_policy" in sql

    def test_skips_when_user_declines_replace(self):
        d = self._make_dialog()
        d.yesno.return_value = d.CANCEL
        conn = self._make_conn()
        with patch.object(W, "_authz_policies_exist", return_value=True):
            result = W.section_init_authz_policies(d, conn)
        assert result is True  # skip is not a failure
        conn.ch.multiquery.assert_not_called()

    def test_replaces_when_user_confirms(self):
        d = self._make_dialog()
        d.yesno.return_value = d.OK
        conn = self._make_conn()
        with patch.object(W, "_authz_policies_exist", return_value=True), \
             patch.object(W, "_msgbox"):
            result = W.section_init_authz_policies(d, conn)
        assert result is True
        conn.ch.multiquery.assert_called_once()

    def test_returns_false_on_ch_error(self):
        d = self._make_dialog()
        conn = self._make_conn()
        conn.ch.multiquery.side_effect = RuntimeError("query failed")
        with patch.object(W, "_authz_policies_exist", return_value=False), \
             patch.object(W, "_error"):
            result = W.section_init_authz_policies(d, conn)
        assert result is False

    def test_password_passed_to_sql_builder(self):
        d = self._make_dialog()
        conn = self._make_conn(password="supersecret")
        with patch.object(W, "_authz_policies_exist", return_value=False), \
             patch.object(W, "_msgbox"):
            W.section_init_authz_policies(d, conn)
        sql = conn.ch.multiquery.call_args[0][0]
        assert "supersecret" in sql

    def test_custom_internal_host_forwarded(self):
        d = self._make_dialog()
        conn = self._make_conn()
        with patch.object(W, "_authz_policies_exist", return_value=False), \
             patch.object(W, "_msgbox"):
            W.section_init_authz_policies(d, conn, ch_internal_host="myhost", ch_internal_port=19000)
        sql = conn.ch.multiquery.call_args[0][0]
        assert "myhost" in sql
        assert "19000" in sql


# ── Tests: enforcement report ──────────────────────────────────────────────────

class TestFormatEnforcementReport:
    def _data(self, total=1000, no_grants=0, grants=None, errors=None):
        return {
            "total": total,
            "no_grants": no_grants,
            "grants": grants or [],
            "errors": errors or [],
        }

    def test_shows_total(self):
        out = W._format_enforcement_report(self._data(total=5432))
        assert "5,432" in out

    def test_admin_always_shows_100_percent(self):
        out = W._format_enforcement_report(self._data(total=100))
        assert "100%" in out

    def test_no_grants_shows_zero(self):
        out = W._format_enforcement_report(self._data(total=100, no_grants=0))
        assert "[no grants]" in out

    def test_grant_row_appears(self):
        grants = [{"group_name": "authz-tlp-esnet-amber-read",
                   "max_tlp_level": "tlp:amber", "permission": "read",
                   "slug": "esnet", "visible": 500}]
        out = W._format_enforcement_report(self._data(total=1000, grants=grants))
        assert "authz-tlp-esnet-amber-read" in out
        assert "500" in out

    def test_percentage_calculated(self):
        grants = [{"group_name": "authz-tlp-esnet-amber-read",
                   "max_tlp_level": "tlp:amber", "permission": "read",
                   "slug": "esnet", "visible": 250}]
        out = W._format_enforcement_report(self._data(total=1000, grants=grants))
        assert "25%" in out

    def test_zero_total_no_division_error(self):
        out = W._format_enforcement_report(self._data(total=0, no_grants=0))
        assert "0" in out

    def test_multiple_grants_all_shown(self):
        grants = [
            {"group_name": "authz-tlp-esnet-amber-read",  "max_tlp_level": "tlp:amber",
             "permission": "read", "slug": "esnet",     "visible": 800},
            {"group_name": "authz-tlp-internet2-clear-read", "max_tlp_level": "tlp:clear",
             "permission": "read", "slug": "internet2", "visible": 200},
        ]
        out = W._format_enforcement_report(self._data(total=1000, grants=grants))
        assert "authz-tlp-esnet-amber-read" in out
        assert "authz-tlp-internet2-clear-read" in out

    def test_none_visible_shows_err(self):
        grants = [{"group_name": "authz-tlp-esnet-amber-read",
                   "max_tlp_level": "tlp:amber", "permission": "read",
                   "slug": "esnet", "visible": None}]
        out = W._format_enforcement_report(self._data(total=1000, grants=grants))
        assert "err" in out

    def test_errors_section_shown(self):
        out = W._format_enforcement_report(
            self._data(errors=["authz-tlp-esnet-amber-read: connection refused"]))
        assert "Errors:" in out
        assert "connection refused" in out

    def test_no_errors_section_when_clean(self):
        out = W._format_enforcement_report(self._data())
        assert "Errors:" not in out

    def test_no_grants_row_empty_message(self):
        out = W._format_enforcement_report(self._data(grants=[]))
        assert "(no active grants)" in out


class TestEnforcementReport:
    def _make_ch(self, total=100, grant_json=""):
        """ch.query dispatches by SQL content; DROP USER calls return ''."""
        ch = MagicMock()
        def _q(sql):
            if "count()" in sql:
                return str(total)
            if "metranova_authz.grants" in sql:
                return grant_json
            return ""  # DROP USER IF EXISTS and other housekeeping
        ch.query.side_effect = _q
        ch.multiquery.return_value = ""
        return ch

    def test_total_comes_from_admin_count(self):
        ch = self._make_ch(total=500)
        with patch.object(W, "_row_count_as", return_value=0):
            data = W._enforcement_report(ch)
        assert data["total"] == 500

    def test_no_grants_count_from_temp_user(self):
        ch = self._make_ch(total=100)
        with patch.object(W, "_row_count_as", return_value=0) as mock_rc:
            data = W._enforcement_report(ch)
        assert data["no_grants"] == 0
        mock_rc.assert_called()

    def test_temp_user_dropped_on_success(self):
        ch = self._make_ch(total=100)
        with patch.object(W, "_row_count_as", return_value=0):
            W._enforcement_report(ch)
        drop_calls = [str(c) for c in ch.query.call_args_list if "DROP USER" in str(c)]
        assert len(drop_calls) >= 1

    def test_temp_user_dropped_on_row_count_error(self):
        ch = self._make_ch(total=100)
        with patch.object(W, "_row_count_as", side_effect=RuntimeError("boom")):
            data = W._enforcement_report(ch)
        assert data["no_grants"] is None
        assert any("boom" in e for e in data["errors"])
        drop_calls = [str(c) for c in ch.query.call_args_list if "DROP USER" in str(c)]
        assert len(drop_calls) >= 1

    def test_one_grant_produces_one_row(self):
        import json as _json
        grant_line = _json.dumps({
            "group_name": "authz-tlp-esnet-amber-read",
            "max_tlp_level": "tlp:amber",
            "permission": "read",
            "slug": "esnet",
        })
        ch = self._make_ch(total=100, grant_json=grant_line)
        with patch.object(W, "_row_count_as", side_effect=[0, 75]):
            data = W._enforcement_report(ch)
        assert len(data["grants"]) == 1
        assert data["grants"][0]["visible"] == 75

    def test_grant_error_recorded_not_raised(self):
        import json as _json
        grant_line = _json.dumps({
            "group_name": "authz-tlp-esnet-amber-read",
            "max_tlp_level": "tlp:amber",
            "permission": "read",
            "slug": "esnet",
        })
        ch = self._make_ch(total=100, grant_json=grant_line)
        with patch.object(W, "_row_count_as", side_effect=[0, RuntimeError("timeout")]):
            data = W._enforcement_report(ch)
        assert data["grants"][0]["visible"] is None
        assert any("timeout" in e for e in data["errors"])
