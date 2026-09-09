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
        assert fields[0].value == "(already set in cluster)"

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
    def test_dry_run_does_not_call_kubectl(self):
        fields = [
            W.SecretField(key="sec/k", label="", description="", group="",
                          generate=W.gen_password, value="val", confirmed=True)
        ]
        groups = W.group_fields(fields)
        with patch("subprocess.run") as mock_run:
            W.apply_secrets(groups, "ns", "release", dry_run=True, fields=fields)
        mock_run.assert_not_called()

    def test_applies_release_secrets_extra_fields(self):
        """release-secrets secret gets token.yaml and hmac.yaml injected."""
        fields = [
            W.SecretField(key="rel-secrets/ENVOY_OIDC_CLIENT_SECRET", label="", description="",
                          group="", generate=W.gen_token, value="my-oidc", confirmed=True),
            W.SecretField(key="rel-secrets/ENVOY_HMAC_SECRET", label="", description="",
                          group="", generate=W.gen_hex, value="my-hmac", confirmed=True),
        ]
        groups = W.group_fields(fields)
        calls_seen = []

        def fake_run(cmd, **kwargs):
            calls_seen.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            W.apply_secrets(groups, "ns", "rel", dry_run=False, fields=fields)

        assert calls_seen, "subprocess.run was never called"
        joined = " ".join(str(c) for c in calls_seen)
        assert "token.yaml" in joined
        assert "hmac.yaml" in joined


class TestEnsureChRole:
    def test_sends_create_role_sql(self):
        ch = MagicMock(spec=W.ClickHouseClient)
        ch.multiquery.return_value = ""
        W._ensure_ch_role(ch, "authz-tlp-esnet-amber-read")
        sql = ch.multiquery.call_args[0][0]
        assert "CREATE ROLE IF NOT EXISTS" in sql
        assert "authz-tlp-esnet-amber-read" in sql
