"""Helm chart validation tests (no cluster needed)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CHART_DIR = REPO_ROOT / "helm" / "charts" / "auth"
VALUES_FILE = CHART_DIR / "values.yaml.example"


def _helm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["helm", *args],
        capture_output=True,
        text=True,
    )


def _template_docs() -> list[dict]:
    result = _helm("template", "test", str(CHART_DIR), "-f", str(VALUES_FILE))
    assert result.returncode == 0, f"helm template failed:\n{result.stderr}"
    docs = list(yaml.safe_load_all(result.stdout))
    return [d for d in docs if d is not None]


class TestHelmLint:
    def test_lint_passes(self):
        result = _helm("lint", str(CHART_DIR), "-f", str(VALUES_FILE))
        assert result.returncode == 0, f"helm lint failed:\n{result.stderr}"


class TestHelmTemplate:
    def test_renders_without_error(self):
        result = _helm("template", "test", str(CHART_DIR), "-f", str(VALUES_FILE))
        assert result.returncode == 0, f"helm template failed:\n{result.stderr}"

    def test_resource_count(self):
        docs = _template_docs()
        kinds = [d["kind"] for d in docs]
        assert kinds.count("Deployment") == 6
        assert kinds.count("Service") == 6
        assert kinds.count("ConfigMap") == 4
        assert kinds.count("Secret") == 2
        assert kinds.count("NetworkPolicy") == 2
        assert kinds.count("PersistentVolumeClaim") == 3
        assert kinds.count("ServiceAccount") == 1
        assert len(docs) == 24

    def test_substitutions(self):
        docs = _template_docs()
        envoy_cm = next(
            d for d in docs
            if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-envoy")
        )
        envoy_yaml = envoy_cm["data"]["envoy.yaml"]
        assert "metranova.io" in envoy_yaml or "localhost" in envoy_yaml

        ldap_cm = next(
            d for d in docs
            if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-ldap")
        )
        ldif = ldap_cm["data"]["bootstrap.ldif"]
        assert "dc=metranova,dc=io" in ldif

    def test_keycloak_realm_substituted(self):
        docs = _template_docs()
        kc_cm = next(
            d for d in docs
            if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-keycloak")
        )
        realm_json = kc_cm["data"]["metranova-realm.json"]
        assert "PLACEHOLDER_" not in realm_json


class TestTLSSecret:
    def test_default_creates_tls_secret(self):
        docs = _template_docs()
        tls_secrets = [
            d for d in docs
            if d["kind"] == "Secret" and d.get("type") == "kubernetes.io/tls"
        ]
        assert len(tls_secrets) == 1

    def test_existing_tls_secret_skips_creation(self):
        result = _helm(
            "template", "test", str(CHART_DIR),
            "-f", str(VALUES_FILE),
            "--set", "envoy.tls.existingTLSSecret=my-cert",
        )
        assert result.returncode == 0
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        tls_secrets = [
            d for d in docs
            if d["kind"] == "Secret" and d.get("type") == "kubernetes.io/tls"
        ]
        assert len(tls_secrets) == 0
        envoy_dep = next(
            d for d in docs
            if d["kind"] == "Deployment" and d["metadata"]["name"].endswith("-envoy")
        )
        volumes = envoy_dep["spec"]["template"]["spec"]["volumes"]
        tls_vol = next(v for v in volumes if v["name"] == "envoy-tls")
        assert tls_vol["secret"]["secretName"] == "my-cert"


class TestHelmDryRun:
    def test_dry_run_install(self):
        result = _helm(
            "install", "--dry-run", "test",
            str(CHART_DIR), "-f", str(VALUES_FILE),
        )
        assert result.returncode == 0, f"helm dry-run failed:\n{result.stderr}"


# ── Umbrella chart tests ───────────────────────────────────────────────────────

UMBRELLA_DIR = REPO_ROOT / "helm" / "metranova"
AUTH_CHART_DIR = REPO_ROOT / "helm" / "charts" / "auth"


@pytest.fixture(scope="session")
def umbrella_fixture(tmp_path_factory):
    """
    Build a minimal umbrella fixture with only the auth subchart so tests run
    without needing the full set of upstream charts (clickhouse, kafka, etc).
    """
    import shutil

    d = tmp_path_factory.mktemp("umbrella")

    # Copy auth chart directly into charts/ — helm finds it without dep build
    charts_dir = d / "charts"
    charts_dir.mkdir()
    shutil.copytree(AUTH_CHART_DIR, charts_dir / "metranova-auth")

    # Chart.yaml referencing the already-present subchart (no repository needed)
    (d / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: metranova-test\n"
        "version: 0.1.0\n"
        "dependencies:\n"
        "  - name: metranova-auth\n"
        "    alias: auth\n"
        "    version: '0.1.0'\n"
        "    condition: auth.enabled\n"
    )

    # Build values: auth subchart defaults prefixed with "auth:", plus overrides.
    # Read the auth chart's values.yaml.example and nest it under "auth:".
    auth_defaults = yaml.safe_load(VALUES_FILE.read_text())
    umbrella_values = {
        "auth": {
            **auth_defaults,
            "enabled": True,
            "domain": "test.example.com",
        }
    }
    import json as _json
    # Write as YAML (use json-safe subset via yaml dump)
    (d / "values.yaml").write_text(yaml.dump(umbrella_values, default_flow_style=False))

    return d


class TestUmbrellaLint:
    def test_lint_passes(self, umbrella_fixture):
        result = subprocess.run(
            ["helm", "lint", str(umbrella_fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"helm lint failed:\n{result.stderr}"


class TestUmbrellaTemplate:
    def _docs(self, umbrella_fixture):
        result = subprocess.run(
            ["helm", "template", "test", str(umbrella_fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"helm template failed:\n{result.stderr}"
        return [d for d in yaml.safe_load_all(result.stdout) if d is not None]

    def test_renders_without_error(self, umbrella_fixture):
        result = subprocess.run(
            ["helm", "template", "test", str(umbrella_fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"helm template failed:\n{result.stderr}"

    def test_auth_resources_present(self, umbrella_fixture):
        docs = self._docs(umbrella_fixture)
        kinds = [d["kind"] for d in docs]
        assert "Deployment" in kinds
        assert "Service" in kinds
        assert "ConfigMap" in kinds

    def test_auth_deployments_have_expected_components(self, umbrella_fixture):
        docs = self._docs(umbrella_fixture)
        deployments = [d for d in docs if d["kind"] == "Deployment"]
        components = {
            d["metadata"]["labels"].get("app.kubernetes.io/component")
            for d in deployments
        }
        assert components >= {"keycloak", "envoy", "grafana", "openldap",
                              "token-store", "clickhouse-auth-proxy"}

    def test_domain_propagated(self, umbrella_fixture):
        docs = self._docs(umbrella_fixture)
        envoy_cm = next(
            (d for d in docs
             if d["kind"] == "ConfigMap"
             and d["metadata"]["name"].endswith("-envoy")),
            None,
        )
        assert envoy_cm is not None
        assert "test.example.com" in envoy_cm["data"]["envoy.yaml"]

    def test_auth_disabled_produces_no_auth_resources(self, tmp_path):
        """When auth.enabled=false, no auth resources should be rendered."""
        import shutil
        d = tmp_path
        charts_dir = d / "charts"
        charts_dir.mkdir()
        shutil.copytree(AUTH_CHART_DIR, charts_dir / "metranova-auth")
        (d / "Chart.yaml").write_text(
            "apiVersion: v2\nname: metranova-test\nversion: 0.1.0\n"
            "dependencies:\n"
            "  - name: metranova-auth\n"
            "    alias: auth\n"
            "    version: '0.1.0'\n"
            "    condition: auth.enabled\n"
        )
        (d / "values.yaml").write_text("auth:\n  enabled: false\n")
        result = subprocess.run(
            ["helm", "template", "test", str(d)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc is not None]
        assert len(docs) == 0, f"Expected no resources when auth disabled, got: {[d['kind'] for d in docs]}"
