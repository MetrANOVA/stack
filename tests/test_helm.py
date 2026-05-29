"""Helm chart validation tests (no cluster needed)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CHART_DIR = REPO_ROOT / "helm" / "auth"
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
