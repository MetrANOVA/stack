"""Shared fixtures for stack tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "docker"))


MINIMAL_REALM = {
    "realm": "test",
    "roles": {
        "realm": [
            {"name": "admin"},
            {"name": "operator"},
            {"name": "viewer"},
        ]
    },
    "users": [
        {"username": "alice", "enabled": True, "realmRoles": ["admin", "operator"]},
        {"username": "bob", "enabled": True, "realmRoles": ["viewer"]},
        {"username": "disabled_user", "enabled": False, "realmRoles": ["admin"]},
        {"username": "norole_user", "enabled": True, "realmRoles": ["some_other_role"]},
    ],
    "clients": [],
}


PLACEHOLDER_REALM = {
    "realm": "test",
    "clients": [
        {"clientId": "envoy", "secret": "PLACEHOLDER_ENVOY_SECRET"},
        {"clientId": "grafana", "secret": "PLACEHOLDER_GRAFANA_SECRET"},
    ],
    "components": {
        "org.keycloak.storage.UserStorageProvider": [
            {"config": {"bindCredential": ["PLACEHOLDER_LDAP_BIND_PASSWORD"]}}
        ]
    },
    "sslRequired": "PLACEHOLDER_DOMAIN",
}


@pytest.fixture()
def realm_json(tmp_path: Path) -> Path:
    p = tmp_path / "realm.json"
    p.write_text(json.dumps(MINIMAL_REALM, indent=2))
    return p


@pytest.fixture()
def placeholder_realm_json(tmp_path: Path) -> Path:
    p = tmp_path / "realm-placeholders.json"
    p.write_text(json.dumps(PLACEHOLDER_REALM, indent=2))
    return p


@pytest.fixture()
def sample_env_file(tmp_path: Path) -> Path:
    p = tmp_path / "test.env"
    p.write_text(
        "# A comment\n"
        "\n"
        "KEY1=value1\n"
        "KEY2=value2 # inline comment\n"
        "KEY3=value with spaces\n"
    )
    return p
