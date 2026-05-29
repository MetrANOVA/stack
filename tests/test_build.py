"""Unit tests for docker/build.py pure functions."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from build import (
    copytree_if_missing,
    extract_realm_users,
    generate_self_signed_cert,
    load_config,
    load_env_file,
    patch_realm_json,
    render_jinja2_file,
    set_env_value,
    sync_missing_files,
    write_envoy_sds_secret,
)


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_valid_yaml(self, tmp_path: Path):
        p = tmp_path / "config.yml"
        p.write_text(yaml.dump({"auth": {"enabled": True}}))
        result = load_config(p)
        assert result == {"auth": {"enabled": True}}

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yml")

    def test_non_dict_raises(self, tmp_path: Path):
        p = tmp_path / "bad.yml"
        p.write_text("- a list\n- not a dict\n")
        with pytest.raises(ValueError, match="YAML object"):
            load_config(p)


# ---------------------------------------------------------------------------
# load_env_file
# ---------------------------------------------------------------------------


class TestLoadEnvFile:
    def test_parses_key_value(self, sample_env_file: Path):
        result = load_env_file(sample_env_file)
        assert result["KEY1"] == "value1"
        assert result["KEY3"] == "value with spaces"

    def test_strips_inline_comments(self, sample_env_file: Path):
        result = load_env_file(sample_env_file)
        assert result["KEY2"] == "value2"

    def test_skips_comments_and_blanks(self, sample_env_file: Path):
        result = load_env_file(sample_env_file)
        assert len(result) == 3

    def test_missing_file_returns_empty(self, tmp_path: Path):
        result = load_env_file(tmp_path / "nope.env")
        assert result == {}


# ---------------------------------------------------------------------------
# set_env_value
# ---------------------------------------------------------------------------


class TestSetEnvValue:
    def test_updates_existing_key(self, sample_env_file: Path):
        set_env_value(sample_env_file, "KEY1", "new_value")
        result = load_env_file(sample_env_file)
        assert result["KEY1"] == "new_value"

    def test_appends_new_key(self, sample_env_file: Path):
        set_env_value(sample_env_file, "KEY_NEW", "added")
        result = load_env_file(sample_env_file)
        assert result["KEY_NEW"] == "added"

    def test_preserves_other_lines(self, sample_env_file: Path):
        set_env_value(sample_env_file, "KEY1", "changed")
        result = load_env_file(sample_env_file)
        assert result["KEY2"] == "value2"
        assert result["KEY3"] == "value with spaces"


# ---------------------------------------------------------------------------
# extract_realm_users
# ---------------------------------------------------------------------------


class TestExtractRealmUsers:
    def test_returns_enabled_users_with_roles(self, realm_json: Path):
        users = extract_realm_users(realm_json)
        names = [u["username"] for u in users]
        assert "alice" in names
        assert "bob" in names

    def test_skips_disabled_users(self, realm_json: Path):
        users = extract_realm_users(realm_json)
        names = [u["username"] for u in users]
        assert "disabled_user" not in names

    def test_skips_users_with_no_known_roles(self, realm_json: Path):
        users = extract_realm_users(realm_json)
        names = [u["username"] for u in users]
        assert "norole_user" not in names

    def test_primary_role_priority(self, realm_json: Path):
        users = extract_realm_users(realm_json)
        alice = next(u for u in users if u["username"] == "alice")
        assert alice["primary_role"] == "admin"

    def test_single_role_user(self, realm_json: Path):
        users = extract_realm_users(realm_json)
        bob = next(u for u in users if u["username"] == "bob")
        assert bob["primary_role"] == "viewer"
        assert bob["roles"] == ["viewer"]


# ---------------------------------------------------------------------------
# patch_realm_json
# ---------------------------------------------------------------------------


class TestPatchRealmJson:
    def test_replaces_placeholders(self, placeholder_realm_json: Path):
        patch_realm_json(
            placeholder_realm_json,
            domain="example.com",
            envoy_secret="env_sec",
            grafana_secret="graf_sec",
            ldap_bind_password="ldap_pass",
        )
        data = json.loads(placeholder_realm_json.read_text())
        assert data["sslRequired"] == "example.com"
        assert data["clients"][0]["secret"] == "env_sec"
        assert data["clients"][1]["secret"] == "graf_sec"
        cred = data["components"]["org.keycloak.storage.UserStorageProvider"][0]
        assert cred["config"]["bindCredential"] == ["ldap_pass"]

    def test_empty_ldap_password_preserves_placeholder(self, placeholder_realm_json: Path):
        patch_realm_json(
            placeholder_realm_json,
            domain="example.com",
            envoy_secret="e",
            grafana_secret="g",
            ldap_bind_password="",
        )
        text = placeholder_realm_json.read_text()
        assert "PLACEHOLDER_LDAP_BIND_PASSWORD" in text


# ---------------------------------------------------------------------------
# copytree_if_missing / sync_missing_files
# ---------------------------------------------------------------------------


class TestCopyTreeIfMissing:
    def test_copies_when_dst_absent(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "file.txt").write_text("hello")
        dst = tmp_path / "dst"
        copytree_if_missing(src, dst)
        assert (dst / "file.txt").read_text() == "hello"

    def test_noop_when_dst_exists(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "file.txt").write_text("hello")
        dst = tmp_path / "dst"
        dst.mkdir()
        (dst / "other.txt").write_text("existing")
        copytree_if_missing(src, dst)
        assert not (dst / "file.txt").exists()

    def test_missing_src_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            copytree_if_missing(tmp_path / "nonexistent", tmp_path / "dst")


class TestSyncMissingFiles:
    def test_copies_only_absent_files(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "new.txt").write_text("new")
        (src / "existing.txt").write_text("src_version")
        dst = tmp_path / "dst"
        dst.mkdir()
        (dst / "existing.txt").write_text("dst_version")
        sync_missing_files(src, dst)
        assert (dst / "new.txt").read_text() == "new"
        assert (dst / "existing.txt").read_text() == "dst_version"

    def test_missing_src_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            sync_missing_files(tmp_path / "nonexistent", tmp_path / "dst")


# ---------------------------------------------------------------------------
# generate_self_signed_cert
# ---------------------------------------------------------------------------


class TestGenerateSelfSignedCert:
    def test_produces_pem_files(self, tmp_path: Path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        generate_self_signed_cert("test.local", cert, key)
        assert cert.exists()
        assert key.exists()
        assert b"BEGIN CERTIFICATE" in cert.read_bytes()
        assert b"BEGIN RSA PRIVATE KEY" in key.read_bytes()

    def test_san_includes_domain_and_localhost(self, tmp_path: Path):
        from cryptography import x509

        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        generate_self_signed_cert("myhost.io", cert_path, key_path)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "myhost.io" in dns_names
        assert "localhost" in dns_names


# ---------------------------------------------------------------------------
# write_envoy_sds_secret
# ---------------------------------------------------------------------------


class TestWriteEnvoySdsSecret:
    def test_output_format(self, tmp_path: Path):
        p = tmp_path / "secret.yaml"
        write_envoy_sds_secret(p, "my-secret", "secret-value")
        text = p.read_text()
        assert "name: my-secret" in text
        assert 'inline_string: "secret-value"' in text
        assert "GenericSecret" in text or "generic_secret" in text


# ---------------------------------------------------------------------------
# render_jinja2_file
# ---------------------------------------------------------------------------


class TestRenderJinja2File:
    def test_substitutes_variables(self, tmp_path: Path):
        tmpl = tmp_path / "template.txt.j2"
        tmpl.write_text("Hello {{ name }}, port={{ port }}")
        out = tmp_path / "output.txt"
        render_jinja2_file(tmpl, out, name="world", port=8080)
        assert out.read_text() == "Hello world, port=8080"

    def test_undefined_variable_raises(self, tmp_path: Path):
        from jinja2 import UndefinedError

        tmpl = tmp_path / "bad.j2"
        tmpl.write_text("{{ missing_var }}")
        out = tmp_path / "out.txt"
        with pytest.raises(UndefinedError):
            render_jinja2_file(tmpl, out)
