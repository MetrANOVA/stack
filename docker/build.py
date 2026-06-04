#!/usr/bin/env python3
"""Build docker config for enabled components."""

from __future__ import annotations

import argparse
import ipaddress
import json
import secrets as secrets_module
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, StrictUndefined

try:
    import yaml
except ImportError:  # pragma: no cover - runtime guard
    print("Missing dependency: pyyaml. Install with 'pip install pyyaml'.")
    sys.exit(1)

try:
    import datetime
    from cryptography import x509
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("Config must be a YAML object")
    return data


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def copytree_if_missing(src: Path, dst: Path) -> None:
    if dst.exists():
        return
    if not src.exists():
        raise FileNotFoundError(f"Missing source directory: {src}")
    shutil.copytree(src, dst)


def sync_missing_files(src: Path, dst: Path) -> None:
    """Copy any files from src that are absent in dst, without touching existing ones."""
    if not src.exists():
        raise FileNotFoundError(f"Missing source directory: {src}")
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.rglob("*"):
        if not item.is_file():
            continue
        target = dst / item.relative_to(src)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def remove_dir_if_exists(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def render_compose(template_dir: Path, config: Dict[str, Any], output_path: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    template = env.get_template("docker-compose.yml.j2")
    output_path.write_text(template.render(**config))


def load_env_file(path: Path) -> Dict[str, str]:
    """Parse a KEY=VALUE env file, skipping comments and blanks."""
    result: Dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            # Strip inline comments
            value = value.split(" #")[0].strip()
            result[key.strip()] = value
    return result


def set_env_value(path: Path, key: str, value: str) -> None:
    """Set KEY=value in an env file, adding the line if the key is absent."""
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    updated = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(key + "=") and not stripped.startswith("#"):
            lines[i] = f"{key}={value}\n"
            updated = True
            break
    if not updated:
        lines.append(f"{key}={value}\n")
    path.write_text("".join(lines))


def generate_self_signed_cert(domain: str, cert_path: Path, key_path: Path) -> None:
    """Generate a self-signed RSA TLS certificate for the given domain."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required for TLS cert generation. "
            "Run: pip install cryptography"
        )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    san_entries = [x509.DNSName(domain), x509.DNSName("localhost")]
    try:
        san_entries.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    except Exception:
        pass
    if domain != "localhost":
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(domain)))
        except ValueError:
            pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"Generated self-signed TLS cert for '{domain}' at {cert_path}")


def write_envoy_sds_secret(path: Path, name: str, value: str) -> None:
    """Write an Envoy SDS secret file (GenericSecret)."""
    path.write_text(
        f"resources:\n"
        f'- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret\n'
        f"  name: {name}\n"
        f"  generic_secret:\n"
        f"    secret:\n"
        f'      inline_string: "{value}"\n'
    )


def render_jinja2_file(template_path: Path, output_path: Path, **kwargs: Any) -> None:
    """Render a Jinja2 template file to an output file."""
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    template = env.get_template(template_path.name)
    output_path.write_text(template.render(**kwargs))


_ROLE_PRIORITY = {"admin": 0, "operator": 1, "viewer": 2}


def extract_realm_users(realm_path: Path) -> list[Dict[str, Any]]:
    """Return OIDC users with their primary role, parsed from a Keycloak realm JSON."""
    realm = json.loads(realm_path.read_text())
    known_roles = {r["name"] for r in realm.get("roles", {}).get("realm", [])}
    users = []
    for user in realm.get("users", []):
        if not user.get("enabled", True):
            continue
        username = user.get("username", "")
        roles = [r for r in user.get("realmRoles", []) if r in known_roles]
        if not roles:
            continue
        primary_role = min(roles, key=lambda r: _ROLE_PRIORITY.get(r, 99))
        users.append({"username": username, "roles": roles, "primary_role": primary_role})
    return users


def patch_realm_json(
    realm_path: Path,
    domain: str,
    envoy_secret: str,
    grafana_secret: str,
    ldap_bind_password: str = "",
) -> None:
    """Replace placeholder values in the Keycloak realm JSON."""
    text = realm_path.read_text()
    text = text.replace("PLACEHOLDER_DOMAIN", domain)
    text = text.replace("PLACEHOLDER_ENVOY_SECRET", envoy_secret)
    text = text.replace("PLACEHOLDER_GRAFANA_SECRET", grafana_secret)
    if ldap_bind_password:
        text = text.replace("PLACEHOLDER_LDAP_BIND_PASSWORD", ldap_bind_password)
    realm_path.write_text(text)


def bootstrap_auth(auth_dir: Path, conf_d: Path) -> None:
    """Bootstrap the auth component: generate secrets, TLS cert, and render configs."""
    # sync_missing_files (not copytree_if_missing) so new files added to conf.example
    # across phases are picked up on existing installations without clobbering edits.
    sync_missing_files(auth_dir / "conf.example", auth_dir / "conf")
    conf = auth_dir / "conf"

    # Load shared auth settings
    auth_values = load_env_file(conf / "auth.env")
    domain = auth_values.get("AUTH_DOMAIN", "localhost")
    realm = auth_values.get("AUTH_REALM", "metranova")

    # Load and update Envoy env file with generated secrets
    envoy_env_path = conf / "envoy.env"
    envoy_values = load_env_file(envoy_env_path)

    envoy_secret = envoy_values.get("ENVOY_CLIENT_SECRET", "CHANGEME")
    if not envoy_secret or envoy_secret == "CHANGEME":
        envoy_secret = secrets_module.token_hex(32)
        set_env_value(envoy_env_path, "ENVOY_CLIENT_SECRET", envoy_secret)
        print("Generated ENVOY_CLIENT_SECRET")

    envoy_hmac = envoy_values.get("ENVOY_HMAC_SECRET", "CHANGEME")
    if not envoy_hmac or envoy_hmac == "CHANGEME":
        envoy_hmac = secrets_module.token_hex(32)
        set_env_value(envoy_env_path, "ENVOY_HMAC_SECRET", envoy_hmac)
        print("Generated ENVOY_HMAC_SECRET")

    # Grafana client secret (written to grafana.env when that phase is enabled;
    # generate it now so the realm JSON can include it)
    grafana_env_path = conf / "grafana.env"
    grafana_values = load_env_file(grafana_env_path) if grafana_env_path.exists() else {}
    grafana_secret = grafana_values.get("GRAFANA_CLIENT_SECRET", "CHANGEME")
    if not grafana_secret or grafana_secret == "CHANGEME":
        grafana_secret = secrets_module.token_hex(32)
        if grafana_env_path.exists():
            set_env_value(grafana_env_path, "GRAFANA_CLIENT_SECRET", grafana_secret)
        print("Generated GRAFANA_CLIENT_SECRET")

    # Keycloak admin password
    kc_env_path = conf / "keycloak.env"
    kc_values = load_env_file(kc_env_path)
    kc_admin_password = kc_values.get("KEYCLOAK_ADMIN_PASSWORD", "CHANGEME")
    if not kc_admin_password or kc_admin_password == "CHANGEME":
        kc_admin_password = secrets_module.token_hex(16)
        set_env_value(kc_env_path, "KEYCLOAK_ADMIN_PASSWORD", kc_admin_password)
        print(f"Generated KEYCLOAK_ADMIN_PASSWORD (save this!): {kc_admin_password}")

    # OpenLDAP secrets — generated before realm patch so bindCredential can be substituted
    openldap_env_path = conf / "openldap.env"
    ldap_admin_password: str = ""
    if openldap_env_path.exists():
        ldap_values = load_env_file(openldap_env_path)
        for key in ("LDAP_ADMIN_PASSWORD", "LDAP_CONFIG_PASSWORD"):
            val = ldap_values.get(key, "CHANGEME")
            if not val or val == "CHANGEME":
                set_env_value(openldap_env_path, key, secrets_module.token_hex(16))
                print(f"Generated {key}")
        ldap_values = load_env_file(openldap_env_path)
        ldap_admin_password = ldap_values.get("LDAP_ADMIN_PASSWORD", "")
        ldap_domain = ldap_values.get("LDAP_DOMAIN", "metranova.io")
    else:
        ldap_domain = "metranova.io"
    ldap_base_dn = ",".join(f"dc={part}" for part in ldap_domain.split("."))

    # Re-copy the realm JSON template each run so new sections (e.g. LDAP federation)
    # are always present, then replace placeholders with current secrets.
    realm_template = auth_dir / "conf.example" / "keycloak" / "metranova-realm.json"
    realm_path = conf / "keycloak" / "metranova-realm.json"
    if realm_template.exists():
        ensure_dir(realm_path.parent)
        shutil.copy2(realm_template, realm_path)
        patch_realm_json(realm_path, domain, envoy_secret, grafana_secret, ldap_admin_password)
        print(f"Patched Keycloak realm JSON for domain '{domain}'")

    # Generate self-signed TLS cert
    tls_dir = conf / "tls"
    ensure_dir(tls_dir)
    if not (tls_dir / "server.crt").exists():
        generate_self_signed_cert(domain, tls_dir / "server.crt", tls_dir / "server.key")

    # Write Envoy SDS secret files
    secrets_dir = conf / "secrets"
    ensure_dir(secrets_dir)
    write_envoy_sds_secret(secrets_dir / "token.yaml", "token-secret", envoy_secret)
    write_envoy_sds_secret(secrets_dir / "hmac.yaml", "hmac-secret", envoy_hmac)

    # Render Envoy config from Jinja2 template
    envoy_conf_dir = conf / "envoy"
    ensure_dir(envoy_conf_dir)
    template_path = conf / "envoy" / "envoy.yaml.j2"
    if template_path.exists():
        render_jinja2_file(
            template_path,
            envoy_conf_dir / "envoy.yaml",
            domain=domain,
            realm=realm,
            keycloak_host="keycloak",
            keycloak_port=8080,
        )
        print("Rendered envoy.yaml")

    # Grafana admin password
    if grafana_env_path.exists():
        gf_admin = load_env_file(grafana_env_path).get("GF_SECURITY_ADMIN_PASSWORD", "CHANGEME")
        if not gf_admin or gf_admin == "CHANGEME":
            gf_admin = secrets_module.token_hex(16)
            set_env_value(grafana_env_path, "GF_SECURITY_ADMIN_PASSWORD", gf_admin)
            print(f"Generated GF_SECURITY_ADMIN_PASSWORD (save this!): {gf_admin}")

    # Render Grafana config from Jinja2 template
    grafana_conf_dir = conf / "grafana"
    ensure_dir(grafana_conf_dir)
    grafana_ini_template = auth_dir / "conf.example" / "grafana" / "grafana.ini.j2"
    if grafana_ini_template.exists():
        render_jinja2_file(
            grafana_ini_template,
            grafana_conf_dir / "grafana.ini",
            domain=domain,
            realm=realm,
            grafana_client_secret=grafana_secret,
        )
        print("Rendered grafana.ini")

    # Export auth configs for other components to consume
    auth_export_dir = conf_d / "auth"
    ensure_dir(auth_export_dir)
    (auth_export_dir / "domain").write_text(domain)
    (auth_export_dir / "realm").write_text(realm)

    # Token Store secrets
    ts_key: str = ""
    token_store_env_path = conf / "token_store.env"
    if token_store_env_path.exists():
        ts_values = load_env_file(token_store_env_path)
        ts_key = ts_values.get("TOKEN_STORE_ENCRYPTION_KEY", "CHANGEME")
        if not ts_key or ts_key == "CHANGEME":
            # Fernet key = 32 random bytes, URL-safe base64-encoded
            import base64
            ts_key = base64.urlsafe_b64encode(secrets_module.token_bytes(32)).decode()
            set_env_value(token_store_env_path, "TOKEN_STORE_ENCRYPTION_KEY", ts_key)
            print("Generated TOKEN_STORE_ENCRYPTION_KEY")
        # Keep LDAP bind password in sync with the LDAP admin password
        if ldap_admin_password and ldap_admin_password != "CHANGEME":
            set_env_value(token_store_env_path, "LDAP_BIND_PASSWORD", ldap_admin_password)

    # Portal needs the Keycloak admin password and LDAP bind credentials
    portal_env_path = conf / "portal.env"
    if portal_env_path.exists():
        set_env_value(portal_env_path, "KEYCLOAK_ADMIN_PASSWORD", kc_admin_password)
        if ldap_admin_password and ldap_admin_password != "CHANGEME":
            set_env_value(portal_env_path, "LDAP_BIND_PASSWORD", ldap_admin_password)
        if ldap_base_dn:
            set_env_value(portal_env_path, "LDAP_BASE_DN", ldap_base_dn)
            set_env_value(portal_env_path, "LDAP_BIND_DN", f"cn=admin,{ldap_base_dn}")

    # keycloak-ldap-sync needs the Keycloak admin password
    ldap_sync_env_path = conf / "keycloak_ldap_sync.env"
    if ldap_sync_env_path.exists():
        set_env_value(ldap_sync_env_path, "KEYCLOAK_ADMIN_PASSWORD", kc_admin_password)

    # ClickHouse auth proxy shares the encryption key and LDAP bind with the token-store
    proxy_env_path = conf / "clickhouse_auth_proxy.env"
    if proxy_env_path.exists():
        if ldap_admin_password and ldap_admin_password != "CHANGEME":
            set_env_value(proxy_env_path, "LDAP_BIND_PASSWORD", ldap_admin_password)
        if ts_key and ts_key != "CHANGEME":
            set_env_value(proxy_env_path, "TOKEN_STORE_ENCRYPTION_KEY", ts_key)

    # Render ClickHouse LDAP exports
    ch_export_src = auth_dir / "conf.example" / "clickhouse-export"
    oidc_users = extract_realm_users(realm_path) if realm_path.exists() else []
    render_jinja2_file(
        ch_export_src / "ldap_servers.xml.j2",
        auth_export_dir / "ldap_servers.xml",
        ldap_base_dn=ldap_base_dn,
    )
    render_jinja2_file(
        ch_export_src / "oidc_users.xml.j2",
        auth_export_dir / "oidc_users.xml",
        oidc_users=oidc_users,
    )
    print(f"Rendered ClickHouse LDAP exports ({len(oidc_users)} OIDC users)")
    print(f"Auth bootstrap complete for domain '{domain}', realm '{realm}'")


def clean_auth(auth_dir: Path) -> None:
    remove_dir_if_exists(auth_dir / "conf")


def bootstrap_datastore(
    datastore_type: str,
    ds_dir: Path,
    auth_export_dir: Path | None,
) -> None:
    copytree_if_missing(ds_dir / "conf.example", ds_dir / "conf")
    if auth_export_dir and datastore_type == "clickhouse":
        ch_configd = ds_dir / "conf" / "config.d"
        ch_usersd = ds_dir / "conf" / "users.d"
        ensure_dir(ch_configd)
        ensure_dir(ch_usersd)
        for fname, dest in [
            ("ldap_servers.xml", ch_configd),
            ("oidc_users.xml", ch_usersd),
        ]:
            src = auth_export_dir / fname
            if src.exists():
                shutil.copy2(src, dest / fname)
        print("Copied auth LDAP config into ClickHouse conf")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build docker config for enabled components.")
    parser.add_argument(
        "-c",
        "--config",
        default="docker/config.yml",
        help="Path to config.yml (default: docker/config.yml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="docker/docker-compose.yml",
        help="Output docker-compose.yml path (default: docker/docker-compose.yml)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove generated conf directories for enabled components",
    )
    return parser.parse_args()


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    docker_dir = repo_root / "docker"
    args = parse_args()
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = repo_root / output_path
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = repo_root / config_path
    config = load_config(config_path)

    auth = config.get("auth", {}) or {}
    message_bus = config.get("message_bus", {}) or {}
    datastore = config.get("datastore", {}) or {}
    stacks = config.get("stacks", []) or []

    conf_d = docker_dir / "conf.d"
    ensure_dir(conf_d)

    if not args.clean:
        render_compose(docker_dir / "templates", config, output_path)

    # Auth bootstrap
    if auth.get("enabled"):
        auth_dir = repo_root / "auth"
        if not auth_dir.exists():
            raise FileNotFoundError(f"Auth directory not found: {auth_dir}")
        if args.clean:
            clean_auth(auth_dir)
        else:
            bootstrap_auth(auth_dir, conf_d)

    # Datastore bootstrap (clickhouse: copy conf, inject auth LDAP config if auth enabled)
    # Runs before message_bus so ClickHouse conf is ready regardless of message bus status.
    if datastore.get("enabled"):
        datastore_type = datastore.get("type")
        if not datastore_type:
            raise ValueError("datastore.type is required when enabled")
        ds_dir = repo_root / datastore_type
        if not ds_dir.exists():
            raise FileNotFoundError(f"Datastore directory not found: {ds_dir}")
        if args.clean:
            remove_dir_if_exists(ds_dir / "conf")
        else:
            auth_export_dir = conf_d / "auth" if auth.get("enabled") else None
            bootstrap_datastore(datastore_type, ds_dir, auth_export_dir)

    message_bus_type = None
    if message_bus.get("enabled"):
        message_bus_type = message_bus.get("type")
        if not message_bus_type:
            raise ValueError("message_bus.type is required when enabled")
        mb_dir = repo_root / message_bus_type
        if not mb_dir.exists():
            raise FileNotFoundError(f"Message bus directory not found: {mb_dir}")

        if args.clean:
            remove_dir_if_exists(mb_dir / "conf")
        else:
            copytree_if_missing(mb_dir / "conf.example", mb_dir / "conf")

            compose_file = output_path
            run([
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "run",
                "--rm",
                f"{message_bus_type}-init",
            ])

            export_dir = mb_dir / "conf" / "export"
            if not export_dir.exists():
                raise FileNotFoundError(f"Missing message bus export dir: {export_dir}")
            mb_export_dir = conf_d / message_bus_type
            ensure_dir(mb_export_dir)
            for item in export_dir.iterdir():
                if item.is_file():
                    shutil.copy2(item, mb_export_dir / item.name)

    for stack in stacks:
        stack_type = stack.get("type")
        if not stack_type:
            raise ValueError("stack.type is required")
        collectors = stack.get("collectors", []) or []
        for collector in collectors:
            if not collector.get("enabled"):
                continue
            collector_type = collector.get("type")
            if not collector_type:
                raise ValueError("collector.type is required when enabled")

            collector_dir = repo_root / stack_type / "collector" / collector_type
            if not collector_dir.exists():
                raise FileNotFoundError(f"Collector directory not found: {collector_dir}")

            if args.clean:
                remove_dir_if_exists(collector_dir / "conf")
                continue

            copytree_if_missing(collector_dir / "conf.example", collector_dir / "conf")

            if message_bus_type and not args.clean:
                export_src_dir = conf_d / message_bus_type
                if not export_src_dir.exists():
                    raise FileNotFoundError(f"Missing message bus export dir: {export_src_dir}")
                export_dest_dir = collector_dir / "conf" / message_bus_type
                ensure_dir(export_dest_dir)
                for item in export_src_dir.iterdir():
                    if item.is_file():
                        shutil.copy2(item, export_dest_dir / item.name)

            compose_file = output_path
            run([
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "run",
                "--rm",
                f"{collector_type}-init",
            ])

        pipeline = stack.get("pipeline", {}) or {}
        if pipeline.get("enabled"):
            pipeline_dir = repo_root / stack_type / "pipeline"
            if not pipeline_dir.exists():
                raise FileNotFoundError(f"Pipeline directory not found: {pipeline_dir}")
            if args.clean:
                remove_dir_if_exists(pipeline_dir / "conf")
            else:
                copytree_if_missing(pipeline_dir / "conf.example", pipeline_dir / "conf")


if __name__ == "__main__":
    main()
