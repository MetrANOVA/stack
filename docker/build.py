#!/usr/bin/env python3
"""Build docker config for enabled components."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Set

from jinja2 import Environment, FileSystemLoader, StrictUndefined

try:
	import yaml
except ImportError:  # pragma: no cover - runtime guard
	print("Missing dependency: pyyaml. Install with 'pip install pyyaml'.")
	sys.exit(1)


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


def ensure_dir(path: Path) -> None:
	path.mkdir(parents=True, exist_ok=True)


def remove_dir_if_exists(path: Path) -> None:
	if path.exists():
		shutil.rmtree(path)


def load_services(path: Path) -> Dict[str, Any]:
	if not path.exists():
		raise FileNotFoundError(f"Services file not found: {path}")
	data = yaml.safe_load(path.read_text())
	if not isinstance(data, dict):
		raise ValueError("Services file must be a YAML object")
	return data


def generate_shared_pipeline_compose(
	services: Set[str],
	output_path: Path,
	shared_pipeline_cfg: Dict[str, Any],
	template_dir: Path,
) -> None:
	"""Write shared/pipeline/docker-compose.yml from a Jinja template."""
	image = shared_pipeline_cfg.get("image", "")
	if not image:
		raise ValueError("shared_pipeline.image is required in services.yml")
	service_definitions: Dict[str, Any] = shared_pipeline_cfg.get("services", {}) or {}

	unknown = services - service_definitions.keys()
	if unknown:
		raise ValueError(f"Unknown shared pipeline service(s): {', '.join(sorted(unknown))}")

	env = Environment(
		loader=FileSystemLoader(str(template_dir)),
		autoescape=False,
		trim_blocks=True,
		lstrip_blocks=True,
		undefined=StrictUndefined,
	)
	template = env.get_template("shared-pipeline-docker-compose.yml.j2")
	rendered = template.render(
		image=image,
		services=[
			{"name": svc, "profiles": [], **service_definitions[svc]}
			for svc in sorted(services)
		],
	)
	output_path.write_text(rendered)


def copy_exported_creds(export_src: Path, dest_dir: Path) -> None:
	"""Copy all files from an export dir into dest_dir, creating it if needed."""
	ensure_dir(dest_dir)
	for item in export_src.iterdir():
		if item.is_file():
			shutil.copy2(item, dest_dir / item.name)


def render_service_compose(service_dir: Path, context: Dict[str, Any]) -> None:
	"""Render <service>/docker-compose.yml from <service>/templates/docker-compose.yml.j2."""
	template_path = service_dir / "templates" / "docker-compose.yml.j2"
	if not template_path.exists():
		raise FileNotFoundError(f"No compose template found: {template_path}")
	env = Environment(
		loader=FileSystemLoader(str(service_dir / "templates")),
		autoescape=False,
		trim_blocks=True,
		lstrip_blocks=True,
		undefined=StrictUndefined,
	)
	template = env.get_template("docker-compose.yml.j2")
	(service_dir / "docker-compose.yml").write_text(template.render(**context))


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
	services_path = docker_dir / "services.yml"
	services_cfg = load_services(services_path)
	shared_pipeline_cfg: Dict[str, Any] = services_cfg.get("shared_pipeline", {}) or {}

	message_bus = config.get("message_bus", {}) or {}
	datastore = config.get("datastore", {}) or {}
	stacks = config.get("stacks", []) or []
	dashboard = config.get("dashboard", {}) or {}
	proxy = config.get("proxy", {}) or {}

	# Collect the union of shared pipeline services across all enabled stacks.
	shared_pipeline_services: Set[str] = set()
	for stack in stacks:
		pipeline = stack.get("pipeline", {}) or {}
		if pipeline.get("enabled"):
			for svc in pipeline.get("shared_services", []) or []:
				shared_pipeline_services.add(svc)

	conf_d = docker_dir / "conf.d"
	ensure_dir(conf_d)

	shared_pipeline_dir = repo_root / "shared" / "pipeline"

	if not args.clean:
		render_compose(
			docker_dir / "templates",
			{
				**config,
				"shared_pipeline_services": shared_pipeline_services,
				# Ensure proxy always has an `enabled` key for the template.
				"proxy": {"enabled": False, "type": None, **proxy},
			},
			output_path,
		)
		# Generate shared/pipeline/docker-compose.yml before any `docker compose`
		# invocation — the root compose file includes it, so Docker needs it to
		# exist even when parsing for unrelated services (e.g. kafka-init).
		if shared_pipeline_services:
			generate_shared_pipeline_compose(
				shared_pipeline_services,
				shared_pipeline_dir / "docker-compose.yml",
				shared_pipeline_cfg,
				docker_dir / "templates",
			)

		# Generate service-level compose files that the root compose includes.
		# These must exist before the first `docker compose` invocation.
		proxy_enabled = proxy.get("enabled", False)
		if datastore.get("enabled"):
			_ds_type = datastore.get("type")
			if _ds_type:
				_ds_dir = repo_root / _ds_type
				_proxy_covers = proxy_enabled and datastore.get("use_proxy", True)
				render_service_compose(_ds_dir, {
					"expose_port": datastore.get("expose_port", not _proxy_covers),
				})
		if dashboard.get("enabled"):
			_db_type = dashboard.get("type")
			if _db_type:
				_db_dir = repo_root / _db_type
				_proxy_covers = proxy_enabled and dashboard.get("use_proxy", True)
				render_service_compose(_db_dir, {
					"expose_port": dashboard.get("expose_port", not _proxy_covers),
				})

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

	datastore_type = None
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
			copytree_if_missing(ds_dir / "conf.example", ds_dir / "conf")

			compose_file = output_path
			run([
				"docker",
				"compose",
				"-f",
				str(compose_file),
				"run",
				"--rm",
				f"{datastore_type}-init",
			])

			export_dir = ds_dir / "conf" / "export"
			if not export_dir.exists():
				raise FileNotFoundError(f"Missing datastore export dir: {export_dir}")
			ds_export_dir = conf_d / datastore_type
			ensure_dir(ds_export_dir)
			for item in export_dir.iterdir():
				if item.is_file():
					shutil.copy2(item, ds_export_dir / item.name)

	# Shared pipeline — deduplicated services used by one or more stacks.
	if shared_pipeline_services:
		if args.clean:
			remove_dir_if_exists(shared_pipeline_dir / "conf")
		else:
			copytree_if_missing(shared_pipeline_dir / "conf.example", shared_pipeline_dir / "conf")

			if message_bus_type:
				copy_exported_creds(conf_d / message_bus_type, shared_pipeline_dir / "conf" / message_bus_type)
			if datastore_type:
				copy_exported_creds(conf_d / datastore_type, shared_pipeline_dir / "conf" / datastore_type)

			run([
				"docker", "compose", "-f", str(output_path),
				"run", "--rm", "shared-pipeline-init",
			])

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
				is_first_run = not (pipeline_dir / "conf").exists()
				copytree_if_missing(pipeline_dir / "conf.example", pipeline_dir / "conf")
				if is_first_run and sys.platform.startswith("linux"):
					try:
						subprocess.run(
							["chown", "-R", "1000:1000", str(pipeline_dir / "caches")],
							check=True,
						)
					except Exception:
						pass

				if message_bus_type:
					export_src_dir = conf_d / message_bus_type
					if not export_src_dir.exists():
						raise FileNotFoundError(f"Missing message bus export dir: {export_src_dir}")
					export_dest_dir = pipeline_dir / "conf" / message_bus_type
					ensure_dir(export_dest_dir)
					for item in export_src_dir.iterdir():
						if item.is_file():
							shutil.copy2(item, export_dest_dir / item.name)

				if datastore_type:
					export_src_dir = conf_d / datastore_type
					if not export_src_dir.exists():
						raise FileNotFoundError(f"Missing datastore export dir: {export_src_dir}")
					export_dest_dir = pipeline_dir / "conf" / datastore_type
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
					f"{stack_type}-pipeline-init",
				])

	dashboard_type = None
	if dashboard.get("enabled"):
		dashboard_type = dashboard.get("type")
		if not dashboard_type:
			raise ValueError("dashboard.type is required when enabled")
		dashboard_dir = repo_root / dashboard_type
		if not dashboard_dir.exists():
			raise FileNotFoundError(f"Dashboard directory not found: {dashboard_dir}")

		if args.clean:
			remove_dir_if_exists(dashboard_dir / "conf")
			datasources_dir = dashboard_dir / "provisioning" / "datasources"
			if datasources_dir.exists():
				for item in datasources_dir.iterdir():
					if item.is_file() and item.suffix == ".yaml":
						item.unlink()
		else:
			copytree_if_missing(dashboard_dir / "conf.example", dashboard_dir / "conf")

			if datastore_type:
				export_src_dir = conf_d / datastore_type
				if not export_src_dir.exists():
					raise FileNotFoundError(f"Missing datastore export dir: {export_src_dir}")
				export_dest_dir = dashboard_dir / "conf" / datastore_type
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
				f"{dashboard_type}-init",
			])

	if proxy.get("enabled"):
		proxy_type = proxy.get("type")
		if not proxy_type:
			raise ValueError("proxy.type is required when enabled")
		proxy_dir = repo_root / proxy_type
		if not proxy_dir.exists():
			raise FileNotFoundError(f"Proxy directory not found: {proxy_dir}")

		if args.clean:
			remove_dir_if_exists(proxy_dir / "conf")
		else:
			copytree_if_missing(proxy_dir / "conf.example", proxy_dir / "conf")

			# A service is wired into the proxy only when it is enabled and has
			# not opted out via dashboard/datastore.use_proxy: false.
			upstream_grafana = (
				dashboard.get("enabled")
				and dashboard.get("type") == "grafana"
				and dashboard.get("use_proxy", True)
			)
			upstream_clickhouse = (
				datastore.get("enabled")
				and datastore.get("type") == "clickhouse"
				and datastore.get("use_proxy", True)
			)
			proxy_env_path = proxy_dir / "conf" / "envoy.env"
			_set_env_value(proxy_env_path, "ENVOY_UPSTREAM_GRAFANA", str(upstream_grafana).lower())
			_set_env_value(proxy_env_path, "ENVOY_UPSTREAM_CLICKHOUSE", str(upstream_clickhouse).lower())

			# Let's Encrypt configuration.
			le_cfg = proxy.get("letsencrypt", {}) or {}
			le_enabled = le_cfg.get("enabled", False)
			le_hostname = le_cfg.get("hostname", "")
			if le_enabled and not le_hostname:
				raise ValueError("proxy.letsencrypt.hostname is required when letsencrypt is enabled")
			_set_env_value(proxy_env_path, "ENVOY_LETSENCRYPT_ENABLED", str(le_enabled).lower())
			if le_hostname:
				_set_env_value(proxy_env_path, "ENVOY_LETSENCRYPT_HOSTNAME", le_hostname)

			# Provide the ClickHouse CA so envoy can verify its TLS certificate.
			if upstream_clickhouse and datastore_type:
				ch_ca_src = conf_d / datastore_type / "ca.crt"
				ch_ca_dest_dir = proxy_dir / "conf" / "clickhouse"
				ensure_dir(ch_ca_dest_dir)
				if ch_ca_src.exists():
					shutil.copy2(ch_ca_src, ch_ca_dest_dir / "ca.crt")

			# When Let's Encrypt is enabled, run certbot first to obtain the
			# certificate, then copy it into the envoy-data volume.
			# envoy-certs runs next and skips self-signed generation because the
			# cert files are already populated.
			if le_enabled:
				for init_svc in ("certbot-init", "envoy-letsencrypt"):
					run([
						"docker", "compose", "-f", str(output_path),
						"run", "--rm", init_svc,
					])

			for init_svc in ("envoy-certs", "envoy-config"):
				run([
					"docker", "compose", "-f", str(output_path),
					"run", "--rm", init_svc,
				])


def _set_env_value(env_path: Path, key: str, value: str) -> None:
	"""Set or append a KEY=value line in an env file.

	Replaces an existing active line (KEY=...) or a commented-out placeholder
	(# KEY=... or #KEY=...) if found; otherwise appends.
	"""
	text = env_path.read_text() if env_path.exists() else ""
	lines = text.splitlines()
	new_line = f"{key}={value}"
	for i, line in enumerate(lines):
		stripped = line.lstrip("#").lstrip()
		if stripped.startswith(f"{key}="):
			lines[i] = new_line
			env_path.write_text("\n".join(lines) + "\n")
			return
	env_path.write_text(text.rstrip("\n") + "\n" + new_line + "\n")


if __name__ == "__main__":
	main()