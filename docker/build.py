#!/usr/bin/env python3
"""Build docker config for enabled components."""

from __future__ import annotations

import argparse
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
	return parser.parse_args()


def main() -> None:
	repo_root = Path(__file__).resolve().parents[1]
	docker_dir = repo_root / "docker"
	args = parse_args()
	config_path = Path(args.config)
	if not config_path.is_absolute():
		config_path = repo_root / config_path
	config = load_config(config_path)

	message_bus = config.get("message_bus", {}) or {}
	stacks = config.get("stacks", []) or []

	conf_d = docker_dir / "conf.d"
	ensure_dir(conf_d)

	message_bus_type = None
	if message_bus.get("enabled"):
		message_bus_type = message_bus.get("type")
		if not message_bus_type:
			raise ValueError("message_bus.type is required when enabled")
		mb_dir = repo_root / message_bus_type
		if not mb_dir.exists():
			raise FileNotFoundError(f"Message bus directory not found: {mb_dir}")

		copytree_if_missing(mb_dir / "conf.example", mb_dir / "conf")

		compose_file = mb_dir / "docker-compose.yml"
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

			copytree_if_missing(collector_dir / "conf.example", collector_dir / "conf")

			if message_bus_type:
				env_src = conf_d / message_bus_type / f"{message_bus_type}.env"
				if not env_src.exists():
					raise FileNotFoundError(f"Missing message bus env file: {env_src}")
				shutil.copy2(env_src, collector_dir / "conf" / f"{message_bus_type}.env")

			compose_file = collector_dir / "docker-compose.yml"
			run([
				"docker",
				"compose",
				"-f",
				str(compose_file),
				"run",
				"--rm",
				f"{collector_type}-init",
			])

	output_path = Path(args.output)
	if not output_path.is_absolute():
		output_path = repo_root / output_path
	render_compose(docker_dir / "templates", config, output_path)


if __name__ == "__main__":
	main()