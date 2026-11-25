#!/usr/bin/env python3
"""Render pipeline env files from env files and Jinja templates."""

import os
from pathlib import Path
from typing import Dict

from jinja2 import Environment, FileSystemLoader


def parse_env_file(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists():
        return data
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def main() -> None:
    conf_dir = Path(os.environ.get("PIPELINE_CONF_DIR", "/app/conf"))
    templates_dir = conf_dir / "templates"
    output_dir = conf_dir / "envs"

    pipeline_env = parse_env_file(conf_dir / "pipeline.env")
    kafka_env = parse_env_file(conf_dir / "kafka" / "kafka.env")
    clickhouse_env = parse_env_file(conf_dir / "clickhouse" / "clickhouse.env")

    # Merge: kafka and clickhouse first, then pipeline to allow it to override collisions.
    merged: Dict[str, str] = {}
    merged.update({k.lower(): v for k, v in kafka_env.items()})
    merged.update({k.lower(): v for k, v in clickhouse_env.items()})
    merged.update({k.lower(): v for k, v in pipeline_env.items()})

    force_update = is_truthy(pipeline_env.get("FORCE_UPDATE", ""))

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=False,
    )

    for template_path in sorted(templates_dir.glob("*.j2")):
        template = env.get_template(template_path.name)
        rendered = template.render(**merged)
        output_path = output_dir / template_path.stem
        if output_path.exists() and not force_update:
            print(f"Skipped {output_path} (exists, FORCE_UPDATE not true)")
            continue
        output_path.write_text(rendered)
        print(f"Rendered {template_path.name} -> {output_path}")


if __name__ == "__main__":
    main()
