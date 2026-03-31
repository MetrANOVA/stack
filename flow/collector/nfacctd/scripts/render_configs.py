#!/usr/bin/env python3
"""Render nfacctd config files from env files and Jinja templates."""

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
    conf_dir = Path(os.environ.get("NFACCTD_CONF_DIR", "/etc/pmacct"))
    templates_dir = Path(os.environ.get("NFACCTD_TEMPLATES_DIR", conf_dir / "templates"))

    nfacctd_env = parse_env_file(conf_dir / "nfacctd.env")
    kafka_env = parse_env_file(conf_dir / "kafka" / "kafka.env")

    # Kafka first, then nfacctd to allow nfacctd to override collisions.
    merged: Dict[str, str] = {}
    merged.update({k.lower(): v for k, v in kafka_env.items()})
    merged.update({k.lower(): v for k, v in nfacctd_env.items()})

    force_update = is_truthy(nfacctd_env.get("FORCE_UPDATE", ""))

    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=False)

    for template_path in templates_dir.glob("*.j2"):
        template = env.get_template(template_path.name)
        rendered = template.render(**merged)
        output_path = conf_dir / template_path.stem
        if output_path.exists() and not force_update:
            print(f"Skipped {output_path} (exists, FORCE_UPDATE not true)")
            continue
        output_path.write_text(rendered)
        print(f"Rendered {template_path.name} -> {output_path}")


if __name__ == "__main__":
    main()
