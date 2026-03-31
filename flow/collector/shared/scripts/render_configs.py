#!/usr/bin/env python3
"""Render pmacct collector config files from env files and Jinja templates."""

import argparse
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render pmacct configs from env and templates.")
    parser.add_argument(
        "-c",
        "--collector",
        default="nfacctd",
        help="Collector name (default: nfacctd)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    conf_dir = Path(
        os.environ.get(
            "PMACCT_CONF_DIR",
            os.environ.get("NFACCTD_CONF_DIR", "/etc/pmacct"),
        )
    )
    templates_dir = Path(
        os.environ.get(
            "PMACCT_TEMPLATES_DIR",
            os.environ.get("NFACCTD_TEMPLATES_DIR", conf_dir / "templates"),
        )
    )
    shared_templates_dir = Path(
        os.environ.get(
            "PMACCT_SHARED_TEMPLATES_DIR",
            os.environ.get("NFACCTD_SHARED_TEMPLATES_DIR", conf_dir / "shared_templates"),
        )
    )

    collector_env = parse_env_file(conf_dir / f"{args.collector}.env")
    kafka_env = parse_env_file(conf_dir / "kafka" / "kafka.env")

    # Kafka first, then collector to allow collector to override collisions.
    merged: Dict[str, str] = {}
    merged.update({k.lower(): v for k, v in kafka_env.items()})
    merged.update({k.lower(): v for k, v in collector_env.items()})

    force_update = is_truthy(collector_env.get("FORCE_UPDATE", ""))

    env = Environment(
        loader=FileSystemLoader([str(templates_dir), str(shared_templates_dir)]),
        autoescape=False,
    )

    template_paths = list(templates_dir.glob("*.j2"))
    if shared_templates_dir.exists():
        template_paths.extend(shared_templates_dir.glob("*.j2"))

    for template_path in template_paths:
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
