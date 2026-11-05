#!/usr/bin/env bash
# Render envoy.yaml from envoy.yaml.j2 using Python + Jinja2.
set -euo pipefail

CONF_FILE="${ENVOY_CONF_FILE:-/config/envoy.env}"
TEMPLATE_FILE="/app/templates/envoy.yaml.j2"
OUTPUT_FILE="/srv/envoy/envoy.yaml"

python3 - <<'PYEOF'
import os, sys
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined

conf_file = os.environ.get("ENVOY_CONF_FILE", "/config/envoy.env")
env_vars = {}
conf_path = Path(conf_file)
if conf_path.exists():
    for line in conf_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env_vars[k.strip()] = v.strip()

# Merge with actual environment (env takes precedence)
env_vars.update(os.environ)

template_dir = "/app/templates"
jenv = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=StrictUndefined,
)
template = jenv.get_template("envoy.yaml.j2")

# Build context from env vars
ctx = {
    "https_port":    int(env_vars.get("ENVOY_HTTPS_PORT", "443")),
    "grafana":       env_vars.get("ENVOY_UPSTREAM_GRAFANA", "false").lower() == "true",
    "clickhouse":    env_vars.get("ENVOY_UPSTREAM_CLICKHOUSE", "false").lower() == "true",
}

output = template.render(**ctx)
Path("/srv/envoy/envoy.yaml").write_text(output)
print("Rendered envoy.yaml")
PYEOF
