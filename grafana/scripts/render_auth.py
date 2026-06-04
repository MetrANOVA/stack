#!/usr/bin/env python3
"""Render Grafana auth configuration with random password."""

import os
import secrets
import string
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def generate_password(length: int = 32) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Ensure the password has at least one of each type
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]
    # Fill the rest randomly
    password.extend(secrets.choice(alphabet) for _ in range(length - 4))
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def main() -> None:
    conf_dir = Path(os.environ.get("GRAFANA_CONF_DIR", "/app/conf"))
    templates_dir = Path(os.environ.get("GRAFANA_TEMPLATES_DIR", "/app/templates"))
    output_path = conf_dir / "grafana_auth.env"

    # Check if auth file already exists
    if output_path.exists():
        print(f"Skipped {output_path} (already exists)")
        return

    # Generate random password
    password = generate_password()

    # Render template
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=False,
    )

    template = env.get_template("grafana_auth.env.j2")
    rendered = template.render(gf_security_admin_password=password)

    # Write output
    output_path.write_text(rendered)
    os.chmod(output_path, 0o600)  # Restrict permissions
    print(f"Rendered grafana_auth.env.j2 -> {output_path}")
    print(f"Generated admin password: {password}")


if __name__ == "__main__":
    main()
