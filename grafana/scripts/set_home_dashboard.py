#!/usr/bin/env python3
"""Set Grafana organization home dashboard via API."""

import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import quote_plus
import json


def parse_env_file(path: Path) -> dict:
    """Parse environment file and return key-value pairs."""
    data = {}
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


def wait_for_grafana(url: str, max_attempts: int = 60) -> bool:
    """Wait for Grafana to be ready."""
    print("Waiting for Grafana to start...")
    for attempt in range(max_attempts):
        try:
            req = Request(f"{url}/api/health")
            with urlopen(req, timeout=2) as response:
                if response.status == 200:
                    print("Grafana is ready!")
                    return True
        except (URLError, OSError):
            pass
        time.sleep(2)
    return False


def set_home_dashboard(url: str, username: str, password: str, dashboard_uid: str) -> bool:
    """Set organization home dashboard preference."""
    print(f"Setting home dashboard to UID: {dashboard_uid}")
    
    # Create basic auth header
    import base64
    credentials = f"{username}:{password}"
    auth_header = base64.b64encode(credentials.encode()).decode()
    
    # First, verify the dashboard exists
    print(f"Verifying dashboard exists...")
    try:
        check_req = Request(
            f"{url}/api/dashboards/uid/{dashboard_uid}",
            headers={"Authorization": f"Basic {auth_header}"},
        )
        with urlopen(check_req, timeout=10) as response:
            if response.status == 200:
                dashboard_data = json.loads(response.read().decode())
                print(f"✓ Dashboard found: {dashboard_data.get('dashboard', {}).get('title', 'Unknown')}")
            else:
                print(f"⚠ Dashboard check returned status: {response.status}")
    except URLError as e:
        print(f"⚠ Could not verify dashboard (it may not be provisioned yet): {e}")
        # Continue anyway as it might be provisioned shortly
    
    # Prepare request
    data = json.dumps({"homeDashboardUID": dashboard_uid}).encode()
    req = Request(
        f"{url}/api/org/preferences",
        data=data,
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_header}",
        },
    )
    
    try:
        with urlopen(req, timeout=10) as response:
            response_body = response.read().decode()
            if response.status in (200, 204):
                print(f"✓ Home dashboard set successfully!")
                return True
            else:
                print(f"✗ Failed with status: {response.status}")
                print(f"Response: {response_body}")
                return False
    except URLError as e:
        print(f"✗ Error setting home dashboard: {e}")
        if hasattr(e, 'code'):
            print(f"Status code: {e.code}")
        if hasattr(e, 'read'):
            try:
                error_body = e.read().decode()
                print(f"Error response: {error_body}")
            except:
                pass
        return False


def find_dashboard_by_title(url: str, username: str, password: str, title: str) -> str | None:
    """Search for dashboard by title and return its UID."""
    print(f"Searching for dashboard: {title}")
    
    import base64
    credentials = f"{username}:{password}"
    auth_header = base64.b64encode(credentials.encode()).decode()
    
    try:
        # URL-encode the title for the query parameter
        encoded_title = quote_plus(title)
        req = Request(
            f"{url}/api/search?query={encoded_title}&type=dash-db",
            headers={"Authorization": f"Basic {auth_header}"},
        )
        with urlopen(req, timeout=10) as response:
            if response.status == 200:
                results = json.loads(response.read().decode())
                for dashboard in results:
                    if dashboard.get("title") == title:
                        uid = dashboard.get("uid")
                        print(f"✓ Found dashboard '{title}' with UID: {uid}")
                        return uid
                print(f"⚠ Dashboard '{title}' not found in search results")
                return None
            else:
                print(f"✗ Search failed with status: {response.status}")
                return None
    except URLError as e:
        print(f"✗ Error searching for dashboard: {e}")
        return None


def main() -> int:
    grafana_url = os.environ.get("GRAFANA_URL", "http://grafana:3000")
    conf_dir = Path(os.environ.get("GRAFANA_CONF_DIR", "/app/conf"))
    dashboard_title = os.environ.get("GRAFANA_HOME_DASHBOARD_TITLE", "MetrANOVA Home")
    
    # Wait for Grafana
    if not wait_for_grafana(grafana_url):
        print("✗ Grafana did not become ready in time")
        return 1
    
    # Read admin password
    auth_env = parse_env_file(conf_dir / "grafana_auth.env")
    password = auth_env.get("GF_SECURITY_ADMIN_PASSWORD")
    
    if not password:
        print("✗ Could not find GF_SECURITY_ADMIN_PASSWORD in grafana_auth.env")
        return 1
    
    # Find the dashboard by title to get its current UID
    dashboard_uid = find_dashboard_by_title(grafana_url, "admin", password, dashboard_title)
    
    if not dashboard_uid:
        print(f"✗ Could not find dashboard '{dashboard_title}'")
        print("Make sure the dashboard is provisioned and the title matches exactly")
        return 1
    
    # Set home dashboard
    if set_home_dashboard(grafana_url, "admin", password, dashboard_uid):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
