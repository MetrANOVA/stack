from pathlib import Path
import subprocess

import pytest
import yaml


CHART = Path(__file__).resolve().parents[1] / "helm/charts/api"


@pytest.mark.parametrize("with_mounts", [False, True])
def test_api_validation_mounts_and_environment(tmp_path, with_mounts):
    volumes = [{"name": "validation-base", "configMap": {"name": "collector-base"}}]
    mounts = [{
        "name": "validation-base",
        "mountPath": "/etc/telegraf",
        "readOnly": True,
    }]
    environment = [{
        "name": "TELEGRAF_BASE_CONFIG_PATH",
        "value": "/etc/telegraf/telegraf.conf",
    }]
    values = tmp_path / "values.yaml"
    values.write_text(yaml.safe_dump({
        "extraVolumes": volumes if with_mounts else [],
        "extraVolumeMounts": mounts if with_mounts else [],
        "extraEnv": environment,
    }))
    result = subprocess.run(
        ["helm", "template", "example", str(CHART), "-f", str(values)],
        capture_output=True, text=True, check=True,
    )
    deployment = next(
        document for document in yaml.safe_load_all(result.stdout)
        if document["kind"] == "Deployment"
    )
    pod = deployment["spec"]["template"]["spec"]
    container, = pod["containers"]
    assert pod.get("volumes", []) == (volumes if with_mounts else [])
    assert container.get("volumeMounts", []) == (mounts if with_mounts else [])
    assert all(entry in container["env"] for entry in environment)
