"""Syntax-check every shipped playbook and every role task entry point."""

import os
from pathlib import Path
import subprocess
import tempfile

import yaml


def main():
    assets = Path(__file__).resolve().parents[1] / "internal" / "provision" / "ansible"
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(assets / "ansible.cfg"),
        "ANSIBLE_ROLES_PATH": str(assets / "roles"),
    }
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        env["ANSIBLE_HOME"] = str(directory / "ansible-home")
        env["ANSIBLE_LOCAL_TEMP"] = str(directory / "ansible")
        roles = [
            {"ansible.builtin.import_role": {"name": task.parents[1].name, "tasks_from": task.name}}
            for task in sorted(assets.glob("roles/*/tasks/*.yml"))
        ]
        harness = directory / "all_roles.yml"
        harness.write_text(yaml.safe_dump([{"hosts": "all", "tasks": roles}]), encoding="utf-8")
        for playbook in [assets / "preflight.yml", assets / "action.yml", harness]:
            subprocess.run(
                ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(playbook)],
                cwd=assets, env=env, check=True,
            )
    subprocess.run(
        ["bash", "-n", str(assets / "roles/firewall_guard/files/restore.sh")], check=True
    )


if __name__ == "__main__":
    main()
