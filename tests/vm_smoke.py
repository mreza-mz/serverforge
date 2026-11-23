"""Exercise provisioning on a disposable Ubuntu VM forwarded only to loopback."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml


TEST_PASSWORD = "test-only account password! 認#4"
TEST_PASSPHRASE = "serverforge-test-only-vault"


def fixture(port, suite):
    data = {
        "version": 1,
        "target": {"connection": "ssh", "host": "127.0.0.1", "user": "tester", "port": port},
        "modules": ["caddy", "mariadb"],
        "web": {"domain": "app.example.test", "http_port": 8090},
        "databases": {"mariadb": {"name": "demo_maria", "user": "app_maria", "port": 3311}},
    }
    if suite == "main":
        data.update(
            modules=["docker", "docker_compose", "postgresql", "mysql", "redis", "nginx"],
            databases={
                "postgresql": {"name": "demo_pg", "user": "app_pg", "port": 5433},
                "mysql": {"name": "demo_mysql", "user": "app_mysql", "port": 3307},
            },
            web={"domain": "app.example.test", "http_port": 8080},
            redis={"port": 6381},
            security={"ufw": True, "fail2ban": True, "security_updates": True},
        )
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--suite", choices=("main", "alternate"), required=True)
    args = parser.parse_args()

    expected_host = "forge-test" if args.suite == "main" else "forge-test-b"
    ssh = [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-p", str(args.port), "tester@127.0.0.1",
    ]
    host = subprocess.check_output(ssh + ["hostname"], text=True).strip()
    if host != expected_host:
        raise RuntimeError("this test expects its disposable Ubuntu VM")

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        os.environ.setdefault("ANSIBLE_HOME", str(root / "ansible"))
        from ansible.parsing.vault import VaultLib, VaultSecret

        cli = root / "serverforge"
        shutil.copy2(args.binary, cli)
        profile = root / "profile.yaml"
        receipt = root / "approval.json"
        data = fixture(args.port, args.suite)
        keys = [name + "_password" for name in data["databases"]]
        if "redis" in data:
            keys.append("redis_password")
        vault = VaultLib([("default", VaultSecret(TEST_PASSPHRASE.encode()))])
        data["vault"] = vault.encrypt(
            yaml.safe_dump(dict.fromkeys(keys, TEST_PASSWORD)).encode()
        ).decode()
        profile.write_text(yaml.safe_dump(data), encoding="utf-8")

        def command(*flags, vault_input=None):
            run = subprocess.run(
                [str(cli), *map(str, flags), "--config", str(profile)],
                input=vault_input, capture_output=True, text=True,
            )
            output = run.stdout + run.stderr
            if TEST_PASSWORD in output or TEST_PASSPHRASE in output or "$ANSIBLE_VAULT" in output:
                raise RuntimeError("ServerForge emitted credential data")
            if run.returncode != 0:
                raise RuntimeError(output)
            return run.stdout

        plan = json.loads(command("plan", "--json"))
        # The integration fixture approves only these deliberately selected security actions.
        approved = ["mariadb"] if args.suite == "alternate" else [
            "postgresql", "mysql", "redis", "fail2ban", "security_updates", "ufw",
        ]
        security_flags = [flag for name in approved for flag in ("--approve-security", name)]
        command("approve", "--non-interactive", "--plan-id", plan["id"], "--output", receipt, *security_flags)
        password_line = TEST_PASSPHRASE + "\n"
        packages = ssh + ["dpkg-query -W"]
        installed_before = subprocess.check_output(packages)
        if " check (changed " not in command("apply", "--dry-run", "--vault-passphrase-stdin", vault_input=password_line):
            raise RuntimeError("dry-run reported no checked action")
        if subprocess.check_output(packages) != installed_before:
            raise RuntimeError("dry-run changed the installed package inventory")
        if list(root.glob("*.state.json")):
            raise RuntimeError("dry-run wrote a checkpoint")
        apply_args = ("apply", "--approval", receipt, "--vault-passphrase-stdin")
        command(*apply_args, vault_input=password_line)
        repeated = command(*apply_args, vault_input=password_line)
        for action in plan["actions"]:
            if action["id"] + " ok (changed 0," not in repeated:
                raise RuntimeError("repeat run changed a converged action: " + action["id"])
        resumed = command(*apply_args, "--resume", vault_input=password_line)
        if resumed.count(" resumed (") != len(plan["actions"]):
            raise RuntimeError("resume did not preserve successful checkpoints")
        subprocess.run(
            ssh + ["sudo -n tee /var/www/serverforge/app.example.test/health.txt >/dev/null"],
            input="ready\n", text=True, check=True,
        )
        cli.unlink()

    if args.suite == "main":
        health = """
set -eu
IFS= read -r password
PGPASSWORD="$password" psql -h 127.0.0.1 -p 5433 -U app_pg -d demo_pg -XAtc 'SELECT 1' | grep -qx 1
MYSQL_PWD="$password" mysql --protocol=tcp -h 127.0.0.1 -P 3307 -u app_mysql -N demo_mysql -e 'SELECT 1' | grep -qx 1
REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p 6381 ping | grep -qx PONG
sudo -n docker compose version >/dev/null
sudo -n fail2ban-client status sshd >/dev/null
sudo -n ufw status | grep -q '^Status: active'
curl -fsS -H 'Host: app.example.test' http://127.0.0.1:8080/health.txt | grep -qx ready
"""
    else:
        health = """
set -eu
IFS= read -r password
MYSQL_PWD="$password" mariadb --protocol=tcp -h 127.0.0.1 -P 3311 -u app_maria -N demo_maria -e 'SELECT 1' | grep -qx 1
curl -fsS -H 'Host: app.example.test' http://127.0.0.1:8090/health.txt | grep -qx ready
"""
    subprocess.run(ssh + [health], input=TEST_PASSWORD + "\n", text=True, check=True)
    print("Disposable Ubuntu VM smoke test passed")


if __name__ == "__main__":
    main()
