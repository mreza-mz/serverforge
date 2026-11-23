"""Drive the built ServerForge CLI through a Linux pseudo-terminal."""

import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pexpect
import yaml


def spawn(binary, *args):
    return pexpect.spawn(
        binary,
        list(args),
        env={**os.environ, "TERM": "xterm-256color"},
        dimensions=(48, 110),
        encoding="utf-8",
        timeout=8,
    )


def create_redis_profile(binary, path):
    password = "test-only-redis!credential"
    passphrase = "test-only-vault!passphrase"
    transcript = io.StringIO()
    with spawn(binary, "init", "--output", str(path)) as session:
        session.logfile_read = transcript
        session.expect_exact("Which services should this profile include?")
        for _ in range(7):
            session.send("j")
        session.send(" ")
        session.send("\r")
        session.expect_exact("Target connection")
        session.send("\r")
        session.expect_exact("Redis port")
        session.send("\r")
        session.expect_exact("Redis password")
        session.send(password + "\r")
        session.expect_exact("Security Wizard")
        # Enter accepts the default Skip. Only Fail2ban gets explicit approval.
        session.send("\r")
        session.send("y")
        session.send("\r")
        session.expect_exact("Ansible Vault passphrase")
        session.send(passphrase + "\r")
        session.expect_exact("Confirm Ansible Vault passphrase")
        session.send(passphrase + "\r")
        session.expect_exact("Save this profile?")
        session.send("y")
        session.expect(pexpect.EOF)
        if "Profile saved." not in session.before:
            raise AssertionError("wizard did not report a saved profile")
        session.close()
    if session.exitstatus != 0:
        raise AssertionError(f"wizard exited with status {session.exitstatus}")
    if password in transcript.getvalue() or passphrase in transcript.getvalue():
        raise AssertionError("the terminal echoed a credential")

    raw = path.read_text(encoding="utf-8")
    if password in raw or passphrase in raw or path.stat().st_mode & 0o777 != 0o600:
        raise AssertionError("profile exposed a credential or had unexpected permissions")
    profile = yaml.safe_load(raw)
    if profile["modules"] != ["redis"] or profile["redis"] != {"port": 6379}:
        raise AssertionError("the profile did not retain the selected module and its port")
    if profile["security"] != {"fail2ban": True}:
        raise AssertionError("a security choice diverged from explicit approval")
    if not profile["vault"].startswith("$ANSIBLE_VAULT;1.1;AES256\n"):
        raise AssertionError("profile omitted the encrypted Vault payload")
    subprocess.run([binary, "validate", "--config", str(path)], check=True)


def cancel_before_writing(binary, path):
    with spawn(binary, "init", "--output", str(path)) as session:
        session.expect_exact("Which services should this profile include?")
        session.sendcontrol("c")
        session.expect_exact("wizard interrupted")
        session.expect(pexpect.EOF)
        session.close()
    if session.exitstatus != 1 or path.exists():
        raise AssertionError("interrupted wizard unexpectedly completed")


def decline_save(binary, path):
    with spawn(binary, "init", "--output", str(path)) as session:
        session.expect_exact("Which services should this profile include?")
        session.send("\r")
        session.expect_exact("Target connection")
        session.send("\r")
        session.expect_exact("Security Wizard")
        for _ in range(3):
            session.send("\r")
        session.expect_exact("Save this profile?")
        session.send("\r")
        session.expect_exact("profile creation canceled")
        session.expect(pexpect.EOF)
        session.close()
    if session.exitstatus != 1 or path.exists():
        raise AssertionError("declining the save prompt unexpectedly created a profile")


def review_plan(binary, receipt_path, accept):
    profile = Path(__file__).resolve().parents[1] / "examples" / "ssh.yaml"
    with spawn(binary, "approve", "--config", str(profile), "--output", str(receipt_path)) as session:
        session.expect_exact("Execution plan sha256:")
        session.expect_exact("stage SSH allow rules")
        session.expect_exact("Security approval · ssl")
        if accept:
            session.send("y")
            session.expect_exact("Security approval · security_updates")
            session.send("y")
            session.expect_exact("Security approval · ufw")
            session.send("y")
            session.expect_exact("Approve this execution plan?")
            session.send("y")
            session.expect_exact("Approval receipt saved.")
        else:
            session.send("\r")
            session.expect_exact("plan approval declined")
        session.expect(pexpect.EOF)
        session.close()

    if not accept:
        if session.exitstatus != 1 or receipt_path.exists():
            raise AssertionError("declining a security action unexpectedly issued a receipt")
        return
    if session.exitstatus != 0:
        raise AssertionError("the approval wizard did not complete")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    plan = json.loads(subprocess.check_output([binary, "plan", "--config", str(profile), "--json"]))
    if receipt["plan_id"] != plan["id"] or receipt["security_actions"] != ["ssl", "security_updates", "ufw"]:
        raise AssertionError("approval receipt differs from the reviewed plan")


def setup_declines_before_ansible(binary, path):
    with spawn(binary, "setup", "--config", str(path)) as session:
        session.expect_exact("Which services should this profile include?")
        session.send(" ")
        session.send("\r")
        session.expect_exact("Target connection")
        session.send("\r")
        session.expect_exact("Security Wizard")
        for _ in range(3):
            session.send("\r")
        session.expect_exact("Save this profile?")
        session.send("y")
        session.expect_exact("Execution plan sha256:")
        session.expect_exact("Approve this execution plan?")
        session.send("\r")
        session.expect_exact("plan approval declined")
        session.expect(pexpect.EOF)
        session.close()
    if session.exitstatus != 1 or not path.is_file() or list(path.parent.glob("*.state.json")):
        raise AssertionError("declined setup did not preserve just the saved profile")


if __name__ == "__main__":
    cli = str(Path(sys.argv[1]).resolve(strict=True))
    with tempfile.TemporaryDirectory() as temp:
        create_redis_profile(cli, Path(temp) / "redis.yaml")
        cancel_before_writing(cli, Path(temp) / "canceled.yaml")
        decline_save(cli, Path(temp) / "declined.yaml")
        review_plan(cli, Path(temp) / "approved.json", accept=True)
        review_plan(cli, Path(temp) / "declined.json", accept=False)
        setup_declines_before_ansible(cli, Path(temp) / "guided.yaml")
    print("Wizard smoke checks passed")
