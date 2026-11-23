"""Emit approved metadata only. Task output can contain sensitive values."""

import json

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "serverforge"

    def __init__(self):
        super().__init__()
        self.target_id = ""
        self.failure = ""

    def v2_runner_on_ok(self, result):
        if result.task_name == "Report verified target identity":
            self.target_id = result.result.get("ansible_facts", {}).get("sf_machine_id", "")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if not ignore_errors and not self.failure:
            self.failure = result.task_name

    def v2_runner_on_unreachable(self, result):
        if not self.failure:
            self.failure = result.task_name

    def v2_playbook_on_stats(self, stats):
        hosts = [stats.summarize(host) for host in stats.processed]
        self._display.display(json.dumps({
            "target_id": self.target_id,
            "failure": self.failure,
            "changed": sum(host["changed"] for host in hosts),
            "skipped": sum(host["skipped"] for host in hosts),
            "hosts": len(hosts),
        }))
