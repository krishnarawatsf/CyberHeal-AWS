"""Use actual OPA, either its local executable or protected loopback HTTP server."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx


@dataclass(frozen=True)
class Lab:
    account_id: str = "123456789012"
    region: str = "ap-south-1"
    lab_tag: str = "cyberheal-student-lab"
    vm_id: str = "i-EXAMPLE"
    volume_id: str = "vol-EXAMPLE"
    quarantine_sg_id: str = "sg-MOCK-quarantine"

    @property
    def resource(self):
        return {"vm_id": self.vm_id, "volume_id": self.volume_id}

    @property
    def scope(self):
        return {
            "account_id": self.account_id,
            "region": self.region,
            "lab_tag": self.lab_tag,
        }


class OPA:
    def __init__(self, *, executable=None, policies=None, url=None, client=None):
        self.executable = (
            str(Path(executable).resolve())
            if executable and Path(executable).is_file()
            else executable
        )
        self.policies = Path(
            policies or Path(__file__).resolve().parents[2] / "respond" / "policies"
        )
        if url and urlparse(url).hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("OPA must use protected local transport")
        self.url = url
        self.client = client or httpx.Client(timeout=5, trust_env=False)

    def evaluate(self, value):
        try:
            if self.executable:
                completed = subprocess.run(
                    [
                        str(self.executable),
                        "eval",
                        "--format=json",
                        "--stdin-input",
                        "--data",
                        "cyberheal.rego",
                        "--data",
                        "lab.json",
                        "data.cyberheal.decision",
                    ],
                    input=json.dumps(value),
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=True,
                    cwd=self.policies,
                )
                decision = json.loads(completed.stdout)["result"][0]["expressions"][0][
                    "value"
                ]
            elif self.url:
                response = self.client.post(self.url, json={"input": value})
                response.raise_for_status()
                decision = response.json()["result"]
            else:
                raise RuntimeError("OPA unconfigured")
            if type(decision.get("allow")) is not bool or not isinstance(
                decision.get("version"), str
            ):
                raise ValueError("invalid OPA response")
            return decision
        except Exception:
            return {
                "allow": False,
                "version": "unavailable",
                "error": "opa_unavailable_or_invalid",
            }
