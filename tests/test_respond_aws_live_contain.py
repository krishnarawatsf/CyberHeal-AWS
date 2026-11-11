"""Mock-only tests for the opt-in AWS quarantine adapter."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from cyberheal_respond.aws_live_contain import AwsLabQuarantineAdapter
from cyberheal_respond.policy import Lab


class FakeSts:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class FakeCloud:
    meta = SimpleNamespace(region_name="ap-south-1")

    def __init__(self):
        self.calls = []
        self.instance = {
            "InstanceId": "i-EXAMPLE",
            "State": {"Name": "running"},
            "Tags": [{"Key": "CyberHealLab", "Value": "cyberheal-student-lab"}],
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-EXAMPLE"}}],
            "NetworkInterfaces": [{
                "VpcId": "vpc-lab",
                "Groups": [{"GroupId": "sg-original"}],
            }],
        }
        self.groups = {
            "sg-original": {"GroupId": "sg-original", "VpcId": "vpc-lab",
                            "Tags": [{"Key": "CyberHealLab", "Value": "cyberheal-student-lab"}],
                            "IpPermissions": [], "IpPermissionsEgress": [{"IpProtocol": "tcp"}]},
            "sg-MOCK-quarantine": {"GroupId": "sg-MOCK-quarantine", "VpcId": "vpc-lab",
                                   "Tags": [{"Key": "CyberHealLab", "Value": "cyberheal-student-lab"}],
                                   "IpPermissions": [], "IpPermissionsEgress": []},
        }

    def describe_instances(self, **kwargs):
        return {"Reservations": [{"Instances": [deepcopy(self.instance)]}]}

    def describe_security_groups(self, **kwargs):
        return {"SecurityGroups": [deepcopy(self.groups[x]) for x in kwargs["GroupIds"]]}

    def modify_instance_attribute(self, **kwargs):
        self.calls.append(kwargs)
        self.instance["NetworkInterfaces"][0]["Groups"] = [
            {"GroupId": x} for x in kwargs["Groups"]
        ]


def test_read_only_inventory_and_default_deny():
    cloud = FakeCloud()
    adapter = AwsLabQuarantineAdapter(cloud, FakeSts(), Lab())
    assert adapter.describe("i-EXAMPLE")["groups"] == ["sg-original"]
    with pytest.raises(PermissionError, match="disabled"):
        adapter.modify("i-EXAMPLE", ["sg-MOCK-quarantine"])
    assert cloud.calls == []


def test_explicit_opt_in_exact_quarantine_only():
    cloud = FakeCloud()
    adapter = AwsLabQuarantineAdapter(cloud, FakeSts(), Lab(), allow_mutations=True)
    with pytest.raises(PermissionError, match="only the designated"):
        adapter.modify("i-EXAMPLE", ["sg-original"])
    adapter.modify("i-EXAMPLE", ["sg-MOCK-quarantine"])
    assert cloud.calls == [{"InstanceId": "i-EXAMPLE", "Groups": ["sg-MOCK-quarantine"]}]


def test_untagged_instance_rejected():
    cloud = FakeCloud()
    cloud.instance["Tags"] = []
    with pytest.raises(PermissionError, match="ownership"):
        AwsLabQuarantineAdapter(cloud, FakeSts(), Lab()).describe("i-EXAMPLE")
    assert cloud.calls == []


def test_secondary_network_interface_rejected():
    cloud = FakeCloud()
    cloud.instance["NetworkInterfaces"].append({"VpcId": "vpc-lab", "Groups": []})
    with pytest.raises(PermissionError, match="single-network"):
        AwsLabQuarantineAdapter(cloud, FakeSts(), Lab()).describe("i-EXAMPLE")


def test_quarantine_group_with_egress_is_rejected():
    cloud = FakeCloud()
    cloud.groups["sg-MOCK-quarantine"]["IpPermissionsEgress"] = [{"IpProtocol": "-1"}]
    adapter = AwsLabQuarantineAdapter(cloud, FakeSts(), Lab(), allow_mutations=True)
    with pytest.raises(PermissionError, match="no rules"):
        adapter.modify("i-EXAMPLE", ["sg-MOCK-quarantine"])
    assert cloud.calls == []


def test_wrong_aws_account_rejected():
    class BadSts:
        def get_caller_identity(self):
            return {"Account": "999999999999"}

    with pytest.raises(PermissionError, match="account"):
        AwsLabQuarantineAdapter(FakeCloud(), BadSts(), Lab())
