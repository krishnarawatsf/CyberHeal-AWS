from copy import deepcopy
from types import SimpleNamespace

import pytest

from cyberheal_recover.aws_preflight import check_aws_lab


class Sts:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class Ec2:
    meta = SimpleNamespace(region_name="ap-south-1")
    instance = {
        "InstanceId": "i-abc123",
        "Placement": {"AvailabilityZone": "ap-south-1a"},
        "State": {"Name": "running"},
        "Tags": [{"Key": "CyberHealLab", "Value": "lab"}],
    }
    volume = {
        "VolumeId": "vol-abc123",
        "AvailabilityZone": "ap-south-1a",
        "State": "in-use",
        "Encrypted": True,
        "Attachments": [{"InstanceId": "i-abc123", "State": "attached"}],
        "Tags": [{"Key": "CyberHealLab", "Value": "lab"}],
    }

    def describe_instances(self, **kwargs):
        return {"Reservations": [{"Instances": [deepcopy(self.instance)]}]}

    def describe_volumes(self, **kwargs):
        return {"Volumes": [deepcopy(self.volume)]}


def run(ec2):
    return check_aws_lab(
        ec2,
        Sts(),
        account_id="123456789012",
        region="ap-south-1",
        lab_tag="lab",
        instance_id="i-abc123",
        volume_id="vol-abc123",
    )


def test_readonly_scope_succeeds():
    output = run(Ec2())
    assert output["mode"] == "READ_ONLY_NO_MUTATIONS"


def test_cross_zone_rejected():
    ec2 = Ec2()
    ec2.volume = deepcopy(Ec2.volume)
    ec2.volume["AvailabilityZone"] = "ap-south-1b"
    with pytest.raises(RuntimeError, match="AZ"):
        run(ec2)


def test_untagged_vm_rejected():
    ec2 = Ec2()
    ec2.instance = deepcopy(Ec2.instance)
    ec2.instance["Tags"] = []
    with pytest.raises(PermissionError):
        run(ec2)


def test_mismatched_returned_instance_id_rejected():
    ec2 = Ec2()
    ec2.instance = deepcopy(Ec2.instance)
    ec2.instance["InstanceId"] = "i-other"
    with pytest.raises(PermissionError, match="IDs"):
        run(ec2)


def test_mismatched_returned_volume_id_rejected():
    ec2 = Ec2()
    ec2.volume = deepcopy(Ec2.volume)
    ec2.volume["VolumeId"] = "vol-other"
    with pytest.raises(PermissionError, match="IDs"):
        run(ec2)


def test_wrong_volume_attachment_rejected():
    ec2 = Ec2()
    ec2.volume = deepcopy(Ec2.volume)
    ec2.volume["Attachments"][0]["InstanceId"] = "i-untrusted"
    with pytest.raises(PermissionError, match="attached only"):
        run(ec2)


def test_unencrypted_volume_rejected():
    ec2 = Ec2()
    ec2.volume = deepcopy(Ec2.volume)
    ec2.volume["Encrypted"] = False
    with pytest.raises(PermissionError, match="encrypted"):
        run(ec2)


def test_detached_volume_not_ready():
    ec2 = Ec2()
    ec2.volume = deepcopy(Ec2.volume)
    ec2.volume["Attachments"] = []
    with pytest.raises(PermissionError, match="attached only"):
        run(ec2)
