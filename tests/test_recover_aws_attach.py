"""The isolated verifier attachment has no real cloud side effects in tests."""
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cyberheal_recover.aws_attach import AwsIsolatedVerifierAttachment

V = "vol-" + "1" * 17
S = "snap-" + "2" * 17
INST_ID = "i-" + "3" * 17
INCIDENT = str(uuid4())


class STS:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class EC2:
    meta = SimpleNamespace(region_name="ap-south-1")

    def __init__(self):
        self.calls = []
        self.instance = {
            "InstanceId": INST_ID,
            "State": {"Name": "running"},
            "Placement": {"AvailabilityZone": "ap-south-1a"},
            "NetworkInterfaces": [{"Groups": [{"GroupId": "sg-lab"}]}],
            "Tags": [
                {"Key": "CyberHealLab", "Value": "lab"},
                {"Key": "Role", "Value": "CyberHealVerifier"},
            ],
        }
        self.volume = {
            "VolumeId": V,
            "State": "available",
            "Attachments": [],
            "Encrypted": True,
            "SnapshotId": S,
            "AvailabilityZone": "ap-south-1a",
            "Tags": [
                {"Key": "CyberHealLab", "Value": "lab"},
                {"Key": "ManagedBy", "Value": "MemberC"},
                {"Key": "IncidentId", "Value": INCIDENT},
            ],
        }

    def describe_instances(self, **kwargs):
        return {"Reservations": [{"Instances": [deepcopy(self.instance)]}]}

    def describe_volumes(self, **kwargs):
        return {"Volumes": [deepcopy(self.volume)]}

    def attach_volume(self, **kwargs):
        self.calls.append(kwargs)


def gateway(ec2, allow_mutations=False):
    return AwsIsolatedVerifierAttachment(
        ec2, STS(), account_id="123456789012", region="ap-south-1",
        lab_tag="lab", verifier_instance_id=INST_ID, allow_mutations=allow_mutations,
    )


def test_readonly_preflight_and_default_deny():
    ec2 = EC2()
    assert gateway(ec2).inspect(recovered_volume_id=V, snapshot_id=S, incident_id=INCIDENT)["volume_id"] == V
    with pytest.raises(PermissionError, match="disabled"):
        gateway(ec2).attach(recovered_volume_id=V, snapshot_id=S, incident_id=INCIDENT)
    assert ec2.calls == []


def test_explicitly_authorized_attachment_request():
    ec2 = EC2()
    result = gateway(ec2, True).attach(recovered_volume_id=V, snapshot_id=S, incident_id=INCIDENT)
    assert result["status"] == "ATTACH_REQUESTED_NOT_VERIFIED_OR_MOUNTED"
    assert ec2.calls == [{"VolumeId": V, "InstanceId": INST_ID, "Device": "/dev/sdf"}]


@pytest.mark.parametrize("field,value", [
    ("State", "in-use"),
    ("Encrypted", False),
    ("SnapshotId", "snap-" + "0" * 17),
    ("AvailabilityZone", "ap-south-1b"),
])
def test_wrong_volume_state_prevents_attach(field, value):
    ec2 = EC2()
    ec2.volume[field] = value
    with pytest.raises(PermissionError):
        gateway(ec2, True).attach(recovered_volume_id=V, snapshot_id=S, incident_id=INCIDENT)
    assert ec2.calls == []


def test_verifier_without_role_prevents_attach():
    ec2 = EC2()
    ec2.instance["Tags"] = []
    with pytest.raises(PermissionError):
        gateway(ec2, True).attach(recovered_volume_id=V, snapshot_id=S, incident_id=INCIDENT)
    assert ec2.calls == []


def test_cross_incident_prevents_attach():
    ec2 = EC2()
    with pytest.raises(PermissionError):
        gateway(ec2, True).attach(recovered_volume_id=V, snapshot_id=S, incident_id=str(uuid4()))
    assert ec2.calls == []
