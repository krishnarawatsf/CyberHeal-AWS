"""No AWS network access: fake boto3 clients capture mutations."""

from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cyberheal_recover.aws_ebs import AwsEbsLabGateway

ACCOUNT = "123456789012"
REGION = "ap-south-1"
VOL = "vol-0123abcdef"
SNAP = "snap-1234abcdef"
LAB = "cyberheal-student-lab"
INCIDENT = str(uuid4())


class FakeSts:
    def __init__(self, account=ACCOUNT):
        self.account = account

    def get_caller_identity(self):
        return {"Account": self.account}


class FakeEc2:
    def __init__(self):
        self.meta = SimpleNamespace(region_name=REGION)
        self.calls = []
        self.volume = {
            "VolumeId": VOL,
            "State": "available",
            "Attachments": [],
            "AvailabilityZone": "ap-south-1a",
            "Tags": [{"Key": "CyberHealLab", "Value": LAB}],
        }
        self.snapshot = {
            "SnapshotId": SNAP,
            "OwnerId": ACCOUNT,
            "VolumeId": VOL,
            "State": "completed",
            "Tags": [{"Key": "CyberHealLab", "Value": LAB}],
        }

    def describe_volumes(self, **kwargs):
        self.calls.append(("describe_volumes", kwargs))
        return {"Volumes": [deepcopy(self.volume)]}

    def describe_snapshots(self, **kwargs):
        self.calls.append(("describe_snapshots", kwargs))
        return {"Snapshots": [deepcopy(self.snapshot)]}

    def create_volume(self, **kwargs):
        self.calls.append(("create_volume", kwargs))
        return {"VolumeId": "vol-abcdef1234"}

    def create_snapshot(self, **kwargs):
        self.calls.append(("create_snapshot", kwargs))
        return {"SnapshotId": "snap-abc123"}


def gateway(ec2=None, sts=None, enabled=False):
    return AwsEbsLabGateway(
        ec2 or FakeEc2(),
        sts or FakeSts(),
        account_id=ACCOUNT,
        region=REGION,
        lab_tag=LAB,
        approved_source_volume_id=VOL,
        allow_mutations=enabled,
    )


def test_wrong_account_rejected_before_api_actions():
    with pytest.raises(PermissionError, match="account"):
        gateway(sts=FakeSts("999999999999"))


def test_wrong_region_rejected():
    ec2 = FakeEc2()
    ec2.meta.region_name = "eu-west-1"
    with pytest.raises(PermissionError, match="Region"):
        gateway(ec2=ec2)


def test_mutation_disabled_by_default():
    ec2 = FakeEc2()
    with pytest.raises(PermissionError, match="mutations disabled"):
        gateway(ec2).create_recovery_volume(
            source_volume_id=VOL, snapshot_id=SNAP, incident_id=INCIDENT
        )
    assert not any(call[0].startswith("create_") for call in ec2.calls)


def test_valid_volume_clone_is_detached_and_scoped():
    ec2 = FakeEc2()
    volume_id = gateway(ec2, enabled=True).create_recovery_volume(
        source_volume_id=VOL, snapshot_id=SNAP, incident_id=INCIDENT
    )
    assert volume_id == "vol-abcdef1234"
    args = next(kwargs for name, kwargs in ec2.calls if name == "create_volume")
    assert args["Encrypted"] is True
    assert args["AvailabilityZone"] == "ap-south-1a"
    assert args["SnapshotId"] == SNAP
    assert args["ClientToken"] == "cyberheal-" + INCIDENT
    assert not any(k in args for k in ("InstanceId", "Device", "DeleteOnTermination"))


def test_wrong_snapshot_owner_rejected():
    ec2 = FakeEc2()
    ec2.snapshot["OwnerId"] = "999999999999"
    with pytest.raises(PermissionError, match="snapshot"):
        gateway(ec2, enabled=True).create_recovery_volume(
            source_volume_id=VOL, snapshot_id=SNAP, incident_id=INCIDENT
        )
    assert not any(x[0] == "create_volume" for x in ec2.calls)


def test_wrong_snapshot_source_rejected():
    ec2 = FakeEc2()
    ec2.snapshot["VolumeId"] = "vol-fffffffffff"
    with pytest.raises(PermissionError):
        gateway(ec2, enabled=True).create_recovery_volume(
            source_volume_id=VOL, snapshot_id=SNAP, incident_id=INCIDENT
        )


def test_source_lab_tag_missing_rejected():
    ec2 = FakeEc2()
    ec2.volume["Tags"] = []
    with pytest.raises(PermissionError, match="lab tag"):
        gateway(ec2, enabled=True).create_recovery_volume(
            source_volume_id=VOL, snapshot_id=SNAP, incident_id=INCIDENT
        )


def test_wrong_input_volume_rejected():
    ec2 = FakeEc2()
    with pytest.raises(PermissionError, match="allow-list"):
        gateway(ec2, enabled=True).create_recovery_volume(
            source_volume_id="vol-different", snapshot_id=SNAP, incident_id=INCIDENT
        )
    assert not ec2.calls


def test_invalid_incident_rejected():
    with pytest.raises(ValueError, match="UUID"):
        gateway(enabled=True).create_recovery_volume(
            source_volume_id=VOL, snapshot_id=SNAP, incident_id="not-a-uuid"
        )


def test_snapshot_requires_detached_data_volume():
    ec2 = FakeEc2()
    ec2.volume["State"] = "in-use"
    with pytest.raises(RuntimeError, match="detached"):
        gateway(ec2, enabled=True).create_snapshot_of_clean_detached_volume(
            name="cyberheal-baseline"
        )
    assert not any(x[0] == "create_snapshot" for x in ec2.calls)


def test_snapshot_created_is_not_declared_clean():
    ec2 = FakeEc2()
    assert (
        gateway(ec2, enabled=True).create_snapshot_of_clean_detached_volume(
            name="cyberheal-clean-candidate"
        )
        == "snap-abc123"
    )
    args = next(kwargs for name, kwargs in ec2.calls if name == "create_snapshot")
    assert args["VolumeId"] == VOL
    assert "VerifiedClean" not in str(args)


def test_no_snapshot_create_without_opt_in():
    ec2 = FakeEc2()
    with pytest.raises(PermissionError):
        gateway(ec2).create_snapshot_of_clean_detached_volume(name="cyberheal-baseline")
    assert not any(name == "create_snapshot" for name, _ in ec2.calls)
