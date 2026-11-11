"""Opt-in AWS EC2 quarantine adapter for B's existing `quarantine()` workflow.

Not wired into FastAPI. An authorized operator must separately configure an
AWS lab identity, replace mock inventory IDs and turn on mutations. This is
unit-testable but has not been exercised against a live AWS account.
"""

from typing import Any


def _tag(tags: list[dict[str, str]] | None, key: str) -> str | None:
    return next((t.get("Value") for t in (tags or []) if t.get("Key") == key), None)


class AwsLabQuarantineAdapter:
    """Fail-closed EC2 adapter with the same `describe`/`modify` as FakeEC2."""

    def __init__(
        self,
        ec2: Any,
        sts: Any,
        lab: Any,
        *,
        allow_mutations: bool = False,
    ) -> None:
        self.ec2 = ec2
        self.lab = lab
        self.allow_mutations = allow_mutations
        if getattr(getattr(ec2, "meta", None), "region_name", None) != lab.region:
            raise PermissionError("AWS client Region does not match approved lab")
        if str(sts.get_caller_identity().get("Account", "")) != lab.account_id:
            raise PermissionError("AWS identity does not match approved lab account")

    def _instance(self, instance_id: str) -> dict[str, Any]:
        if instance_id != self.lab.vm_id:
            raise PermissionError("instance outside approved test inventory")
        reservations = self.ec2.describe_instances(InstanceIds=[instance_id]).get(
            "Reservations", []
        )
        instances = [
            instance
            for reservation in reservations
            for instance in reservation.get("Instances", [])
        ]
        if len(instances) != 1 or instances[0].get("InstanceId") != instance_id:
            raise PermissionError("AWS instance inventory does not match approved ID")
        instance = instances[0]
        if _tag(instance.get("Tags"), "CyberHealLab") != self.lab.lab_tag:
            raise PermissionError("instance missing lab ownership tag")
        if instance.get("State", {}).get("Name") not in {"running", "stopped"}:
            raise PermissionError("instance state is not supported")
        mappings = instance.get("BlockDeviceMappings", [])
        if self.lab.volume_id not in {
            entry.get("Ebs", {}).get("VolumeId") for entry in mappings
        }:
            raise PermissionError("approved data volume is not attached to instance")
        nics = instance.get("NetworkInterfaces", [])
        if len(nics) != 1:
            raise PermissionError("only single-network-interface lab instances allowed")
        return instance

    def _groups(self, instance: dict[str, Any]) -> list[str]:
        nics = instance["NetworkInterfaces"]
        groups = [g["GroupId"] for g in nics[0].get("Groups", [])]
        if not groups or len(groups) != len(set(groups)):
            raise PermissionError("instance security group inventory incomplete")
        self._verify_group_scope(groups, nics[0]["VpcId"])
        return groups

    def _verify_group_scope(self, ids: list[str], vpc: str) -> None:
        groups = self.ec2.describe_security_groups(GroupIds=ids).get(
            "SecurityGroups", []
        )
        if {g.get("GroupId") for g in groups} != set(ids):
            raise PermissionError("security group lookup mismatches requested groups")
        if any(
            g.get("VpcId") != vpc
            or _tag(g.get("Tags"), "CyberHealLab") != self.lab.lab_tag
            for g in groups
        ):
            raise PermissionError("security groups not in approved lab VPC")
        for group in groups:
            if group.get("GroupId") == self.lab.quarantine_sg_id and (
                group.get("IpPermissions") or group.get("IpPermissionsEgress")
            ):
                raise PermissionError("quarantine security group must have no rules")

    def describe(self, vm_id: str) -> dict[str, Any]:
        instance = self._instance(vm_id)
        groups = self._groups(instance)
        return {
            "instance_id": vm_id,
            "account_id": self.lab.account_id,
            "region": self.lab.region,
            "lab_tag": self.lab.lab_tag,
            "interfaces": 1,
            "volume_id": self.lab.volume_id,
            "groups": groups,
        }

    def modify(self, vm_id: str, groups: list[str]) -> None:
        if not self.allow_mutations:
            raise PermissionError("live AWS containment is disabled by default")
        if groups != [self.lab.quarantine_sg_id]:
            raise PermissionError("only the designated no-egress quarantine SG is permitted")
        instance = self._instance(vm_id)
        self._groups(instance)
        self._verify_group_scope(groups, instance["NetworkInterfaces"][0]["VpcId"])
        # No rule creation, no IAM changes, no other AWS mutations.
        self.ec2.modify_instance_attribute(InstanceId=vm_id, Groups=groups)
