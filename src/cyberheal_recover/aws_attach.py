"""Opt-in attachment of an already restored EBS clone to a tagged verifier EC2.

This module does not mount, scan, execute, detach, delete or return a SAFE result.
The operator must separately confirm an approved incident and an authorized
recovery job. Mutations default to disabled; IAM least privilege is essential.
"""

import re
from typing import Any
from uuid import UUID


def _tag(tags: list[dict[str, str]] | None, name: str) -> str | None:
    return next((t.get("Value") for t in (tags or []) if t.get("Key") == name), None)


class AwsIsolatedVerifierAttachment:
    def __init__(
        self,
        ec2: Any,
        sts: Any,
        *,
        account_id: str,
        region: str,
        lab_tag: str,
        verifier_instance_id: str,
        allow_mutations: bool = False,
    ) -> None:
        if not re.fullmatch(r"\d{12}", account_id):
            raise ValueError("12-digit account required")
        if not re.fullmatch(r"i-[0-9a-f]{17}", verifier_instance_id):
            raise ValueError("real verifier instance ID required")
        if not lab_tag:
            raise ValueError("lab tag required")
        if getattr(getattr(ec2, "meta", None), "region_name", None) != region:
            raise PermissionError("AWS region mismatch")
        if str(sts.get_caller_identity().get("Account", "")) != account_id:
            raise PermissionError("AWS account mismatch")
        self.ec2 = ec2
        self.lab_tag = lab_tag
        self.verifier = verifier_instance_id
        self.allow_mutations = allow_mutations

    def inspect(self, *, recovered_volume_id: str, snapshot_id: str, incident_id: str) -> dict:
        """Read-only scope validation, including the expected snapshot and job."""
        if not re.fullmatch(r"vol-[0-9a-f]{17}", recovered_volume_id):
            raise ValueError("real recovered volume ID required")
        if not re.fullmatch(r"snap-[0-9a-f]{17}", snapshot_id):
            raise ValueError("real snapshot ID required")
        incident_id = str(UUID(incident_id))
        reservations = self.ec2.describe_instances(InstanceIds=[self.verifier]).get(
            "Reservations", []
        )
        instances = [
            item
            for reservation in reservations
            for item in reservation.get("Instances", [])
        ]
        if len(instances) != 1 or instances[0].get("InstanceId") != self.verifier:
            raise PermissionError("unexpected verifier inventory")
        instance = instances[0]
        if (
            instance.get("State", {}).get("Name") != "running"
            or _tag(instance.get("Tags"), "CyberHealLab") != self.lab_tag
            or _tag(instance.get("Tags"), "Role") != "CyberHealVerifier"
            or len(instance.get("NetworkInterfaces", [])) != 1
        ):
            raise PermissionError("verifier not an approved running isolated worker")
        volumes = self.ec2.describe_volumes(VolumeIds=[recovered_volume_id]).get(
            "Volumes", []
        )
        if len(volumes) != 1 or volumes[0].get("VolumeId") != recovered_volume_id:
            raise PermissionError("unexpected recovery volume inventory")
        volume = volumes[0]
        if (
            volume.get("State") != "available"
            or volume.get("Attachments")
            or volume.get("Encrypted") is not True
            or volume.get("SnapshotId") != snapshot_id
            or _tag(volume.get("Tags"), "CyberHealLab") != self.lab_tag
            or _tag(volume.get("Tags"), "IncidentId") != incident_id
            or _tag(volume.get("Tags"), "ManagedBy") != "MemberC"
            or volume.get("AvailabilityZone")
            != instance.get("Placement", {}).get("AvailabilityZone")
        ):
            raise PermissionError("recovered volume not eligible for verifier attachment")
        return {
            "instance_id": self.verifier,
            "volume_id": recovered_volume_id,
            "snapshot_id": snapshot_id,
            "incident_id": incident_id,
            "availability_zone": volume["AvailabilityZone"],
            "mutation_allowed": self.allow_mutations,
        }

    def attach(self, *, recovered_volume_id: str, snapshot_id: str, incident_id: str) -> dict:
        if not self.allow_mutations:
            raise PermissionError("EBS attachment disabled by default")
        inspected = self.inspect(
            recovered_volume_id=recovered_volume_id,
            snapshot_id=snapshot_id,
            incident_id=incident_id,
        )
        # AWS Nitro/EC2 can map /dev/sdf to a different /dev/nvme*n* path.
        # Never assume the OS pathname without verifying NVMe serial == EBS ID.
        self.ec2.attach_volume(
            VolumeId=recovered_volume_id,
            InstanceId=self.verifier,
            Device="/dev/sdf",
        )
        return {**inspected, "status": "ATTACH_REQUESTED_NOT_VERIFIED_OR_MOUNTED"}
