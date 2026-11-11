"""Conservative AWS EBS adapter for the isolated CyberHeal student lab.

IMPORTANT: This implements only creating snapshots and *new detached* volumes.
It never mounts data, changes security groups, deletes snapshots, attaches
volumes, or marks a recovered workload safe. Live mutating calls require an
explicit opt-in; do not connect to an unrestricted AWS identity.

Boto3 clients are injected for offline tests and safety review.
"""

import re
from typing import Any
from uuid import UUID

ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
RESOURCE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$")


def _tag_value(tags: list[dict[str, str]] | None, key: str) -> str | None:
    for tag in tags or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


class AwsEbsLabGateway:
    """Strictly scoped access to a known AWS account, Region and source volume.

    `allow_mutations` is False by default. IAM must separately enforce least
    privilege because application-level tags and checks are defense in depth.
    """

    def __init__(
        self,
        ec2: Any,
        sts: Any,
        *,
        account_id: str,
        region: str,
        lab_tag: str,
        approved_source_volume_id: str,
        allow_mutations: bool = False,
    ) -> None:
        if not ACCOUNT_RE.fullmatch(account_id):
            raise ValueError("expected AWS account ID must have 12 digits")
        if not lab_tag or not RESOURCE_RE.fullmatch(lab_tag):
            raise ValueError("explicit lab tag is required")
        if not re.fullmatch(r"vol-[0-9a-f]+", approved_source_volume_id):
            raise ValueError("approved source must be an EBS vol-* ID")
        if not region:
            raise ValueError("AWS Region is required")
        actual_region = getattr(getattr(ec2, "meta", None), "region_name", None)
        if actual_region != region:
            raise PermissionError("EC2 client does not match the approved Region")
        actual_account = str(sts.get_caller_identity().get("Account", ""))
        if actual_account != account_id:
            raise PermissionError("AWS identity is not in the approved account")
        self.ec2 = ec2
        self.account_id = account_id
        self.region = region
        self.lab_tag = lab_tag
        self.source_volume_id = approved_source_volume_id
        self.allow_mutations = allow_mutations

    def _require_mutations(self) -> None:
        if not self.allow_mutations:
            raise PermissionError(
                "AWS mutations disabled: require an explicit lab opt-in"
            )

    def _source_volume(self) -> dict[str, Any]:
        volumes = self.ec2.describe_volumes(VolumeIds=[self.source_volume_id]).get(
            "Volumes", []
        )
        if len(volumes) != 1 or volumes[0].get("VolumeId") != self.source_volume_id:
            raise LookupError("approved source EBS volume is not found")
        volume = volumes[0]
        if _tag_value(volume.get("Tags"), "CyberHealLab") != self.lab_tag:
            raise PermissionError("EBS volume missing the approved lab tag")
        return volume

    def create_snapshot_of_clean_detached_volume(self, *, name: str) -> str:
        """Create an UNTRUSTED snapshot, to be validated separately.

        It requires a detached source volume for crash-consistency simplicity;
        snapshot success is not independent evidence that its data is clean.
        """
        if not name or not name.startswith("cyberheal-") or len(name) > 80:
            raise ValueError("snapshot name must begin with cyberheal- (max 80)")
        volume = self._source_volume()
        if volume.get("State") != "available" or volume.get("Attachments"):
            raise RuntimeError(
                "clean baseline snapshot requires detached available EBS volume"
            )
        self._require_mutations()
        response = self.ec2.create_snapshot(
            VolumeId=self.source_volume_id,
            Description=name,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "CyberHealLab", "Value": self.lab_tag},
                        {"Key": "ManagedBy", "Value": "MemberC"},
                    ],
                }
            ],
        )
        snapshot_id = str(response.get("SnapshotId", ""))
        if not re.fullmatch(r"snap-[0-9a-f]+", snapshot_id):
            raise RuntimeError("AWS did not return a valid snapshot ID")
        return snapshot_id

    def create_recovery_volume(
        self, *, source_volume_id: str, snapshot_id: str, incident_id: str
    ) -> str:
        """Create a NEW, detached, encrypted volume; never replace source data.

        The caller is responsible for prior authorization, clean-baseline
        selection, audit logging, and later isolated verification. The adapter
        confirms that AWS snapshot belongs to the expected volume and account.
        """
        if source_volume_id != self.source_volume_id:
            raise PermissionError("source EBS volume outside the lab allow-list")
        try:
            incident = UUID(incident_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("incident_id must be a UUID") from exc
        if not re.fullmatch(r"snap-[0-9a-f]+", snapshot_id):
            raise ValueError("invalid EBS snapshot ID")
        volume = self._source_volume()
        snapshots = self.ec2.describe_snapshots(SnapshotIds=[snapshot_id]).get(
            "Snapshots", []
        )
        if len(snapshots) != 1 or snapshots[0].get("SnapshotId") != snapshot_id:
            raise LookupError("EBS snapshot is not found")
        snapshot = snapshots[0]
        if (
            snapshot.get("OwnerId") != self.account_id
            or snapshot.get("VolumeId") != self.source_volume_id
            or snapshot.get("State") != "completed"
            or _tag_value(snapshot.get("Tags"), "CyberHealLab") != self.lab_tag
        ):
            raise PermissionError(
                "snapshot is not a completed, lab-owned source snapshot"
            )
        az = volume.get("AvailabilityZone")
        if not isinstance(az, str) or not az.startswith(self.region):
            raise PermissionError("source volume has an unexpected Availability Zone")
        self._require_mutations()
        # ClientToken makes retries of the SAME request idempotent within AWS's
        # supported idempotency behavior. Durable job records remain necessary.
        result = self.ec2.create_volume(
            SnapshotId=snapshot_id,
            AvailabilityZone=az,
            VolumeType="gp3",
            Encrypted=True,
            ClientToken=f"cyberheal-{incident}",
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "Name", "Value": f"cyberheal-recovery-{incident}"},
                        {"Key": "CyberHealLab", "Value": self.lab_tag},
                        {"Key": "IncidentId", "Value": str(incident)},
                        {"Key": "ManagedBy", "Value": "MemberC"},
                    ],
                }
            ],
        )
        volume_id = str(result.get("VolumeId", ""))
        if not re.fullmatch(r"vol-[0-9a-f]+", volume_id):
            raise RuntimeError("AWS did not return a valid recovered EBS volume ID")
        return volume_id


def boto3_lab_gateway(
    *,
    account_id: str,
    region: str,
    lab_tag: str,
    approved_source_volume_id: str,
    allow_mutations: bool = False,
    profile_name: str | None = None,
) -> AwsEbsLabGateway:
    """Construct the live gateway via the AWS SDK credential chain.

    No credentials are stored in source, config or logs; caller must use an
    AWS SSO/role profile or the standard AWS credential chain.
    """
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("install boto3 to connect to AWS") from exc
    session = boto3.Session(profile_name=profile_name, region_name=region)
    return AwsEbsLabGateway(
        session.client("ec2"),
        session.client("sts"),
        account_id=account_id,
        region=region,
        lab_tag=lab_tag,
        approved_source_volume_id=approved_source_volume_id,
        allow_mutations=allow_mutations,
    )
