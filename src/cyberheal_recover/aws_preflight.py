"""Read-only AWS readiness check; never mutates resources."""

import argparse
import json
import re
from typing import Any


def check_aws_lab(
    ec2: Any,
    sts: Any,
    *,
    account_id: str,
    region: str,
    lab_tag: str,
    instance_id: str,
    volume_id: str,
) -> dict[str, str]:
    """Validate expected AWS scope, tags and AZ relationships."""
    if not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("account ID must have 12 digits")
    if sts.get_caller_identity().get("Account") != account_id:
        raise PermissionError("unexpected AWS account")
    if getattr(getattr(ec2, "meta", None), "region_name", None) != region:
        raise PermissionError("unexpected AWS Region")
    reservations = ec2.describe_instances(InstanceIds=[instance_id]).get(
        "Reservations", []
    )
    instances = [
        i for reservation in reservations for i in reservation.get("Instances", [])
    ]
    volumes = ec2.describe_volumes(VolumeIds=[volume_id]).get("Volumes", [])
    if len(instances) != 1 or len(volumes) != 1:
        raise LookupError("test EC2 instance or EBS volume not found")
    instance, volume = instances[0], volumes[0]
    # Describe APIs should never be trusted merely because they returned one
    # object. Bind the response to the exact IDs supplied by the operator.
    if instance.get("InstanceId") != instance_id or volume.get("VolumeId") != volume_id:
        raise PermissionError("AWS response IDs differ from the approved lab inventory")

    def owned(item: dict[str, Any]) -> bool:
        return any(
            t.get("Key") == "CyberHealLab" and t.get("Value") == lab_tag
            for t in item.get("Tags", [])
        )

    if not owned(instance) or not owned(volume):
        raise PermissionError("resource missing the approved CyberHealLab tag")
    if instance.get("Placement", {}).get("AvailabilityZone") != volume.get(
        "AvailabilityZone"
    ):
        raise RuntimeError("instance and EBS data volume must share an AZ")
    if instance.get("State", {}).get("Name") not in {"running", "stopped"}:
        raise RuntimeError("EC2 test instance in unsupported state")
    attachments = volume.get("Attachments", [])
    # This readiness mode is for the *active* lab workload, not a detached
    # snapshot source or an EBS volume attached to a different instance.
    if len(attachments) != 1 or attachments[0].get("InstanceId") != instance_id:
        raise PermissionError("EBS data volume must be attached only to the approved EC2 instance")
    if attachments[0].get("State") != "attached":
        raise RuntimeError("EBS data volume attachment is not ready")
    if volume.get("State") != "in-use":
        raise RuntimeError("EBS data volume must be in-use on the test workload")
    if volume.get("Encrypted") is not True:
        raise PermissionError("test EBS volume must be encrypted")
    return {
        "account": account_id,
        "region": region,
        "instance": instance_id,
        "volume": volume_id,
        "availability_zone": volume["AvailabilityZone"],
        "instance_state": instance["State"]["Name"],
        "volume_state": volume.get("State", "unknown"),
        "mode": "READ_ONLY_NO_MUTATIONS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberHeal AWS read-only preflight")
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--lab-tag", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--volume-id", required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()
    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result = check_aws_lab(
        session.client("ec2"),
        session.client("sts"),
        account_id=args.account,
        region=args.region,
        lab_tag=args.lab_tag,
        instance_id=args.instance_id,
        volume_id=args.volume_id,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
