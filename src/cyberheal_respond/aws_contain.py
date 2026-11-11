"""Mock-only quarantine. No credentials, boto3 session, or live mutation path."""


class FakeEC2:
    def __init__(self, lab):
        self.lab = lab
        self.groups = ["sg-MOCK-original"]
        self.interfaces = 1
        self.account_id = lab.account_id
        self.region = lab.region
        self.tag = lab.lab_tag
        self.fail = False
        self.changes = []

    def describe(self, vm_id):
        if vm_id != self.lab.vm_id:
            raise PermissionError("instance not allow-listed")
        return {
            "instance_id": vm_id,
            "account_id": self.account_id,
            "region": self.region,
            "lab_tag": self.tag,
            "interfaces": self.interfaces,
            "volume_id": self.lab.volume_id,
            "groups": list(self.groups),
        }

    def modify(self, vm_id, groups):
        if vm_id != self.lab.vm_id:
            raise PermissionError("wrong instance")
        if self.fail:
            raise RuntimeError("simulated EC2 failure")
        self.changes.append({"instance_id": vm_id, "groups": groups})
        self.groups = list(groups)


def quarantine(*, ec2, store, lab, incident, approval):
    if (
        approval["action"] != "quarantine_instance"
        or approval["allowed"] is not True
        or approval["resource"] != lab.resource
    ):
        raise PermissionError("quarantine approval required")
    actual = ec2.describe(lab.vm_id)
    if (
        any(actual[key] != value for key, value in lab.scope.items())
        or actual["interfaces"] != 1
        or actual["volume_id"] != lab.volume_id
    ):
        raise PermissionError("instance inventory validation failed")
    store.audit(
        incident,
        "quarantine_proposed",
        {
            "mock": True,
            "resource": lab.resource,
            "previous_sg_ids": actual["groups"],
            "proposed_sg_ids": [lab.quarantine_sg_id],
        },
    )
    ec2.modify(lab.vm_id, [lab.quarantine_sg_id])
    if ec2.describe(lab.vm_id)["groups"] != [lab.quarantine_sg_id]:
        raise RuntimeError("quarantine verification failed")
    return {
        "mock": True,
        "resource": lab.resource,
        "previous_sg_ids": actual["groups"],
        "quarantine_sg_ids": [lab.quarantine_sg_id],
        "rollback": "operator_review_required",
    }
