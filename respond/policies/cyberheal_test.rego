package cyberheal_test

import rego.v1
import data.cyberheal

valid := {
    "subject": {"actor": "approved-demo-operator", "roles": ["incident-responder"]},
    "action": "quarantine_instance",
    "scope": {"account_id": "123456789012", "region": "ap-south-1", "lab_tag": "cyberheal-student-lab"},
    "resource": {"vm_id": "i-EXAMPLE", "volume_id": "vol-EXAMPLE"},
    "incident_id": "49a29bc4-04ca-4ce7-8ead-2671c970e942",
}

test_allow_quarantine if { cyberheal.allow with input as valid }
test_allow_recovery if { cyberheal.allow with input as object.union(valid, {"action": "recover_volume"}) }
test_deny_empty if { not cyberheal.allow with input as {} }
test_deny_action if { not cyberheal.allow with input as object.union(valid, {"action": "delete_volume"}) }
test_deny_account if { not cyberheal.allow with input as object.union(valid, {"scope": object.union(valid.scope, {"account_id": "000000000000"})}) }
test_deny_region if { not cyberheal.allow with input as object.union(valid, {"scope": object.union(valid.scope, {"region": "us-east-1"})}) }
test_deny_tag if { not cyberheal.allow with input as object.union(valid, {"scope": object.union(valid.scope, {"lab_tag": "prod"})}) }
test_deny_instance if { not cyberheal.allow with input as object.union(valid, {"resource": object.union(valid.resource, {"vm_id": "i-other"})}) }
test_deny_volume if { not cyberheal.allow with input as object.union(valid, {"resource": object.union(valid.resource, {"volume_id": "vol-other"})}) }
test_deny_role if { not cyberheal.allow with input as object.union(valid, {"subject": {"actor": "approved-demo-operator", "roles": ["admin"]}}) }
test_deny_actor if { not cyberheal.allow with input as object.union(valid, {"subject": {"actor": "unknown", "roles": ["incident-responder"]}}) }
test_deny_uuid if { not cyberheal.allow with input as object.union(valid, {"incident_id": "bad"}) }
test_deny_extra if { not cyberheal.allow with input as object.union(valid, {"extra": true}) }
test_deny_missing if { not cyberheal.allow with input as object.remove(valid, ["scope"]) }
