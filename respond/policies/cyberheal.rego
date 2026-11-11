package cyberheal

import rego.v1

default allow := false

allow if {
    input.subject.actor in data.lab.actors
    input.subject.roles == ["incident-responder"]
    input.action in {"quarantine_instance", "recover_volume"}
    input.scope == {"account_id": data.lab.account_id, "region": data.lab.region, "lab_tag": data.lab.lab_tag}
    input.resource == data.lab.resource
    regex.match(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, input.incident_id)
    object.keys(input) == {"subject", "action", "scope", "resource", "incident_id"}
}

decision := {"allow": allow, "version": "cyberheal-b-0.1"}
