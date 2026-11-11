# OpenStack runbook — only when the college confirms a test cloud

**Current status: NOT DEPLOYED, NOT LIVE TESTED.** Do not apply these steps to
an unknown cloud or a non-test project. Never paste credentials into chat or
WhatsApp. Configure an uncommitted, limited-scope `clouds.yaml` or environment.

## 1. Read-only capability discovery

Run on an authorized machine after installing the OpenStack CLI and SDK:

```bash
openstack token issue             # check only locally; do NOT share token output
openstack catalog list
openstack server list
openstack network list
openstack volume list
openstack volume snapshot list
python -m cyberheal_recover.preflight --cloud APPROVED_PROFILE
```

The Python preflight lists resource counts only, after making an SDK
connection. If a service is absent, stop and ask A/instructor; do not assume
admin access or install OpenStack on your laptop without a lab plan.

## 2. Infrastructure planning

The templates in `infra/tofu/` are **disabled by default**. Copy
`terraform.tfvars.example` to an unshared `terraform.tfvars`, enter the
approved image/flavor/project profile and CIDR; run `tofu fmt`, `init`,
`validate`, `plan`. Keep `enable_lab_resources=false` until reviewed. A real
apply requires project quotas and an agreed state owner; the lab may already
have VMs, in which case import/adapt rather than duplicating them.

Ansible creates only the dedicated sample directory; its inventory and
playbook require SSH access and permission. It does not mount a Cinder volume.

## 3. Clean snapshot lifecycle

- Put ONLY synthetic sample data on an explicitly allowlisted test volume.
- Capture expected SHA-256 hashes/config baselines and secure them separately
  before running any simulation.
- Ensure application consistency; for the initial demo, stop/quiesce the
  sample workload and snapshot a detached, `available` volume.
- A snapshot does not become "trusted" merely by setting a `clean` tag.
  Verify it in an isolated worker against known-good baselines; record proof
  and timestamp in an independent registry owned by C.
- Never delete original incident data or audit snapshots during the demo.

## 4. Recovery lifecycle

- Reject requests until the B policy approval has been independently verified
  for the exact incident/project/VM/volume and has not expired or been used.
- Select a verified-clean snapshot before the trusted first suspicious time.
- Clone to a NEW Cinder volume. Do not overwrite/revert the original volume.
- Wait for the new volume to become `available` and attach it ONLY to a
  predetermined isolated recovery VM; do not automatically attach it to VM-1.
- On that isolated VM, read recovered data in a safe mode and collect real
  SHA-256 hashes, configuration checks, application functional check and
  separately verify Keystone identity/Neutron network state.
- Produce result JSON and audit every attempt, including failures. Do not
  change routing or release isolation unless all policy gates allow it and the
  agreed change/review procedure has completed.

**The current `run_recovery` coordinator and SDK adapter stop short of live
attachment/scan and do not implement the durable authorization/registry/job
backends.** B's API and the cloud are still missing. A/B/C must complete and
repeat end-to-end real-world tests to claim deployment success.

## 5. Suggested evaluation metrics

- Recovery Time Objective (RTO): measured time from incident approval to a
  verified restored workload in the isolated lab.
- Recovery Point Objective (RPO): time between the clean snapshot and the
  first suspicious activity; estimate data loss exposure.
- Snapshot selection success/failure rates across synthetic scenarios.
- Verification false SAFE rate under deliberately failed checks.
- API rejection rate of missing, expired or mismatched approvals.

Measure rather than invent results. Capture timestamps and raw test logs without
secrets; have A compile the team-wide evaluation table.

## 6. Optional scaling

Senlin needs an installed service and a clearly defined **stateless worker**
profile. A Cinder stateful data volume is **not** suitable for blind scale-out.
If Senlin is unavailable, request the instructor-approved Heat/scripted demo
fallback, as allowed in the project guide.
