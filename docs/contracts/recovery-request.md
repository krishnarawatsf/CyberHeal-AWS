# Member B → Member C recovery request contract (AWS v1)

**AWS redesign approved.** JSON field names remain the original v1 shape; `resource.vm_id` now identifies an AWS EC2 instance `i-*` and `resource.volume_id` an EBS data volume `vol-*`. The v1 recovery request is NOT an authorization token.

```json
{
  "incident_id":"49a29bc4-04ca-4ce7-8ead-2671c970e942",
  "resource":{"vm_id":"i-EXAMPLE","volume_id":"vol-EXAMPLE"},
  "requested_window":{"start":"2026-11-03T00:00:00Z","end":"2026-11-04T08:15:00Z"},
  "opa_decision_ref":"REFERENCE_TO_PROTECTED_APPROVAL_RECORD"
}
```

- `incident_id`: UUID, must match A's original incident.
- `resource.vm_id` / `.volume_id`: exact allow-listed test EC2/EBS pair. Both must belong to the expected AWS account, Region and `CyberHealLab` resource group.
- `requested_window.start/end`: timezone-aware timestamps, in UTC for messaging; C selects only independently validated EBS snapshots in window and **before** trusted first suspicious time.
- `opa_decision_ref`: opaque identifier into B's authenticated, protected audit store; NOT a bearer authorization. C must separately look up the approved `recover_volume` action, exact incident and resource, AWS account, expiry, single-use/replay controls. No lookup means no recovery.

**Required trusted side channel, absent from v1 JSON:** `first_suspicious_at` derived from B's trusted incident timeline, plus real signed/validated authorization. Either look up by incident ID in the shared trusted backend or agree a new versioned contract with A/B/C. Do not let a public caller choose these values.

**Fail closed:** reject unknown/invalid fields, blank ref, wrong resource, expired/ref-only approval, no signed clean snapshot, mismatched AWS metadata, missing permissions, duplicate operation. C's core library has no public HTTP endpoint yet; B may call it in-process through a trusted orchestration layer. See `docs/aws/01_MEMBER_B_BUILD_GUIDE.md`.
