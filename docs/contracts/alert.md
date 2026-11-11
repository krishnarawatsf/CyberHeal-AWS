# Member A → Member B threat alert contract (AWS v1)

This contract retains Member A's existing `cyberheal_detect.models.ThreatAlert` fields: `schema_version` (`"1.0"`), `incident_id` (UUID v4), `timestamp` (ISO 8601 UTC), `resource.vm_id`, `resource.volume_id`, `alert_type` (`ransomware_like` or `credential_anomaly`), `confidence` (0.0–1.0), `features`, `evidence_refs`.

**Approved AWS semantics:** `resource.vm_id` is the explicitly allow-listed AWS EC2 test instance ID (`i-*`); `resource.volume_id` is its EBS sample-data volume ID (`vol-*`). No fake local IDs should be sent as live cloud resource IDs. Evidence references contain sanitized pointers only, never raw keys, passwords, AWS tokens or personal information. B validates schema versions, timestamps and resource allow-list.
