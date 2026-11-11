# Member C → Member B and A verification result contract (AWS v1)

Response fields are unchanged from the original v1 proposal. **`snapshot_id` is an AWS EBS `snap-*` ID.** The score and decision are based on actual verification evidence, not LLM output or a public request value.

```json
{
  "schema_version":"1.0",
  "incident_id":"49a29bc4-04ca-4ce7-8ead-2671c970e942",
  "rcs":100.0,
  "factor_scores":{"identity":100,"file_integrity":100,"network":100,"configuration":100,"health":100},
  "decision":"SAFE",
  "snapshot_id":"snap-EXAMPLE"
}
```

Formula from original guide: `RCS = 0.25*identity + 0.25*file_integrity + 0.20*network + 0.15*configuration + 0.15*health`, each factor 0–100. Score bands: `>=85 SAFE candidate`, `>=70 REVIEW`, `<70 UNSAFE`, **with additional safety gates**. All five checks must complete; any failed check prevents SAFE even if weighted RCS >=85. In the current deterministic test implementation a failed critical check yields REVIEW or UNSAFE per `config/recovery.yaml`. This gate is an AWS design clarification requiring A/B approval for final grading.

Do not publish a SAFE decision until a **real, isolated verifier** has collected evidence from the restored volume and AWS identity/network state. The existing `demo.py` returns synthetic evidence and is **not** a valid live recovery proof.

The result does not auto-release a quarantined service. B records result and A displays it; a designated operator authorizes return to service after an acceptable SAFE and audit review.
