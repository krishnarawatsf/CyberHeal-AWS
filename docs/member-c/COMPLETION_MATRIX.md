# Member C completion matrix — AWS v0.3

| Component | Status | Limitation |
|---|---|---|
| B→C and C→B/A v1 models | Implemented, offline | Cross-process authenticated C worker and atomic approval consumption are not integrated |
| OPA resource/incident matching | Implemented, offline | Cross-process trust transport and live AWS binding still require integration review |
| AWS EC2/EBS account and lab inventory checks | Implemented, fake clients | Read-only AWS preflight not yet run live |
| Signed validation record + AWS snapshot match | Implemented, offline | Human evidence validation/secret custody and storage workflow not deployed |
| Preincident snapshot selection | Implemented, offline | Needs real signed registry and B incident timeline |
| RCS and five check rules | Implemented, offline | Real AWS and recovered filesystem evidence collectors missing |
| Safe file SHA256 read-only scanner | Implemented, offline | Needs isolated read-only mount of EBS clone |
| New EBS volume clone | boto3 adapter + fake tests | Not called against a real account; opt-in disabled by default |
| Clean detached EBS snapshot | boto3 adapter + fake tests | Requires manual quiesce/detach and independent validation |
| Volume wait/attach/mount/scan in verifier | Not implemented | Needs live infrastructure and careful device mapping |
| AWS IAM and network live verification probes | Not implemented | C must implement/collect trusted cloud evidence |
| Durable job/audit record and C metrics endpoint | Not implemented | Integration with B and A pending |
| OpenTofu AWS minimal infrastructure | Template written | `tofu init/validate/plan/apply` not yet run |
| Ansible on AWS | Optional generic template | No approved AWS SSM/SSH connection configured |
| Scaling EC2 Auto Scaling | Not implemented | Only if supervisor retains requirement |
| B investigation/OPA/backend | Implemented, offline | Full OPA-backed suite must pass; live AWS containment and distributed B/C integration remain pending |
| AWS end-to-end live demonstration | Not done | All three members must integrate, measure and document |
